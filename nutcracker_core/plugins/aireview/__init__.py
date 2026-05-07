"""ai-review plugin — LLM-powered false positive filter for nutcracker.

Reads the saved vulnerability scan JSON (decompiled/vuln_<package>.json),
asks an LLM to classify each finding as TRUE_POSITIVE or FALSE_POSITIVE
based on the matched code and surrounding context, then rewrites the JSON
in-place keeping only the true positives. The original file is backed up
to vuln_<package>.json.bak.<timestamp> and a full audit trail with every
verdict + reasoning is saved to decompiled/vuln_<package>_review.json.

Usage:
    nutcracker ai-review com.example.app
    nutcracker ai-review com.example.app --dry-run        # do not modify files
    nutcracker ai-review com.example.app --no-regen-pdf   # skip PDF rebuild
    nutcracker ai-review com.example.app --batch-size 5 --context-lines 6

Required config.yaml block (same as aipwn — reused verbatim):
    llm:
      provider: openai          # openai | anthropic | ollama
      model: gpt-4o-mini
      api_key: sk-...
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

import click


# ── Constants ────────────────────────────────────────────────────────────────

_DECOMPILED_DIR = Path("./decompiled")
_REPORTS_DIR = Path("./reports")
_DEFAULT_BATCH_SIZE = 8
_DEFAULT_CONTEXT_LINES = 4
_VALID_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "DOWNGRADE"}

_SYSTEM_PROMPT = (
    "You are an expert Android application security reviewer. "
    "You receive vulnerability scanner findings from a static analysis tool "
    "that uses regex pattern matching, which produces many false positives. "
    "For each finding you must decide if it is a real security issue "
    "(TRUE_POSITIVE), a false positive (FALSE_POSITIVE), or a real finding "
    "whose severity is overstated (DOWNGRADE).\n\n"
    "━━ ABSOLUTE RULES (override everything else) ━━\n"
    "1. Any finding whose matched text contains an API key matching the pattern "
    "AIzaSy[0-9A-Za-z_-]{35} (Google/Firebase key) MUST be TRUE_POSITIVE. "
    "Never mark these as FALSE_POSITIVE, even if the surrounding code looks benign.\n"
    "2. Any finding that is a hardcoded domain, hostname, or URL endpoint "
    "(e.g. api.example.com, https://backend.app/) MUST be DOWNGRADE with "
    "suggested_severity=INFO. The domain is embedded in the app, which is "
    "noteworthy even if it is not a secret. Never mark these as FALSE_POSITIVE.\n\n"
    "━━ Common false-positive patterns to reject (FALSE_POSITIVE) ━━\n"
    "  - Constants whose value is a key/field/preference name, not a secret "
    "(e.g. KEY_TOKEN = \"access_token\", PREFS_PASSWORD = \"user.password\").\n"
    "  - Test fixtures, sample data, comments, javadoc, BuildConfig debug "
    "values that are clearly placeholders (e.g. \"YOUR_API_KEY_HERE\").\n"
    "  - Obfuscated identifiers with no real semantics.\n"
    "  - Logs that print metadata about a token (status, length) but not the "
    "token value itself.\n"
    "  - Strings that look like a secret but are actually error messages, "
    "regex patterns, JSON keys, or protocol constants.\n\n"
    "━━ When to DOWNGRADE ━━\n"
    "Mark DOWNGRADE when the finding is real but its severity or category is "
    "overstated — e.g. a hardcoded URL flagged HIGH that should be INFO, or an "
    "internal endpoint that should be LOW instead of MEDIUM. "
    "For DOWNGRADE include 'suggested_severity' (one of: CRITICAL, HIGH, MEDIUM, "
    "LOW, INFO) and optionally 'suggested_category' with a short label.\n\n"
    "Mark TRUE_POSITIVE only when the matched code clearly exposes or misuses "
    "real sensitive data (real API keys, real credentials, real secrets, real "
    "private endpoints, real cryptographic misuse).\n\n"
    "You MUST reply with a single JSON object exactly matching this schema:\n"
    "{\"verdicts\": [{\"id\": <int>, \"verdict\": \"TRUE_POSITIVE\"|"
    "\"FALSE_POSITIVE\"|\"DOWNGRADE\", \"reason\": \"<short reason, max 200 chars>\","
    " \"suggested_severity\": \"<only for DOWNGRADE>\","
    " \"suggested_category\": \"<optional, only for DOWNGRADE>\"}, ...]}\n"
    "Include exactly one entry per finding id provided. No prose outside the "
    "JSON. No markdown code fences."
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _load_findings(package: str) -> tuple[Path, dict]:
    """Load the vulnerability JSON for a package. Raises click.ClickException."""
    # Primario: reports/<package>/vuln.json; fallback: decompiled/vuln_<package>.json
    path = _REPORTS_DIR / package / "vuln.json"
    if not path.exists():
        path = _DECOMPILED_DIR / f"vuln_{package}.json"
    if not path.exists():
        raise click.ClickException(
            f"No vuln scan found for {package}. Run a full analysis first."
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"Cannot parse {path}: {exc}") from exc
    if not isinstance(data, dict) or "findings" not in data:
        raise click.ClickException(f"Unexpected schema in {path}.")
    return path, data


def _read_context(package: str, rel_file: str, line: int, ctx: int) -> str:
    """Return ``ctx`` lines before/after ``line`` from the decompiled source."""
    base = _DECOMPILED_DIR / package
    candidate = base / rel_file
    if not candidate.exists():
        # Try runtime_dump_<package>/source/<rel_file>
        alt = _DECOMPILED_DIR / f"runtime_dump_{package}" / "source" / rel_file
        if alt.exists():
            candidate = alt
        else:
            return ""
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""
    lines = text.splitlines()
    start = max(0, line - 1 - ctx)
    end = min(len(lines), line + ctx)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>" if (i + 1) == line else "  "
        snippet_lines.append(f"{marker} {i + 1:>5}: {lines[i]}")
    return "\n".join(snippet_lines)


def _build_user_prompt(batch: list[dict], package: str, ctx_lines: int) -> str:
    """Build the user message for one batch of findings."""
    parts = [f"Application package: {package}", "", "Findings to review:"]
    for idx, f in enumerate(batch):
        ctx = _read_context(package, f.get("file", ""), int(f.get("line", 0)), ctx_lines)
        parts.append(
            "\n----- finding id={id} -----\n"
            "rule_id:        {rule}\n"
            "title:          {title}\n"
            "severity:       {sev}\n"
            "category:       {cat}\n"
            "file:           {file}:{line}\n"
            "matched_text:   {matched}\n"
            "description:    {desc}\n"
            "context:\n{ctx}".format(
                id=idx,
                rule=f.get("rule_id", ""),
                title=f.get("title", ""),
                sev=f.get("severity", ""),
                cat=f.get("category", ""),
                file=f.get("file", ""),
                line=f.get("line", ""),
                matched=(f.get("matched_text", "") or "")[:400],
                desc=f.get("description", ""),
                ctx=ctx or "<source not available>",
            )
        )
    parts.append(
        "\nReply now with the JSON object as specified in the system prompt. "
        f"It must contain exactly {len(batch)} verdicts (ids 0 to "
        f"{len(batch) - 1})."
    )
    return "\n".join(parts)


def _parse_verdicts(raw: str, expected: int) -> list[dict] | None:
    """Best-effort parse of the LLM JSON response."""
    if not raw:
        return None
    text = raw.strip()
    # Strip accidental markdown fences
    if text.startswith("```"):
        text = text.strip("`")
        # remove leading "json\n"
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    # Locate the first JSON object
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except Exception:  # noqa: BLE001
        return None
    verdicts = obj.get("verdicts") if isinstance(obj, dict) else None
    if not isinstance(verdicts, list):
        return None
    out = []
    for v in verdicts:
        if not isinstance(v, dict):
            continue
        try:
            vid = int(v.get("id"))
        except (TypeError, ValueError):
            continue
        verdict = str(v.get("verdict", "")).upper().strip()
        if verdict not in _VALID_VERDICTS:
            continue
        entry: dict = {
            "id": vid,
            "verdict": verdict,
            "reason": str(v.get("reason", ""))[:300],
        }
        if verdict == "DOWNGRADE":
            sev = str(v.get("suggested_severity", "")).upper().strip()
            if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                entry["suggested_severity"] = sev.lower()
            cat = str(v.get("suggested_category", "")).strip()
            if cat:
                entry["suggested_category"] = cat
        out.append(entry)
    if not out:
        return None
    # If model dropped some ids, default them to TRUE_POSITIVE (conservative)
    seen = {v["id"] for v in out}
    for missing in range(expected):
        if missing not in seen:
            out.append({
                "id": missing,
                "verdict": "TRUE_POSITIVE",
                "reason": "missing in LLM response, kept by default",
            })
    return out


def _llm_call(llm_cfg: dict, system: str, user: str) -> str:
    """Invoke any-llm and return raw assistant text. Raises on hard failure."""
    try:
        from any_llm import completion as _llm_completion
    except ImportError as exc:
        raise click.ClickException(
            "any-llm-sdk is not installed. Run: pip install -r "
            "nutcracker_core/plugins/aireview/requirements.txt"
        ) from exc

    provider = str(llm_cfg.get("provider", "openai")).lower()
    model = str(llm_cfg.get("model", "gpt-4o-mini"))
    api_key = llm_cfg.get("api_key") or None
    api_base = llm_cfg.get("base_url") or None
    max_tokens = int(llm_cfg.get("max_tokens", 4096))
    timeout = int(llm_cfg.get("timeout", 120))

    if api_key:
        env_var = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }.get(provider)
        if env_var and not os.environ.get(env_var):
            os.environ[env_var] = api_key

    response = _llm_completion(
        model=model,
        provider=provider,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_tokens=max_tokens,
        api_key=api_key,
        api_base=api_base,
        client_args={"timeout": timeout},
    )
    msg = response.choices[0].message
    content = msg.content or ""
    if isinstance(content, list):
        # Anthropic-style list of content blocks
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif hasattr(block, "type") and block.type == "text":
                parts.append(getattr(block, "text", ""))
        content = "\n".join(parts)
    return str(content)


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _apply_severity_filter(
    findings: list[dict],
    review_severities: list[str] | None,
) -> tuple[list[dict], list[dict]]:
    """Split findings into (to_review, to_skip) by review_severities config.

    findings_to_skip are passed through without LLM review (always kept).
    Returns (findings_to_review, findings_to_skip).
    """
    if not review_severities:
        return findings, []
    allowed = {s.strip().lower() for s in review_severities}
    to_review = [f for f in findings if (f.get("severity") or "").lower() in allowed]
    to_skip   = [f for f in findings if (f.get("severity") or "").lower() not in allowed]
    return to_review, to_skip


def _run_review_batches(
    findings_to_review: list[dict],
    package: str,
    llm_cfg: dict,
    batch_size: int,
    context_lines: int,
    on_batch_start=None,  # callable(start: int, end: int, total: int)
    on_batch_error=None,  # callable(start: int, exc)
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Run LLM review over findings_to_review in batches.

    Callbacks (both optional):
      on_batch_start(start, end, total) — called before each LLM call.
      on_batch_error(start, exc)        — called on LLM failure or unparseable
                                          response; batch findings are kept.

    Returns (verdicts, kept, dropped, downgraded).
    ``kept`` contains only findings from findings_to_review (not skipped ones).
    """
    verdicts: list[dict] = []
    kept: list[dict] = []
    dropped: list[dict] = []
    downgraded: list[dict] = []

    for start in range(0, len(findings_to_review), batch_size):
        batch = findings_to_review[start:start + batch_size]
        end   = start + len(batch)
        if on_batch_start:
            on_batch_start(start + 1, end, len(findings_to_review))

        user_prompt = _build_user_prompt(batch, package, context_lines)
        try:
            raw = _llm_call(llm_cfg, _SYSTEM_PROMPT, user_prompt)
        except Exception as exc:  # noqa: BLE001
            if on_batch_error:
                on_batch_error(start, exc)
            for i, f in enumerate(batch):
                verdicts.append({"id": start + i, "verdict": "TRUE_POSITIVE",
                                  "reason": f"LLM error: {exc}"})
                kept.append(f)
            continue

        parsed = _parse_verdicts(raw, len(batch))
        if parsed is None:
            if on_batch_error:
                on_batch_error(start, "unparseable LLM response")
            for i, f in enumerate(batch):
                verdicts.append({"id": start + i, "verdict": "TRUE_POSITIVE",
                                  "reason": "unparseable"})
                kept.append(f)
            continue

        parsed.sort(key=lambda v: v["id"])
        vmap = {v["id"]: v for v in parsed}
        for i, f in enumerate(batch):
            v = vmap.get(i, {"verdict": "TRUE_POSITIVE", "reason": "missing"})
            enriched = {
                "id": start + i,
                "rule_id": f.get("rule_id"),
                "file": f.get("file"),
                "line": f.get("line"),
                "verdict": v["verdict"],
                "reason": v.get("reason", ""),
            }
            if v["verdict"] == "DOWNGRADE":
                if v.get("suggested_severity"):
                    enriched["suggested_severity"] = v["suggested_severity"]
                if v.get("suggested_category"):
                    enriched["suggested_category"] = v["suggested_category"]
            verdicts.append(enriched)
            if v["verdict"] == "FALSE_POSITIVE":
                dropped.append({**f, "_fp_reason": v.get("reason", "")})
            elif v["verdict"] == "DOWNGRADE":
                modified = dict(f)
                if v.get("suggested_severity"):
                    modified["severity"] = v["suggested_severity"]
                if v.get("suggested_category"):
                    modified["category"] = v["suggested_category"]
                modified["_ai_note"] = v.get("reason", "")
                kept.append(modified)
                downgraded.append(modified)
            else:  # TRUE_POSITIVE
                kept.append(f)

    return verdicts, kept, dropped, downgraded


def _persist_review_results(
    package: str,
    path: "Path",
    data: dict,
    findings_to_review: list[dict],
    findings_skip: list[dict],
    verdicts: list[dict],
    kept_reviewed: list[dict],
    dropped: list[dict],
    downgraded: list[dict],
    llm_cfg: dict,
) -> tuple[int, int, int]:
    """Save review.json and rewrite vuln.json (with backup).

    Returns (tp_count, fp_count, dg_count).
    tp_count includes both findings_skip and kept_reviewed.
    """
    all_kept  = list(findings_skip) + kept_reviewed
    tp_count  = len(all_kept)
    fp_count  = len(dropped)
    dg_count  = len(downgraded)

    pkg_reports_dir = _REPORTS_DIR / package
    pkg_reports_dir.mkdir(parents=True, exist_ok=True)

    review_payload = {
        "package": package,
        "reviewed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": llm_cfg.get("model"),
        "provider": llm_cfg.get("provider"),
        "total": len(findings_to_review),
        "true_positives": tp_count,
        "false_positives": fp_count,
        "downgraded": dg_count,
        "verdicts": verdicts,
    }
    review_json = json.dumps(review_payload, ensure_ascii=False, indent=2)
    (pkg_reports_dir / "review.json").write_text(review_json, encoding="utf-8")
    (_DECOMPILED_DIR / f"vuln_{package}_review.json").write_text(review_json, encoding="utf-8")

    if fp_count == 0 and dg_count == 0:
        return tp_count, fp_count, dg_count

    ts = time.strftime("%Y%m%d_%H%M%S")
    shutil.copy2(path, path.with_suffix(f".json.bak.{ts}"))

    new_data = dict(data)
    # FPs se conservan en el JSON con _fp=True para auditoría; el PDF los ignora
    tagged_fps = [{**d, "_fp": True} for d in dropped]
    new_data["findings"]       = all_kept + tagged_fps
    new_data["total_findings"] = tp_count
    new_data["ai_reviewed"]    = {
        "at":         review_payload["reviewed_at"],
        "model":      llm_cfg.get("model"),
        "provider":   llm_cfg.get("provider"),
        "dropped":    fp_count,
        "downgraded": dg_count,
    }
    new_json = json.dumps(new_data, ensure_ascii=False, indent=2)
    (pkg_reports_dir / "vuln.json").write_text(new_json, encoding="utf-8")
    path.write_text(new_json, encoding="utf-8")

    return tp_count, fp_count, dg_count


def _regen_pdf(package: str, console=None) -> None:
    """Attempt to regenerate the PDF for package, optionally printing errors."""
    try:
        import sys as _sys
        _nc = _sys.modules.get("nutcracker") or _sys.modules.get("__main__")
        cb = getattr(getattr(_nc, "regen_pdf", None), "callback", None)
        if cb is None:
            raise RuntimeError("regen-pdf command not callable")
        cb(package=package)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        if console:
            console.print(
                f"[yellow]Could not auto-regenerate PDF: {exc}. "
                f"Run manually:[/yellow] [bold]nutcracker regen-pdf {package}[/bold]"
            )


# ── Auto-run hook (triggered by fire_post_hooks) ──────────────────────────────

def _after_analysis_hook(
    package: str,
    result,  # AnalysisResult
    vuln_scan,  # ScanResult | None
    config: dict,
) -> None:
    """Runs ai-review automatically if enabled in config post_hooks."""
    enabled_hooks = config.get("post_hooks") or []
    if "ai-review" not in enabled_hooks:
        return
    if vuln_scan is None or not getattr(vuln_scan, "findings", None):
        return
    llm_cfg = config.get("llm") or {}
    if not llm_cfg.get("provider"):
        return

    from rich.console import Console
    console = Console()
    console.print("[dim][ai-review] Auto-running after analysis...[/dim]")

    ai_review_cfg = config.get("ai_review", {}) or {}
    batch_size    = int(ai_review_cfg.get("batch_size",    _DEFAULT_BATCH_SIZE))
    context_lines = int(ai_review_cfg.get("context_lines", _DEFAULT_CONTEXT_LINES))
    do_regen_pdf  = bool(ai_review_cfg.get("regen_pdf", True))

    try:
        path, data = _load_findings(package)
    except Exception:  # noqa: BLE001
        return

    findings = data.get("findings", []) or []
    if not findings:
        return

    findings_to_review, findings_skip = _apply_severity_filter(
        findings, ai_review_cfg.get("review_severities")
    )
    console.print(
        f"[dim][ai-review] {len(findings_to_review)} findings to review "
        f"(batch={batch_size}"
        + (f", skipping {len(findings_skip)} low/info)" if findings_skip else ")")
        + "[/dim]"
    )

    verdicts, kept_reviewed, dropped, downgraded = _run_review_batches(
        findings_to_review, package, llm_cfg, batch_size, context_lines,
        on_batch_start=lambda s, e, t: console.print(
            f"[dim][ai-review] batch {s}-{e} / {t}...[/dim]"
        ),
        on_batch_error=lambda s, exc: console.print(
            f"[red][ai-review] batch at {s} failed: {exc}[/red]"
        ),
    )

    tp_count, fp_count, dg_count = _persist_review_results(
        package, path, data,
        findings_to_review, findings_skip,
        verdicts, kept_reviewed, dropped, downgraded,
        llm_cfg,
    )
    console.print(
        f"[green]\u2714[/green] ai-review: kept {tp_count} TPs, "
        f"dropped {fp_count} FPs, downgraded {dg_count} for {package}"
    )
    if do_regen_pdf:
        _regen_pdf(package)


# ── CLI registration ─────────────────────────────────────────────────────────

def register(cli) -> None:
    """Register the ``ai-review`` command into the nutcracker CLI group."""

    @cli.command("ai-review")
    @click.argument("package")
    @click.option("--dry-run", is_flag=True, default=False,
                  help="Show verdicts but do not modify any file.")
    @click.option("--no-regen-pdf", is_flag=True, default=False,
                  help="Skip regenerating the PDF after filtering.")
    @click.option("--batch-size", default=_DEFAULT_BATCH_SIZE, type=int,
                  show_default=True, help="Findings sent per LLM call.")
    @click.option("--context-lines", default=_DEFAULT_CONTEXT_LINES, type=int,
                  show_default=True,
                  help="Source lines around the match included as context.")
    @click.option("--config", "-c", "config_path", default="config.yaml",
                  show_default=True, help="Path to YAML config file.")
    def ai_review_cmd(
        package: str,
        dry_run: bool,
        no_regen_pdf: bool,
        batch_size: int,
        context_lines: int,
        config_path: str,
    ) -> None:
        """Filter false positives from vuln_<PACKAGE>.json using an LLM."""
        from rich.console import Console
        from rich.table import Table
        from nutcracker_core.config import load_config, get as cfg_get

        console = Console()
        config  = load_config(config_path)
        llm_cfg = cfg_get(config, "llm", default={}) or {}
        if not llm_cfg.get("provider"):
            raise click.ClickException(
                "No 'llm' block found in config.yaml. Add at least "
                "llm.provider, llm.model and llm.api_key."
            )

        # CLI flags override config; fall back to config only when the flag
        # still holds the Click default value.
        ai_review_cfg = cfg_get(config, "ai_review", default={}) or {}
        if batch_size == _DEFAULT_BATCH_SIZE:
            batch_size    = int(ai_review_cfg.get("batch_size",    _DEFAULT_BATCH_SIZE))
        if context_lines == _DEFAULT_CONTEXT_LINES:
            context_lines = int(ai_review_cfg.get("context_lines", _DEFAULT_CONTEXT_LINES))

        path, data = _load_findings(package)
        findings   = data.get("findings", []) or []
        if not findings:
            console.print(f"[yellow]No findings to review in {path}.[/yellow]")
            return

        findings_to_review, findings_skip = _apply_severity_filter(
            findings, ai_review_cfg.get("review_severities")
        )
        console.print(
            f"[cyan]ai-review[/cyan]  {len(findings_to_review)} findings | "
            f"LLM: {llm_cfg.get('model', '?')} via {llm_cfg.get('provider', '?')} | "
            f"batch={batch_size}"
            + (f" | skipping {len(findings_skip)} low/info" if findings_skip else "")
        )

        # ── Run batches with spinner ─────────────────────────────────────
        verdicts: list[dict]    = []
        kept_reviewed: list[dict] = []
        dropped: list[dict]     = []
        downgraded: list[dict]  = []

        with console.status("[cyan]Reviewing findings...[/cyan]") as status:
            def on_progress(start: int, end: int, total: int) -> None:
                status.update(f"[cyan]Reviewing[/cyan] {start}-{end} / {total}")

            def on_error(start: int, exc) -> None:
                console.print(f"[red]LLM call failed for batch at {start}: {exc}[/red]")

            _v, _k, _d, _dg = _run_review_batches(
                findings_to_review, package, llm_cfg, batch_size, context_lines,
                on_batch_start=on_progress,
                on_batch_error=on_error,
            )
            verdicts.extend(_v)
            kept_reviewed.extend(_k)
            dropped.extend(_d)
            downgraded.extend(_dg)

        # ── Summary ──────────────────────────────────────────────────────
        tp_count = len(findings_skip) + len(kept_reviewed)
        fp_count = len(dropped)
        dg_count = len(downgraded)
        console.print()
        console.print(
            f"[green]\u2714[/green] Kept {tp_count} true positives  "
            f"[red]\u2718[/red] Dropped {fp_count} false positives  "
            f"[yellow]\u2193[/yellow] Downgraded {dg_count}"
        )

        if dropped:
            table = Table(title="False positives dropped", show_lines=False)
            table.add_column("rule",     style="magenta", no_wrap=True)
            table.add_column("file:line", style="cyan",   overflow="fold")
            table.add_column("reason",   style="dim",     overflow="fold")
            for d in dropped[:50]:
                table.add_row(
                    str(d.get("rule_id", "")),
                    f"{d.get('file', '')}:{d.get('line', '')}",
                    str(d.get("_fp_reason", ""))[:160],
                )
            console.print(table)
            if len(dropped) > 50:
                console.print(f"[dim]... and {len(dropped) - 50} more[/dim]")

        if downgraded:
            table = Table(title="Downgraded findings", show_lines=False)
            table.add_column("rule",      style="magenta", no_wrap=True)
            table.add_column("file:line", style="cyan",    overflow="fold")
            table.add_column("severity",  style="yellow",  no_wrap=True)
            table.add_column("category",  style="blue",    overflow="fold")
            table.add_column("reason",    style="dim",     overflow="fold")
            for d in downgraded[:50]:
                table.add_row(
                    str(d.get("rule_id", "")),
                    f"{d.get('file', '')}:{d.get('line', '')}",
                    str(d.get("severity", "")),
                    str(d.get("category", "")),
                    str(d.get("_ai_note", ""))[:160],
                )
            console.print(table)
            if len(downgraded) > 50:
                console.print(f"[dim]... and {len(downgraded) - 50} more[/dim]")

        if dry_run:
            console.print(
                f"[yellow]Dry-run: not modifying {path}. "
                f"Audit trail not written.[/yellow]"
            )
            return

        # ── Persist results ──────────────────────────────────────────────
        tp_count, fp_count, dg_count = _persist_review_results(
            package, path, data,
            findings_to_review, findings_skip,
            verdicts, kept_reviewed, dropped, downgraded,
            llm_cfg,
        )
        console.print(
            f"[dim]Audit trail saved to {_REPORTS_DIR / package / 'review.json'}[/dim]"
        )

        if fp_count == 0 and dg_count == 0:
            console.print(
                "[green]No false positives or downgrades detected; "
                f"{path} left untouched.[/green]"
            )
            return

        backup = path.with_suffix(f".json.bak.{time.strftime('%Y%m%d_%H%M%S')}")
        console.print(f"[dim]Backup saved to {backup}[/dim]")
        console.print(f"[green]\u2714[/green] vuln.json updated.")

        if no_regen_pdf:
            console.print("[dim]Skipping PDF regeneration (--no-regen-pdf).[/dim]")
            return
        console.print("[cyan]Regenerating PDF with filtered findings...[/cyan]")
        _regen_pdf(package, console=console)

    # ── Register post-hook ────────────────────────────────────────────────────
    try:
        from nutcracker_core.plugins import register_post_hook
        register_post_hook("after_analysis", _after_analysis_hook)
    except Exception:  # noqa: BLE001
        pass
