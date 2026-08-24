"""aipwn plugin — Autonomous LLM-powered Frida bypass agent for nutcracker.

:author: Carlos Ganoza <drneox@gmail.com>

Installation (from the nutcracker root directory):
    git clone https://github.com/tu-usuario/nutcracker-aipwn \
        nutcracker_core/plugins/aipwn
    pip install -r nutcracker_core/plugins/aipwn/requirements.txt

Minimal config.yaml setup:
    llm:
      provider: openai
      model: gpt-4o
      api_key: sk-...
    aipwn:
      max_frida_runs: 5
      max_llm_iterations: 30
      capture_seconds: 15
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import click
from rich.console import Console as _Console
from rich.markup import escape as _escape

_console = _Console(highlight=False)


# ── Shared UI helpers ────────────────────────────────────────────────────────

def print_agent_says(text: str, truncate: int = 0) -> None:
    """Imprime un mensaje del agente con el formato estándar 'Nutcracker says: ...'."""
    from nutcracker_core.i18n import t
    msg = text[:truncate] if truncate and len(text) > truncate else text
    _console.print(f'[bold cyan]{t("aipwn_nutcracker_says")}[/bold cyan] "{_escape(msg)}"')


def print_agent_thinking(thinking: str) -> None:
    """Imprime el bloque de thinking del LLM con el formato estándar."""
    from nutcracker_core.i18n import t
    _console.print()
    _console.rule(f"[dim]{t('aipwn_thinking')}[/dim]", style="dim")
    _console.print(thinking, style="dim italic")
    _console.rule(style="dim")
    _console.print()


# ── Local helpers (depend only on nutcracker_core) ──────────────────────────

def _init_i18n(config: dict) -> None:
    from nutcracker_core import i18n
    from nutcracker_core.config import get as cfg_get
    from nutcracker_core.i18n import t
    from nutcracker_core.plugins.aipwn.i18n_strings import STRINGS as _AIPWN_STRINGS
    if hasattr(i18n, "register"):
        i18n.register(_AIPWN_STRINGS)
    language = str(cfg_get(config, "language", default="en")).strip().lower()
    if language not in i18n.SUPPORTED_LANGUAGES:
        import rich
        rich.print(f"[yellow]⚠[/yellow]  {t('unsupported_language', lang=language)}")
    i18n.init(language)


def _load_analysis_json(package: str):
    """Load the most recent AnalysisResult from reports/<package>/.

    FIX (encontrado en vivo, job 2823/sh.nutcracker.nutbank, 2026-08-04):
    esto usaba una lista negra de nombres reservados (_SKIP) para filtrar
    los .json que NO son un AnalysisResult real -- pero
    `exploit_report_<package>.json` (escrito por el exploit agent, no
    cubierto por _SKIP) se colaba. Como tiene una key "package" pero no
    "detections", `AnalysisResult.from_dict()` lo aceptaba en silencio como
    un análisis VACÍO (results=[]) en vez de tirar KeyError -- get_app_analysis()
    del agente LLM reportaba entonces "sin protecciones detectadas" pese a
    que el análisis estático real (guardado aparte, con el patrón de nombre
    de save_analysis_json) sí había encontrado RootBeer y compañía.

    En vez de mantener una lista negra que hay que actualizar cada vez que
    se agrega un nuevo tipo de reporte, se filtra por el patrón de nombre
    POSITIVO real que usa `reporter.save_analysis_json()`
    (`<YYYYMMDD>_<HHMMSS>.json`) -- y de paso se valida que el dict cargado
    tenga la key "detections" antes de aceptarlo, como resguardo adicional
    contra cualquier otro .json ajeno que por casualidad tenga "package".
    """
    from nutcracker_core.analyzer import AnalysisResult

    _ANALYSIS_JSON_RE = re.compile(r"^\d{8}_\d{6}\.json$")

    pkg_dir = Path("./reports") / package
    legacy = Path("./reports") / f"{package}.json"
    if pkg_dir.is_dir():
        jsons = sorted(
            (j for j in pkg_dir.glob("*.json") if _ANALYSIS_JSON_RE.match(j.name)),
            reverse=True,
        )
        for j in jsons:
            try:
                data = json.loads(j.read_text(encoding="utf-8"))
                if "detections" not in data:
                    continue
                return AnalysisResult.from_dict(data)
            except Exception:  # noqa: BLE001
                continue
    if legacy.exists():
        try:
            data = json.loads(legacy.read_text(encoding="utf-8"))
            if "detections" in data:
                return AnalysisResult.from_dict(data)
        except Exception:  # noqa: BLE001
            pass
    return None


def _load_scan_result(package: str):
    """Carga el ScanResult desde el JSON de vulns del package, si existe.

    Además corre manifest_analyzer sobre el directorio decompilado para añadir
    findings de componentes exported, cleartext traffic y debuggable que no
    aparecen en el JSON estático (que solo cubre el código Java).
    """
    import json
    from pathlib import Path

    candidates = [
        Path("reports") / package / "vuln.json",
        Path("decompiled") / f"vuln_{package}.json",
        Path("decompiled") / f"vuln_{package}_review.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                from nutcracker_core.vuln_scanner import ScanResult, VulnFinding
                data = json.loads(path.read_text(encoding="utf-8"))
                findings = []
                fields = VulnFinding.__dataclass_fields__
                for f in data.get("findings", []):
                    kwargs = {k: v for k, v in f.items() if k in fields}
                    if "file" in kwargs:
                        kwargs["file"] = Path(kwargs["file"])
                    findings.append(VulnFinding(**kwargs))

                # ── Enriquecer con findings del AndroidManifest ───────────────
                # El directorio decompilado puede llamarse igual que el package
                # (sh.nutcracker.nutbank) o con el nombre corto (nutbank).
                short_name = package.split(".")[-1]
                decompiled_candidates = [
                    Path("decompiled") / package,
                    Path("decompiled") / short_name,
                    Path("decompiled") / f"runtime_dump_{package}" / "_manifest_apktool_base",
                    Path("decompiled") / f"runtime_dump_{package}",
                ]
                decompiled_dir = next((d for d in decompiled_candidates if d.is_dir()), None)
                if decompiled_dir:
                    try:
                        from nutcracker_core.manifest_analyzer import analyze_decompiled_dir
                        from nutcracker_core.vuln_scanner import scan_manifest_components
                        manifest_findings = scan_manifest_components(decompiled_dir)
                        # Deduplicar por (rule_id, matched_text)
                        existing = {(f.rule_id, f.matched_text) for f in findings}
                        for mf in manifest_findings:
                            if (mf.rule_id, mf.matched_text) not in existing:
                                findings.append(mf)
                                existing.add((mf.rule_id, mf.matched_text))
                    except Exception:
                        pass

                sr = ScanResult(
                    base_dir=path.parent,
                    findings=findings,
                    files_scanned=data.get("files_scanned", len(findings)),
                )
                return sr
            except Exception:  # noqa: BLE001
                pass

    # ── Fallback: live scan sobre el directorio descompilado ─────────────────
    short_name = package.split(".")[-1]
    live_candidates = [
        Path("decompiled") / package,
        Path("decompiled") / short_name,
        Path("decompiled") / f"runtime_dump_{package}" / "_manifest_apktool_base",
        Path("decompiled") / f"runtime_dump_{package}" / "source",
    ]
    live_dir = next((d for d in live_candidates if d.is_dir()), None)
    if live_dir:
        try:
            import click as _click
            from nutcracker_core.vuln_scanner import scan_directory, ScanResult
            _click.echo(f"  [aipwn] no vuln JSON found — running live scan on {live_dir}")
            return scan_directory(live_dir)
        except Exception:  # noqa: BLE001
            pass

    return None


# ── Capacidades expuestas a otros plugins (registro plugin→plugin) ──────────

def _load_query_capability() -> dict:
    """Import perezoso del co-piloto de consulta: query_agent arrastra any_llm
    (via frida_agent.LLMClient), que no debe pagarse en cada invocación del
    CLI -- solo cuando alguien realmente usa la capacidad."""
    from .query_agent import QueryAgent, QueryEvent
    from .query_context import resolve_package_context
    from .query_tools import DeviceIO
    return {
        "QueryAgent": QueryAgent,
        "QueryEvent": QueryEvent,
        "resolve_package_context": resolve_package_context,
        "DeviceIO": DeviceIO,
    }


def _load_system_prompt() -> str:
    from .frida_agent import _SYSTEM_PROMPT
    return _SYSTEM_PROMPT


def register_capabilities() -> None:
    """Publica las capacidades de aipwn en ``nutcracker_core.capabilities``
    para que otros plugins (hoy: dashboard) las consuman SIN importar aipwn
    directamente. Separada de ``register()`` para que los tests puedan
    invocarla sin armar un CLI group."""
    from nutcracker_core import capabilities
    from . import agent_memory

    capabilities.register("aipwn.has_resume_state", agent_memory.has_resume_state)
    capabilities.register("aipwn.load_resume_state", agent_memory.load_resume_state)
    capabilities.register_lazy("aipwn.system_prompt", _load_system_prompt)
    capabilities.register_lazy("aipwn.query", _load_query_capability)


# ── Click command registration ───────────────────────────────────────────────

def register(cli) -> None:
    """Register the ``aipwn`` command into the nutcracker CLI group."""
    register_capabilities()

    @cli.command("aipwn")
    @click.argument("package")
    @click.option("--serial", "-s", default=None, help="ADB device serial (default: USB)")
    @click.option("--max-runs", default=None, type=int,
                  help="Max Frida execution slots (default: from config aipwn.max_frida_runs)")
    @click.option("--capture-sec", default=None, type=int,
                  help="Seconds to observe each Frida run (default: from config aipwn.capture_seconds)")
    @click.option("--force", is_flag=True, default=False,
                  help="Skip existing script validation and go straight to the LLM agent")
    @click.option("--only-bypass", is_flag=True, default=False,
                  help="Run Frida bypass only — skip ExploitAgent vulnerability confirmation")
    @click.option("--report", is_flag=True, default=False,
                  help="Save exploit results as JSON + PDF in reports/<package>/")
    @click.option("--resume", is_flag=True, default=False,
                  help="Continue the last inconclusive session for PACKAGE (iteration limit / "
                       "LLM cut off) instead of starting a new conversation. No-op if there's no "
                       "pending session.")
    @click.option("--extra-iterations", default=5, type=int,
                  help="Extra LLM iterations to grant when --resume is used (default: 5)")
    @click.option("--interactive", is_flag=True, default=False,
                  help="If the run ends WITHOUT success (failure or iteration limit), open an "
                       "interactive chat in the terminal with the agent's real conversation "
                       "handed over to the co-pilot — refine the bypass where it stopped.")
    def aipwn_cmd(
        package: str,
        serial: str | None,
        max_runs: int | None,
        capture_sec: int | None,
        force: bool,
        only_bypass: bool,
        report: bool,
        resume: bool,
        extra_iterations: int,
        interactive: bool,
    ) -> None:
        """LLM-assisted autonomous Frida bypass + exploit agent for PACKAGE.

        Runs the Frida bypass and then automatically confirms vulnerabilities
        at runtime via AIpwn Agent (ADB + Frida). Use --only-bypass to skip
        the exploit phase.

        By default, if a previous bypass script exists for PACKAGE it is tested first.
        Only if it fails (or --force is used) the LLM agent is invoked.

        Requires an LLM configured in config.yaml (llm.provider + llm.model + llm.api_key).

        PACKAGE is the app package ID, e.g.: com.example.myapp
        """
        from nutcracker_core.config import load_config
        from .aipwn import run_aipwn

        config = load_config()
        _init_i18n(config)

        analysis_result = _load_analysis_json(package)

        decompiled_dir: Path | None = None
        for candidate in [
            Path("./decompiled") / f"runtime_dump_{package}" / "source",
            Path("./decompiled") / package,
        ]:
            if candidate.exists() and any(candidate.rglob("*.java")):
                decompiled_dir = candidate
                break

        scan_result = None
        if not only_bypass or report:
            scan_result = _load_scan_result(package)

        agent_result = run_aipwn(
            package=package,
            config=config,
            serial=serial,
            analysis_result=analysis_result,
            decompiled_dir=decompiled_dir,
            max_frida_runs=max_runs,
            capture_seconds=capture_sec,
            force=force,
            exploit_mode=not only_bypass,
            scan_result=scan_result,
            resume=resume,
            extra_iterations=extra_iterations,
            interactive=interactive,
        )

        # ROADMAP "Differentiate runtime bypass vs DEX extraction in reports":
        # un bypass confirmado por el agente (report_success) es evidencia
        # válida de RESILIENCE roto aunque no se haya volcado DEX en memoria
        # (AnalysisResult.protection_broken exige dex_count > 0). Persistimos
        # el flag para que build_masvs_report() lo recoja en futuras corridas
        # (analyze/scan/regen-pdf) sin depender de que aipwn corra en el mismo
        # proceso que el análisis original.
        if analysis_result is not None and getattr(agent_result, "success", False):
            analysis_result.aipwn_bypass_confirmed = True
            from nutcracker_core.reporter import save_analysis_json

            save_analysis_json(analysis_result, scan_result=scan_result)

        # ── Guardar reporte de explotación ────────────────────────────────────
        if report and agent_result is not None and getattr(agent_result, "exploit_report", None):
            from .exploit_report_pdf import generate_exploit_pdf, merge_exploit_with_base, save_exploit_json
            import click as _click

            er = agent_result.exploit_report
            out_dir = Path("reports") / package
            out_dir.mkdir(parents=True, exist_ok=True)

            # JSON — sobreescribe siempre (idempotente)
            json_path = save_exploit_json(er, out_dir / f"exploit_report_{package}.json")
            _click.echo(f"  exploit JSON → {json_path}")

            try:
                # PDF standalone — sobreescribe siempre
                exploit_pdf = out_dir / f"exploit_report_{package}.pdf"
                generate_exploit_pdf(er, exploit_pdf)
                _click.echo(f"  exploit PDF  → {exploit_pdf}")

                # PDF fusionado — si existe el reporte base, genera uno combinado
                # sin modificar el original
                base_pdf = Path("reports") / package / f"nutcracker_{package}_report.pdf"
                if base_pdf.exists():
                    merged_pdf = out_dir / f"nutcracker_{package}_full_report.pdf"
                    merge_exploit_with_base(er, base_pdf, merged_pdf)
                    _click.echo(f"  full PDF     → {merged_pdf}")
            except Exception as _pdf_err:
                _click.echo(f"  [warn] PDF no generado: {_pdf_err}")
