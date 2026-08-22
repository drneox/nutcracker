"""Comando `nutcracker batch`: escanea una lista de APKs/URLs.

Migrado a usar el motor de cola de Fase 1 (`nutcracker_core.queue.engine`) en
vez de su bucle secuencial propio original: cada target ahora corre como el
mismo subproceso aislado (`analyze`/`scan`) que usan `queue add` y `serve`,
en paralelo según `queue.static_workers` (config.yaml) — o estrictamente
secuencial con `static_workers: 1`. El resumen consolidado (severidades, top
findings, categorías por app) se reconstruye desde SQLite en vez de desde
objetos en memoria, porque cada job corrió en su propio proceso.

Efecto colateral bienvenido: como cada target pasa por QueueEngine, también
queda auto-agendado para revisión periódica (Fase 1.2, `schedule`/`serve`).
"""

from __future__ import annotations

import time
from pathlib import Path

import click

from nutcracker_core import orchestrator as orch
from nutcracker_core.config import get as cfg_get, load_config
from nutcracker_core.i18n import t
from nutcracker_core.orchestrator import console
from nutcracker_core.queue.engine import JobOutcome, QueueEngine
from nutcracker_core.store import db, repository
from nutcracker_core.store.hooks import db_path_from_config

from . import cli

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_VERDICT_TO_STATUS = {
    "protection_broken": "protected_broken",
    "protected": "protected",
    "not_protected": "unprotected",
}


def _summary_for_outcome(db_path: str | None, outcome: JobOutcome) -> dict:
    """Reconstruye la fila de resumen del batch (severidades, top findings,
    categorías) desde SQLite — cada job corrió en su propio subproceso, así
    que sus hallazgos ya están persistidos para cuando drain() retorna."""
    base: dict = {"target": outcome.job.target, "package": outcome.package}

    if not outcome.ok or outcome.run_id is None:
        base["status"] = "error"
        base["error"] = outcome.error or "análisis fallido"
        return base

    conn = db.connect(db_path)
    try:
        run = repository.get_run(conn, outcome.run_id)
        findings = repository.findings_for_run(conn, outcome.run_id)
    finally:
        conn.close()

    base["status"] = _VERDICT_TO_STATUS.get(run["verdict"] if run else None, "unprotected")

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    leaks_count = 0
    seen_rules: set[str] = set()
    top_findings: list[tuple[str, str, str]] = []
    cat_max_sev: dict[str, str] = {}
    for f in findings:
        sev = (f["severity"] or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        rid = f["rule_id"] or ""
        cat = f["category"] or ""
        if cat:
            prev = cat_max_sev.get(cat, "info")
            if _SEV_ORDER.get(sev, 5) < _SEV_ORDER.get(prev, 5):
                cat_max_sev[cat] = sev
        if rid.upper().startswith(("AL-", "HC", "GL-")):
            leaks_count += 1
        if rid not in seen_rules:
            seen_rules.add(rid)
            top_findings.append((rid, f["title"] or "", sev))
    top_findings.sort(key=lambda x: _SEV_ORDER.get(x[2], 5))

    base.update({
        "findings": len(findings),
        **sev_counts,
        "leaks": leaks_count,
        "top_findings": top_findings[:5],
        "categories": cat_max_sev,
    })
    return base


@cli.command()
@click.argument("list_file", type=click.Path(dir_okay=False), required=False, default=None)
@click.option(
    "--config", "-c",
    "config_path",
    default="config.yaml",
    show_default=True,
    metavar="ARCHIVO",
    help="Path to YAML config file.",
)
@click.option(
    "--output-dir", "-o",
    default=None,
    help="Directory for the consolidated batch_report.pdf (individual per-app "
         "reports always use reports.output_dir from config.yaml, same as "
         "`analyze`/`scan`).",
)
@click.option(
    "--stop-on-error",
    is_flag=True,
    default=False,
    help="Stop queueing further targets on the first error. Only strictly "
         "honored in sequential mode (queue.static_workers: 1) — in parallel "
         "mode, jobs already dispatched to the pool still finish.",
)
def batch(
    list_file: str | None,
    config_path: str,
    output_dir: str | None,
    stop_on_error: bool,
) -> None:
    """
    Scan a list of APKs or URLs in batch mode.

    Runs via the queue (Fase 1 del plan): in parallel according to
    queue.static_workers in config.yaml (default 4), or sequentially with
    static_workers: 1. Each target also gets auto-scheduled for periodic
    re-review (see `nutcracker schedule`).

    LIST_FILE is a text file with one entry per line:
      - Google Play URLs   (https://play.google.com/...)
      - Package IDs        (com.example.app)
      - Direct APK URLs    (https://cdn.example.com/app.apk)
      - Local APK paths    (/path/to/app.apk)

    Lines starting with '#' or empty lines are ignored.
    """
    started_at = time.perf_counter()
    config = load_config(config_path)
    orch._init_i18n(config)

    batch_cfg = cfg_get(config, "batch") or {}
    _stop_on_err = stop_on_error or bool(batch_cfg.get("stop_on_error", False))
    reports_dir = output_dir or batch_cfg.get("reports_dir") or cfg_get(config, "reports", "output_dir") or "./reports"
    save_pdf = cfg_get(config, "reports", "save_pdf", default=True)

    resolved_list_file = list_file or batch_cfg.get("list_file")
    if not resolved_list_file:
        console.print(f"[red]✘[/red] {t('cli_batch_list_missing')}")
        raise SystemExit(1)
    resolved_list_file = Path(resolved_list_file)
    if not resolved_list_file.exists():
        console.print(f"[red]✘[/red] {t('cli_batch_file_not_found', path=resolved_list_file)}")
        raise SystemExit(1)

    raw_lines = resolved_list_file.read_text(encoding="utf-8").splitlines()
    targets = [l.strip() for l in raw_lines if l.strip() and not l.strip().startswith("#")]
    if not targets:
        console.print(f"[yellow]{t('cli_batch_empty_list')}[/yellow]")
        return

    static_workers = int(cfg_get(config, "queue", "static_workers", default=4))
    engine = QueueEngine(
        config_path=config_path,
        db_path=db_path_from_config(config),
        static_workers=static_workers,
    )
    # Streamea la salida de cada job en vivo, prefijada por job id — con
    # varios jobs corriendo en paralelo, sin esto la terminal quedaría muda
    # hasta que cada uno termine.
    engine.on_line = lambda job_id, line: console.print(f"[dim]\\[job #{job_id}][/dim] {line}")

    console.print(
        f"[bold cyan]Batch scan:[/bold cyan] "
        f"{t('cli_batch_scan_header', count=len(targets), file=str(resolved_list_file))}"
        f"  [dim](static_workers={static_workers})[/dim]"
    )
    console.rule()

    results_summary: list[dict] = []
    stop_requested = {"flag": False}

    def _on_result(outcome: JobOutcome) -> None:
        icon = "[green]✔[/green]" if outcome.ok else "[red]✘[/red]"
        console.print(f"{icon} {outcome.package or outcome.job.target}")
        results_summary.append(_summary_for_outcome(engine.db_path, outcome))
        if not outcome.ok and _stop_on_err:
            stop_requested["flag"] = True

    if static_workers <= 1:
        # Secuencial de verdad: encola y drena de a un target por vez para
        # que --stop-on-error pueda cortar antes del siguiente.
        for target in targets:
            if stop_requested["flag"]:
                break
            engine.submit(target, kind="static")
            engine.drain(on_result=_on_result)
    else:
        # Paralelo: se encolan todos de una — --stop-on-error ya no puede
        # cancelar jobs que el pool ya empezó a correr (QueueEngine no
        # soporta cancelación a mitad de camino).
        engine.submit_many(targets, kind="static")
        engine.drain(on_result=_on_result)

    console.rule()
    console.print(f"\n[bold]{t('cli_batch_summary_header', count=len(results_summary))}[/bold]\n")
    ok = [r for r in results_summary if "error" not in r["status"]]
    errors = [r for r in results_summary if "error" in r["status"]]
    broken = [r for r in ok if r["status"] == "protected_broken"]
    console.print(f"  [green]{t('cli_batch_ok_label')}[/green]              {len(ok)}")
    console.print(f"  [red]{t('cli_batch_errors_label')}[/red]         {len(errors)}")
    console.print(f"  [yellow]{t('cli_batch_broken_label')}[/yellow]  {len(broken)}")

    if errors:
        console.print(f"\n[dim]{t('cli_batch_error_targets')}[/dim]")
        for r in errors:
            console.print(f"  - {r['target']}  ({(r.get('error') or '')[:80]})")

    if save_pdf and len(results_summary) > 1:
        from nutcracker_core.pdf_reporter import generate_batch_report
        batch_pdf = Path(reports_dir) / "batch_report.pdf"
        generate_batch_report(results_summary, batch_pdf)
        console.print(f"\n[bold green]✔[/bold green] {t('cli_batch_consolidated_report')} [bold]{batch_pdf}[/bold]")

    orch._print_elapsed(t("cli_elapsed_batch"), time.perf_counter() - started_at)
