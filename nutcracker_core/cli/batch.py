"""Comando `nutcracker batch`: escanea una lista de APKs/URLs."""

from __future__ import annotations

import time
from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn

from nutcracker_core.analyzer import APKAnalyzer
from nutcracker_core.config import load_config, get as cfg_get
from nutcracker_core.downloader import (
    APKPureDownloader,
    GooglePlayDownloader,
    DirectURLDownloader,
    APKDownloadError,
    is_direct_apk_url,
)
from nutcracker_core.i18n import t
from nutcracker_core.reporter import save_analysis_json
from nutcracker_core import orchestrator as orch
from nutcracker_core.orchestrator import console

from . import cli


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
    help="Directory to save PDF/JSON reports.",
)
@click.option(
    "--keep-apk",
    is_flag=True,
    default=False,
    help="Keep downloaded APKs after each analysis.",
)
@click.option(
    "--stop-on-error",
    is_flag=True,
    default=False,
    help="Stop on first error (default: continue).",
)
def batch(
    list_file: str | None,
    config_path: str,
    output_dir: str | None,
    keep_apk: bool,
    stop_on_error: bool,
) -> None:
    """
    Scan a list of APKs or URLs in batch mode.

    LIST_FILE is a text file with one entry per line:
      - Google Play URLs   (https://play.google.com/...)
      - Package IDs        (com.example.app)
      - Direct APK URLs    (https://cdn.example.com/app.apk)
      - Local APK paths    (/path/to/app.apk)

    Lines starting with '#' or empty lines are ignored.
    """
    started_at = time.perf_counter()
    config = load_config(config_path)
    orch._CFG = config
    orch._init_i18n(config)

    batch_cfg   = cfg_get(config, "batch") or {}
    _keep_apk   = keep_apk or bool(batch_cfg.get("keep_apk",   cfg_get(config, "downloader", "keep_apk", default=False)))
    _stop_on_err = stop_on_error or bool(batch_cfg.get("stop_on_error", False))
    reports_dir = output_dir or batch_cfg.get("reports_dir") or cfg_get(config, "reports", "output_dir") or "./reports"
    dl_dir      = batch_cfg.get("download_dir") or cfg_get(config, "downloader", "output_dir") or "./downloads"
    save_pdf    = cfg_get(config, "reports", "save_pdf", default=True)

    # Resolver list_file: CLI > config batch.list_file
    resolved_list_file = list_file or batch_cfg.get("list_file")
    if not resolved_list_file:
        console.print(f"[red]✘[/red] {t('cli_batch_list_missing')}")
        raise SystemExit(1)
    resolved_list_file = Path(resolved_list_file)
    if not resolved_list_file.exists():
        console.print(f"[red]✘[/red] {t('cli_batch_file_not_found', path=resolved_list_file)}")
        raise SystemExit(1)

    # Leer lista de targets
    raw_lines = resolved_list_file.read_text(encoding="utf-8").splitlines()
    targets = [l.strip() for l in raw_lines if l.strip() and not l.strip().startswith("#")]

    if not targets:
        console.print(f"[yellow]{t('cli_batch_empty_list')}[/yellow]")
        return

    console.print(f"[bold cyan]Batch scan:[/bold cyan] {t('cli_batch_scan_header', count=len(targets), file=list_file)}")
    console.rule()

    results_summary: list[dict] = []

    for idx, target in enumerate(targets, 1):
        console.print(f"\n[bold][[{idx}/{len(targets)}]][/bold] {target}")

        apk_path: Path | None = None
        is_local = Path(target).exists() and target.lower().endswith(".apk")

        # ── Descarga si no es local ───────────────────────────────────────────
        if not is_local:
            try:
                if is_direct_apk_url(target):
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        DownloadColumn(),
                        TransferSpeedColumn(),
                        console=console,
                        transient=True,
                    ) as progress:
                        task = progress.add_task(t("cli_batch_downloading"), total=None)
                        def _on_chunk(dl: int, tot: int | None) -> None:
                            progress.update(task, completed=dl, total=tot)
                        apk_path = DirectURLDownloader(dl_dir).download(target, progress_callback=_on_chunk, use_cache=_keep_apk)
                else:
                    # Google Play / APKPure
                    email     = cfg_get(config, "google_play", "email")
                    aas_token = cfg_get(config, "google_play", "aas_token")
                    if email and aas_token:
                        dl = GooglePlayDownloader(email, aas_token, dl_dir)
                    else:
                        dl = APKPureDownloader(dl_dir)
                    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                                  console=console, transient=True) as progress:
                        progress.add_task(t("cli_batch_downloading"), total=None)
                        apk_path = dl.download(target)
                console.print(f"  [green]✔[/green] {t('cli_batch_downloaded', name=apk_path.name)}")
            except APKDownloadError as exc:
                console.print(f"  [red]{t('cli_batch_download_error')}[/red] {exc}")
                results_summary.append({"target": target, "status": "error_download", "error": str(exc)})
                if _stop_on_err:
                    break
                continue
        else:
            apk_path = Path(target)

        # ── Análisis ──────────────────────────────────────────────────────────
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          console=console, transient=True) as progress:
                task = progress.add_task(t("cli_batch_analyzing"), total=None)
                def on_prog(msg: str) -> None:
                    progress.update(task, description=msg)
                analyzer = APKAnalyzer(progress_callback=on_prog)
                result = analyzer.analyze(apk_path)

            # PDF individual por app
            pkg = result.package
            pdf_path: Path | None = None
            if save_pdf:
                pkg_dir = Path(reports_dir) / pkg
                pkg_dir.mkdir(parents=True, exist_ok=True)
                pdf_dest = pkg_dir / f"nutcracker_{pkg}_report.pdf"
                scan_result = orch._post_analysis_flow(result, apk_path)
                # Guardar JSON una vez que todos los datos están completos
                save_analysis_json(result, scan_result=scan_result, manifest=orch._MANIFEST_ANALYSIS)
                from nutcracker_core.pdf_reporter import generate_pdf_report
                pdf_path = generate_pdf_report(result, pdf_dest, scan=scan_result, manifest=orch._MANIFEST_ANALYSIS)
                console.print(f"  [green]✔[/green] PDF: [bold]{pdf_path}[/bold]")
            else:
                scan_result = orch._post_analysis_flow(result, apk_path)
                # Guardar JSON una vez que todos los datos están completos
                save_analysis_json(result, scan_result=scan_result, manifest=orch._MANIFEST_ANALYSIS)

            status = "protected_broken" if result.protection_broken \
                else ("protected" if result.protected else "unprotected")

            # Enriquecer datos para reporte batch consolidado
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            leaks_count = 0
            top_findings: list[tuple[str, str, str]] = []
            cat_max_sev: dict[str, str] = {}  # categoría → peor severidad
            if scan_result:
                seen_rules: set[str] = set()
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                for f in scan_result.findings:
                    sev = getattr(f, "severity", "info").lower()
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                    rid = getattr(f, "rule_id", "")
                    cat = getattr(f, "category", "")
                    # Peor severidad por categoría
                    if cat:
                        prev = cat_max_sev.get(cat, "info")
                        if sev_order.get(sev, 5) < sev_order.get(prev, 5):
                            cat_max_sev[cat] = sev
                    # Contar leaks
                    if rid.upper().startswith(("AL-", "HC", "GL-")):
                        leaks_count += 1
                    # Top findings (únicos por rule_id, ordenados por severidad)
                    if rid not in seen_rules:
                        seen_rules.add(rid)
                        top_findings.append((rid, getattr(f, "title", ""), sev))
                top_findings.sort(key=lambda x: sev_order.get(x[2], 5))
                top_findings = top_findings[:5]

            results_summary.append({
                "target":  target,
                "package": pkg,
                "status":  status,
                "pdf":     str(pdf_path) if pdf_path else None,
                "findings": len(scan_result.findings) if scan_result else 0,
                **sev_counts,
                "leaks": leaks_count,
                "top_findings": top_findings,
                "categories": cat_max_sev,
            })
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]{t('cli_batch_analysis_error')}[/red] {exc}")
            results_summary.append({"target": target, "status": "error_analysis", "error": str(exc)})
            if _stop_on_err:
                break

        finally:
            if not _keep_apk and apk_path and apk_path.exists() and not is_local:
                apk_path.unlink()

    # ── Resumen final ─────────────────────────────────────────────────────────
    console.rule()
    console.print(f"\n[bold]{t('cli_batch_summary_header', count=len(results_summary))}[/bold]\n")
    ok      = [r for r in results_summary if "error" not in r["status"]]
    errors  = [r for r in results_summary if "error" in r["status"]]
    broken  = [r for r in ok if r["status"] == "protected_broken"]
    console.print(f"  [green]{t('cli_batch_ok_label')}[/green]              {len(ok)}")
    console.print(f"  [red]{t('cli_batch_errors_label')}[/red]         {len(errors)}")
    console.print(f"  [yellow]{t('cli_batch_broken_label')}[/yellow]  {len(broken)}")

    if errors:
        console.print(f"\n[dim]{t('cli_batch_error_targets')}[/dim]")
        for r in errors:
            console.print(f"  - {r['target']}  ({r['error'][:80]})")

    # ── Reporte batch consolidado ─────────────────────────────────────────────
    if save_pdf and len(results_summary) > 1:
        from nutcracker_core.pdf_reporter import generate_batch_report
        batch_pdf = Path(reports_dir) / "batch_report.pdf"
        generate_batch_report(results_summary, batch_pdf)
        console.print(f"\n[bold green]✔[/bold green] {t('cli_batch_consolidated_report')} [bold]{batch_pdf}[/bold]")

    orch._print_elapsed(t("cli_elapsed_batch"), time.perf_counter() - started_at)
