"""Comando `nutcracker scan`: descarga un APK y lo analiza."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn

from nutcracker_core.config import load_config, get as cfg_get
from nutcracker_core.downloader import (
    DirectURLDownloader,
    APKDownloadError,
    is_direct_apk_url,
    download_apk_from_config,
)
from nutcracker_core.i18n import t
from nutcracker_core import orchestrator as orch
from nutcracker_core.orchestrator import console

from . import cli


@cli.command()
@click.argument("url")
@click.option(
    "--config", "-c",
    "config_path",
    default="config.yaml",
    show_default=True,
    metavar="ARCHIVO",
    help="Path to YAML config file.",
)
@click.option(
    "--source", "-s",
    default=None,
    type=click.Choice(["apk-pure", "google-play"], case_sensitive=False),
    help="Download source. Default: google-play if credentials in config, else apk-pure.",
)
@click.option(
    "--output-dir", "-o",
    default=None,
    help="Directory to save downloaded APKs.",
)
@click.option(
    "--keep-apk",
    is_flag=True,
    default=False,
    help="Keep the APK after analysis.",
)
@click.option(
    "--report", "-r",
    default=None,
    metavar="ARCHIVO",
    help="Path to save the JSON report.",
)
@click.option(
    "--static-only",
    is_flag=True,
    default=False,
    help="Force jadx-only decompilation and skip Frida/device runtime steps "
         "(used by queued/scheduled batch runs; see `nutcracker queue`/`serve`).",
)
def scan(url: str, config_path: str, source: str | None, output_dir: str | None,
         keep_apk: bool, report: str | None, static_only: bool) -> None:
    """
    Download an APK and analyze it for anti-root protections.

    URL can be:
      - Google Play URL (https://play.google.com/store/apps/details?id=...)
      - Package ID directly (com.example.app)
      - Direct URL to an .apk file (https://example.com/app.apk)
    """
    config = load_config(config_path)
    if static_only:
        orch.apply_static_only_override(config)
    orch._CFG = config
    orch._init_i18n(config)
    output_dir = output_dir or cfg_get(config, "downloader", "output_dir") or "./downloads"

    if not keep_apk:
        keep_apk = bool(cfg_get(config, "downloader", "keep_apk", default=False))

    # Informe JSON automático si está configurado
    save_json_cfg = bool(
        cfg_get(config, "features", "report_json", default=cfg_get(config, "reports", "save_json", default=False))
    )
    if not report and save_json_cfg and not is_direct_apk_url(url):
        reports_dir = cfg_get(config, "reports", "output_dir") or "./reports"
        Path(reports_dir).mkdir(parents=True, exist_ok=True)
        pkg = url.split("id=")[-1].split("&")[0].rstrip("/")
        report = str(Path(reports_dir) / f"{pkg}.json")
    save_pdf = bool(
        cfg_get(config, "features", "report_pdf", default=cfg_get(config, "reports", "save_pdf", default=True))
    )

    def _token_resolver(email: str, cfg: dict) -> str | None:
        """Genera el aas_token interactivamente si falta, recarga config y lo devuelve."""
        nonlocal config
        console.print(f"[yellow]Warning:[/yellow] {t('cli_gplay_token_empty')}")
        script = Path(__file__).parent.parent.parent / "tools" / "extract_token.py"
        if not script.exists():
            console.print(f"[red]Error:[/red] {t('cli_extract_token_not_found')}")
            sys.exit(1)
        cmd = [sys.executable, str(script), "--config", config_path]
        preferred_serial = orch._select_token_serial(cfg)
        if preferred_serial:
            cmd += ["--serial", preferred_serial]
        if orch._unattended():
            cmd.append("--no-interactive")
        token_proc = subprocess.run(cmd)
        if token_proc.returncode != 0:
            console.print(f"[red]Error:[/red] {t('cli_token_gen_failed')}")
            sys.exit(token_proc.returncode)
        config = load_config(config_path)
        orch._CFG = config
        token = cfg_get(config, "google_play", "aas_token")
        if not token:
            console.print(f"[red]Error:[/red] {t('cli_token_still_empty')}")
            sys.exit(1)
        return token

    def _on_start(label: str) -> None:
        _on_start._progress_ctx.__enter__()
        _on_start._progress_ctx.add_task(t("cli_downloading_from", label=label), total=None)

    # Progreso para URL directa (con BarColumn) o spinner para stores
    _progress_direct: Progress | None = None
    _progress_store: Progress | None = None
    _task_ref: list = []

    def _progress_callback(downloaded: int, total: int | None) -> None:
        if _progress_direct and _task_ref:
            _progress_direct.update(_task_ref[0], completed=downloaded, total=total)

    def _on_start_label(label: str) -> None:
        nonlocal _progress_store
        _progress_store.__enter__()
        _progress_store.add_task(t("cli_downloading_from", label=label), total=None)

    apk_path: Path | None = None
    _from_cache = False
    try:
        if is_direct_apk_url(url):
            _dl_check = DirectURLDownloader(output_dir)
            _from_cache = keep_apk and _dl_check.dest_path(url).exists()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                console=console,
                transient=True,
            ) as _progress_direct:
                _task = _progress_direct.add_task(t("cli_downloading_apk"), total=None)
                _task_ref.append(_task)
                apk_path = download_apk_from_config(
                    url, config,
                    output_dir=output_dir,
                    use_cache=keep_apk,
                    progress_callback=_progress_callback,
                )
        else:
            if source == "google-play":
                email = cfg_get(config, "google_play", "email")
                if not email:
                    console.print(f"[red]Error:[/red] {t('cli_gplay_requires_email')}")
                    sys.exit(1)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as _progress_store:
                apk_path = download_apk_from_config(
                    url, config,
                    source=source,
                    output_dir=output_dir,
                    token_resolver=_token_resolver,
                    on_start=_on_start_label,
                )

        if _from_cache:
            console.print(f"[green]✔[/green] {t('cli_apk_cached')} [bold]{apk_path}[/bold]")
        else:
            console.print(f"[green]✔[/green] {t('cli_apk_downloaded')} [bold]{apk_path}[/bold]")
    except APKDownloadError as exc:
        console.print(f"[red]{t('cli_error_download')}[/red] {exc}")
        sys.exit(1)

    orch._run_analysis(apk_path, report, keep_apk, gen_pdf=cfg_get(config, "reports", "save_pdf", default=True))
