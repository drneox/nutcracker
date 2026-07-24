"""Comando `nutcracker setup-token`: wizard interactivo para el aas_token de Google Play."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click

from nutcracker_core.config import load_config
from nutcracker_core.i18n import t
from nutcracker_core import orchestrator as orch
from nutcracker_core.orchestrator import console

from . import cli


@cli.command("setup-token")
@click.option(
    "--config", "config_path",
    default="config.yaml",
    show_default=True,
    metavar="ARCHIVO",
    help="Path to YAML config file.",
)
@click.option("--serial", default=None, help="ADB serial of the target device.")
@click.option(
    "--method",
    default="auto",
    type=click.Choice(["auto", "root", "dumpsys", "gsf"], case_sensitive=False),
    show_default=True,
    help="Token extraction method.",
)
@click.option("--no-interactive", is_flag=True, default=False, help="Skip confirmation prompts.")
def setup_token(config_path: str, serial: str | None, method: str, no_interactive: bool) -> None:
    """Interactive wizard to obtain and save google_play.aas_token."""
    script = Path(__file__).parent.parent.parent / "tools" / "extract_token.py"
    if not script.exists():
        console.print(f"[red]Error:[/red] {t('cli_extract_token_not_found')}")
        raise SystemExit(1)

    cfg = load_config(config_path)
    auto_serial = serial or orch._select_token_serial(cfg)

    cmd = [sys.executable, str(script), "--config", config_path, "--method", method.lower()]
    if auto_serial:
        cmd += ["--serial", auto_serial]
    if no_interactive:
        cmd.append("--no-interactive")

    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)
