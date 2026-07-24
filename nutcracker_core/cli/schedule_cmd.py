"""Comando `nutcracker schedule`: revisión periódica automática por app (Fase 1.2)."""

from __future__ import annotations

import click

from nutcracker_core.config import load_config
from nutcracker_core.store import db, repository
from nutcracker_core.store.hooks import db_path_from_config

from . import cli
from ..orchestrator import console


@cli.group()
def schedule() -> None:
    """Gestiona la revisión periódica automática por app (mín. recomendado: 1/mes)."""


@schedule.command("set")
@click.argument("package")
@click.option("--config", "-c", "config_path", default="config.yaml", show_default=True)
@click.option("--every", "every_days", type=int, default=30, show_default=True,
              help="Intervalo en días entre revisiones (por defecto 30 = ≥1/mes).")
@click.option("--disable", is_flag=True, default=False, help="Deshabilita la revisión periódica.")
def schedule_set(package: str, config_path: str, every_days: int, disable: bool) -> None:
    """Agenda revisiones periódicas de PACKAGE cada --every días."""
    config = load_config(config_path)
    conn = db.connect(db_path_from_config(config))
    try:
        repository.set_schedule(conn, package, interval_days=every_days, enabled=not disable)
    finally:
        conn.close()
    state = " [dim](deshabilitado)[/dim]" if disable else ""
    console.print(f"[green]✔[/green] {package}: cada {every_days} día(s){state}")


@schedule.command("ls")
@click.option("--config", "-c", "config_path", default="config.yaml", show_default=True)
def schedule_ls(config_path: str) -> None:
    """Lista todas las apps con revisión periódica configurada."""
    config = load_config(config_path)
    conn = db.connect(db_path_from_config(config))
    try:
        rows = repository.list_schedules(conn)
        apps = {r["package"]: repository.get_app(conn, r["package"]) for r in rows}
    finally:
        conn.close()

    if not rows:
        console.print("[dim](sin schedules)[/dim]")
        return

    for r in rows:
        state = "on" if r["enabled"] else "off"
        app = apps.get(r["package"])
        due = f"  next_due={app['next_due_at']}" if app and app["next_due_at"] else ""
        console.print(f"  {r['package']:<40} cada {r['interval_days']}d  [{state}]{due}")
