"""Comando `nutcracker queue`: gestión de la cola de jobs (Fase 1 del plan)."""

from __future__ import annotations

from pathlib import Path

import click

from nutcracker_core.config import load_config, get as cfg_get
from nutcracker_core.queue.engine import QueueEngine
from nutcracker_core.store import db, repository
from nutcracker_core.store.hooks import db_path_from_config

from . import cli
from ..orchestrator import console


def _read_targets(target: str) -> list[str]:
    """Si `target` es un list_file existente (una entrada por línea, igual que
    `nutcracker batch`), lo expande; si no, lo trata como un target único."""
    p = Path(target)
    if p.is_file() and not target.lower().endswith(".apk"):
        lines = p.read_text(encoding="utf-8").splitlines()
        return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    return [target]


def _build_engine(config_path: str) -> QueueEngine:
    config = load_config(config_path)
    return QueueEngine(
        config_path=config_path,
        db_path=db_path_from_config(config),
        static_workers=int(cfg_get(config, "queue", "static_workers", default=4)),
        dynamic_workers=int(cfg_get(config, "queue", "dynamic_workers", default=2)),
    )


@cli.group()
def queue() -> None:
    """Gestiona la cola de jobs de análisis (estático/dinámico)."""


@queue.command("add")
@click.argument("target")
@click.option("--config", "-c", "config_path", default="config.yaml", show_default=True)
@click.option("--dynamic", is_flag=True, default=False,
              help="Job dinámico (Frida/ADB sobre dispositivo). Requiere .apk local.")
@click.option("--aipwn", is_flag=True, default=False,
              help="Job del agente de bypass aipwn (Frida+LLM). TARGET es un package id "
                   "ya analizado previamente, no una ruta/URL de APK.")
@click.option("--serial", default=None, help="Serial ADB para job dinámico/aipwn.")
@click.option("--run", "run_now", is_flag=True, default=False,
              help="Ejecutar la cola inmediatamente tras encolar (bloqueante).")
def queue_add(target: str, config_path: str, dynamic: bool, aipwn: bool,
              serial: str | None, run_now: bool) -> None:
    """Encola TARGET: ruta a .apk local, URL, package id, o un list_file con una
    entrada por línea (mismo formato que `nutcracker batch`)."""
    engine = _build_engine(config_path)
    targets = _read_targets(target)
    kind = "aipwn" if aipwn else ("dynamic" if dynamic else "static")

    jobs = []
    for t in targets:
        try:
            jobs.append(engine.submit(t, kind=kind, serial=serial))
        except ValueError as exc:
            console.print(f"[red]✘[/red] {t}: {exc}")

    console.print(f"[green]✔[/green] {len(jobs)} job(s) encolado(s) ({kind}).")

    if run_now and jobs:
        def _on_result(o):  # noqa: ANN001
            icon = "✔" if o.ok else "✘"
            color = "green" if o.ok else "red"
            extra = f"  package={o.package}" if o.package else ""
            console.print(f"  [{color}]{icon}[/{color}] {o.job.target}{extra}")

        outcomes = engine.drain(on_result=_on_result)
        n_ok = sum(1 for o in outcomes if o.ok)
        console.print(f"\n[bold]Resumen:[/bold] {n_ok}/{len(outcomes)} OK")


@queue.command("ls")
@click.option("--config", "-c", "config_path", default="config.yaml", show_default=True)
@click.option("--status", default=None,
              type=click.Choice(["queued", "running", "done", "error"]))
@click.option("--limit", default=20, show_default=True)
def queue_ls(config_path: str, status: str | None, limit: int) -> None:
    """Lista jobs recientes de la cola."""
    config = load_config(config_path)
    conn = db.connect(db_path_from_config(config))
    try:
        rows = repository.list_jobs(conn, status=status, limit=limit)
    finally:
        conn.close()

    if not rows:
        console.print("[dim](sin jobs)[/dim]")
        return

    colors = {"queued": "cyan", "running": "yellow", "done": "green", "error": "red"}
    for r in rows:
        color = colors.get(r["status"], "white")
        pkg = f"  pkg={r['package']}" if r["package"] else ""
        console.print(
            f"  #{r['id']:<5} [{color}]{r['status']:<8}[/{color}] {r['kind']:<8} {r['target']}{pkg}"
        )
