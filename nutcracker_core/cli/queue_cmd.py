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
@click.option("--then-aipwn", "then_aipwn", is_flag=True, default=False,
              help="Encadena un job aipwn tras cada job estático que termine OK -- "
                   "para procesar en cola un list_file completo (análisis estático + "
                   "bypass aipwn para cada package, en orden). No combinar con "
                   "--dynamic/--aipwn (implica un job estático como base).")
@click.option(
    "--source", "-s",
    default=None,
    type=click.Choice(["apk-pure", "google-play", "device"], case_sensitive=False),
    help="Fuente del .apk para jobs estáticos con TARGET=package id o list_file de "
         "package ids. \"device\" extrae el .apk ya instalado en el dispositivo "
         "--serial (adb pull) en vez de descargarlo de una store -- aplica a TODAS "
         "las entradas del list_file por igual (flag global, no por línea).",
)
@click.option("--serial", default=None, help="Serial ADB para job dinámico/aipwn/--source device.")
@click.option("--run", "run_now", is_flag=True, default=False,
              help="Ejecutar la cola inmediatamente tras encolar (bloqueante).")
def queue_add(target: str, config_path: str, dynamic: bool, aipwn: bool, then_aipwn: bool,
              source: str | None, serial: str | None, run_now: bool) -> None:
    """Encola TARGET: ruta a .apk local, URL, package id, o un list_file con una
    entrada por línea (mismo formato que `nutcracker batch`).

    Con --then-aipwn y un list_file de package ids, cada uno recibe primero un
    análisis estático y, si termina OK, un job aipwn encadenado a continuación
    -- útil para programar en cola varios escaneos + bypass desde un .txt.
    """
    if then_aipwn and (dynamic or aipwn):
        console.print("[red]✘[/red] --then-aipwn no se combina con --dynamic/--aipwn.")
        raise SystemExit(1)

    engine = _build_engine(config_path)
    targets = _read_targets(target)
    kind = "aipwn" if aipwn else ("dynamic" if dynamic else "static")

    jobs = []
    for t in targets:
        try:
            jobs.append(engine.submit(t, kind=kind, serial=serial, source=source))
        except ValueError as exc:
            console.print(f"[red]✘[/red] {t}: {exc}")

    console.print(f"[green]✔[/green] {len(jobs)} job(s) encolado(s) ({kind}).")

    if not (run_now and jobs):
        return

    pending_aipwn: list[str] = []

    def _on_result(o):  # noqa: ANN001
        icon = "✔" if o.ok else "✘"
        color = "green" if o.ok else "red"
        extra = f"  package={o.package}" if o.package else ""
        console.print(f"  [{color}]{icon}[/{color}] {o.job.target}{extra}")
        if then_aipwn and o.job.kind == "static" and o.ok and o.package:
            pending_aipwn.append(o.package)

    outcomes = engine.drain(on_result=_on_result)

    if pending_aipwn:
        console.print(f"\n[bold]→[/bold] encadenando aipwn para {len(pending_aipwn)} package(s)...")
        for pkg in pending_aipwn:
            engine.submit(pkg, kind="aipwn", serial=serial)
        outcomes += engine.drain(on_result=_on_result)

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


@queue.command("rm")
@click.argument("job_id", type=int, nargs=-1, required=True)
@click.option("--config", "-c", "config_path", default="config.yaml", show_default=True)
def queue_rm(job_id: tuple[int, ...], config_path: str) -> None:
    """Borra uno o más jobs pendientes (status='queued') de la cola por ID.

    No afecta jobs 'running' (ya despachados a un worker en algún proceso --
    no hay forma de "des-despacharlos" borrando la fila) ni 'done'/'error'
    (son historial, no cola pendiente).
    """
    config = load_config(config_path)
    conn = db.connect(db_path_from_config(config))
    try:
        for jid in job_id:
            if repository.delete_job(conn, jid):
                console.print(f"[green]✔[/green] job #{jid} borrado")
            else:
                console.print(
                    f"[yellow]⚠[/yellow] job #{jid} no existe o ya no está 'queued'"
                )
    finally:
        conn.close()
