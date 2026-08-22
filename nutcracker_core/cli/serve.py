"""Comando `nutcracker serve`: daemon con cola + scheduler (Fase 1 del plan)."""

from __future__ import annotations

import signal
import time

import click

from nutcracker_core import adb_transport
from nutcracker_core.config import load_config, get as cfg_get
from nutcracker_core.queue.engine import QueueEngine
from nutcracker_core.scheduler import NutcrackerScheduler
from nutcracker_core.store.hooks import db_path_from_config

from . import cli
from ..orchestrator import console


@cli.command()
@click.option(
    "--config", "-c",
    "config_path",
    default="config.yaml",
    show_default=True,
    metavar="ARCHIVO",
)
def serve(config_path: str) -> None:
    """Arranca el daemon de nutcracker: cola paralela/secuencial + scheduler
    periódico que garantiza revisiones mínimas por APK (bloque `scheduler:` en
    config.yaml; por defecto, cada 30 días). Ctrl+C para detener."""
    config = load_config(config_path)
    engine = QueueEngine(
        config_path=config_path,
        db_path=db_path_from_config(config),
        static_workers=int(cfg_get(config, "queue", "static_workers", default=4)),
        dynamic_workers=int(cfg_get(config, "queue", "dynamic_workers", default=2)),
    )
    # Mantiene vivo el serial adb-over-wifi mientras el daemon corre (ver
    # nutcracker_core/adb_transport.py): esa conexión no sobrevive a un
    # reinicio del daemon adb ni a un corte de red del teléfono, y sin ella los
    # jobs dinámicos fallan con "device not found" aunque el teléfono esté ahí.
    default_serial = str(
        cfg_get(config, "strategies", "default_device_id", default="")
    ).strip()
    keepalive = adb_transport.TransportKeepAlive(
        serials=[default_serial] if default_serial else [],
    )
    engine.transport_keepalive = keepalive
    keepalive.start()

    scheduler = NutcrackerScheduler(engine, config)
    scheduler.start()

    console.print(
        f"[bold green]✔[/bold green] nutcracker serve — daemon activo "
        f"(static_workers={engine.static_workers}, dynamic_workers={engine.dynamic_workers}) "
        f"— Ctrl+C para detener"
    )

    _stop = {"flag": False}

    def _handle_sigterm(signum, frame):  # noqa: ANN001
        _stop["flag"] = True

    signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        while not _stop["flag"]:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        keepalive.stop()
        scheduler.stop()
        console.print("[dim]nutcracker serve — detenido[/dim]")
