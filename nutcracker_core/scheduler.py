"""Scheduler de nutcracker (Fase 1.2 del plan).

Garantiza revisiones periódicas mínimas por APK (por defecto, cada 30 días =
"≥1/mes"): en cada tick, encola en QueueEngine las apps cuyo ``next_due_at``
ya venció y drena la cola. El re-agendado del *siguiente* vencimiento ocurre
dentro de QueueEngine al terminar cada job (ver ``QueueEngine._reschedule``),
así el ciclo se sostiene solo sin lógica adicional aquí.
"""

from __future__ import annotations

import datetime
import logging

from apscheduler.schedulers.background import BackgroundScheduler

from nutcracker_core.config import get as cfg_get

_log = logging.getLogger(__name__)


class NutcrackerScheduler:
    """Envoltorio delgado sobre APScheduler para el tick periódico de la cola."""

    def __init__(self, engine, config: dict) -> None:
        self.engine = engine
        self.config = config
        self._sched = BackgroundScheduler()
        self._started = False

    def start(self) -> None:
        if not bool(cfg_get(self.config, "scheduler", "enabled", default=True)):
            _log.info("scheduler.enabled=false — no se agendan revisiones periódicas")
            return
        minutes = int(cfg_get(self.config, "scheduler", "poll_interval_minutes", default=60))
        self._sched.add_job(
            self._tick,
            "interval",
            minutes=minutes,
            next_run_time=datetime.datetime.now(),  # primer tick casi inmediato
            id="nutcracker-scheduler-tick",
            replace_existing=True,
        )
        self._sched.start()
        self._started = True
        _log.info("scheduler activo (cada %s min)", minutes)

    def _tick(self) -> None:
        try:
            n = self.engine.enqueue_due_apps()
            if n:
                _log.info("scheduler: %d app(s) vencida(s) encoladas", n)
            # drain() siempre corre (y es barato si no hay nada pendiente): además
            # de lo recién vencido, recoge cualquier job encolado manualmente
            # (`nutcracker queue add`, sin --run) desde el tick anterior.
            self.engine.drain()
        except Exception:  # noqa: BLE001
            _log.exception("scheduler: fallo en el tick periódico")

    def stop(self) -> None:
        if self._started and self._sched.running:
            self._sched.shutdown(wait=False)
