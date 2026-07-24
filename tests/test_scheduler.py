"""Tests de nutcracker_core/scheduler.py (Fase 1.2 del plan)."""

from __future__ import annotations

from nutcracker_core.scheduler import NutcrackerScheduler


class _StubEngine:
    def __init__(self, due: int = 0):
        self._due = due
        self.enqueue_calls = 0
        self.drain_calls = 0

    def enqueue_due_apps(self) -> int:
        self.enqueue_calls += 1
        return self._due

    def drain(self):
        self.drain_calls += 1
        return []


def test_tick_drains_when_apps_are_due():
    engine = _StubEngine(due=3)
    sched = NutcrackerScheduler(engine, config={})
    sched._tick()
    assert engine.enqueue_calls == 1
    assert engine.drain_calls == 1


def test_tick_still_drains_when_nothing_due():
    """drain() debe correr en cada tick aunque no haya apps vencidas: puede
    haber jobs encolados manualmente (`queue add`, sin --run) esperando desde
    un tick anterior, y drain() es barato cuando no hay nada pendiente."""
    engine = _StubEngine(due=0)
    sched = NutcrackerScheduler(engine, config={})
    sched._tick()
    assert engine.enqueue_calls == 1
    assert engine.drain_calls == 1


def test_tick_never_raises_on_engine_failure():
    class _Boom(_StubEngine):
        def enqueue_due_apps(self):
            raise RuntimeError("db is on fire")

    sched = NutcrackerScheduler(_Boom(), config={})
    sched._tick()  # no debe propagar la excepción


def test_start_respects_scheduler_enabled_false():
    engine = _StubEngine()
    sched = NutcrackerScheduler(engine, config={"scheduler": {"enabled": False}})
    sched.start()
    assert sched._started is False
    sched.stop()  # no-op seguro, no debe fallar aunque nunca arrancó


def test_start_and_stop_lifecycle():
    engine = _StubEngine()
    sched = NutcrackerScheduler(engine, config={"scheduler": {"enabled": True, "poll_interval_minutes": 60}})
    sched.start()
    assert sched._started is True
    assert sched._sched.running is True
    sched.stop()
    assert sched._sched.running is False
