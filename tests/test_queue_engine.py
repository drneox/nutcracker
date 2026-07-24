"""Tests de nutcracker_core/queue/engine.py (Fase 1 del plan).

subprocess.run se reemplaza por un doble de prueba: lo que se ejercita aquí es
la mecánica de la cola (paralelismo estático, serialización por dispositivo,
transiciones de estado, re-agendado), no el pipeline de análisis real (ya
cubierto por Fase 0 / tests existentes).
"""

from __future__ import annotations

import subprocess
import threading
import time

import pytest

from nutcracker_core.queue.engine import QueueEngine
from nutcracker_core.store import db, repository


def _touch_apk(tmp_path, name: str):
    """Crea un archivo .apk vacío: basta para que _is_local_apk() lo acepte,
    ya que subprocess.run está mockeado y nunca se invoca androguard de verdad."""
    p = tmp_path / name
    p.write_bytes(b"PK\x03\x04")  # cabecera zip mínima, contenido irrelevante
    return p


@pytest.fixture
def engine(tmp_path):
    db_path = tmp_path / "queue_test.db"
    return QueueEngine(config_path="config.yaml", db_path=str(db_path),
                        static_workers=4, dynamic_workers=2)


# ── Paralelismo estático ────────────────────────────────────────────────────

def test_static_jobs_run_in_parallel(monkeypatch, tmp_path, engine):
    calls = []
    lock = threading.Lock()

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        start = time.monotonic()
        time.sleep(0.25)
        with lock:
            calls.append((start, time.monotonic()))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    for i in range(4):
        engine.submit(str(_touch_apk(tmp_path, f"app{i}.apk")), kind="static")

    t0 = time.monotonic()
    outcomes = engine.drain()
    elapsed = time.monotonic() - t0

    assert len(outcomes) == 4
    assert all(o.ok for o in outcomes)
    # 4 jobs de 0.25s con static_workers=4 deberían solaparse: muy por debajo
    # de 4*0.25=1.0s si corrieran en serie. Margen generoso para CI lento.
    assert elapsed < 0.7, f"jobs estáticos no parecen haber corrido en paralelo ({elapsed:.2f}s)"


def test_static_jobs_run_sequentially_with_one_worker(monkeypatch, tmp_path, tmp_path_factory):
    db_path = tmp_path / "seq.db"
    engine = QueueEngine(config_path="config.yaml", db_path=str(db_path), static_workers=1)

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        time.sleep(0.15)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    for i in range(3):
        engine.submit(str(_touch_apk(tmp_path, f"seq{i}.apk")), kind="static")

    t0 = time.monotonic()
    engine.drain()
    elapsed = time.monotonic() - t0

    # queue.mode "sequential" = pool de tamaño 1: 3 jobs de 0.15s deben tardar
    # ~0.45s (serie), no ~0.15s (paralelo).
    assert elapsed >= 0.40, f"static_workers=1 no serializó los jobs ({elapsed:.2f}s)"


# ── Serialización por dispositivo (jobs dinámicos) ──────────────────────────

def test_dynamic_jobs_same_serial_never_overlap(monkeypatch, tmp_path, engine):
    intervals: list[tuple[float, float]] = []
    lock = threading.Lock()

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        start = time.monotonic()
        time.sleep(0.2)
        end = time.monotonic()
        with lock:
            intervals.append((start, end))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    for i in range(2):
        engine.submit(str(_touch_apk(tmp_path, f"dyn{i}.apk")), kind="dynamic", serial="SAME-SERIAL")

    outcomes = engine.drain()
    assert len(outcomes) == 2 and all(o.ok for o in outcomes)

    (s1, e1), (s2, e2) = sorted(intervals)
    assert e1 <= s2, "dos jobs dinámicos con el mismo serial se solaparon (el lock por device falló)"


def test_dynamic_jobs_different_serials_run_in_parallel(monkeypatch, tmp_path, engine):
    intervals: list[tuple[float, float]] = []
    lock = threading.Lock()

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        start = time.monotonic()
        time.sleep(0.2)
        end = time.monotonic()
        with lock:
            intervals.append((start, end))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit(str(_touch_apk(tmp_path, "devA.apk")), kind="dynamic", serial="DEVICE-A")
    engine.submit(str(_touch_apk(tmp_path, "devB.apk")), kind="dynamic", serial="DEVICE-B")

    outcomes = engine.drain()
    assert len(outcomes) == 2 and all(o.ok for o in outcomes)

    (s1, e1), (s2, e2) = sorted(intervals)
    # Solapan si el segundo empieza antes de que termine el primero.
    assert s2 < e1, "jobs dinámicos en dispositivos distintos no corrieron en paralelo"


def test_dynamic_job_requires_local_apk(engine):
    with pytest.raises(ValueError):
        engine.submit("com.example.app", kind="dynamic", serial="X")


# ── Estado en SQLite ─────────────────────────────────────────────────────────

def test_job_status_transitions_and_error_recorded(monkeypatch, tmp_path, engine):
    def fake_run_fail(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom: jadx not found")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run_fail)

    job = engine.submit(str(_touch_apk(tmp_path, "broken.apk")), kind="static")
    outcomes = engine.drain()

    assert len(outcomes) == 1 and outcomes[0].ok is False
    assert "boom" in outcomes[0].error

    conn = db.connect(engine.db_path)
    try:
        row = repository.get_job(conn, job.db_id)
    finally:
        conn.close()
    assert row["status"] == "error"
    assert "boom" in row["error"]
    assert row["started_at"] is not None and row["finished_at"] is not None


# ── Re-agendado tras completar un job (Fase 1.2) ────────────────────────────

def test_reschedule_sets_next_due_at_after_job_completes(monkeypatch, tmp_path, engine):
    """Simula lo que hace store/hooks.py en el subproceso real: enlaza el job
    con un run_id/package vía repository.link_job_run. QueueEngine debe leer
    ese package de vuelta y fijar next_due_at (~30 días) automáticamente."""

    def fake_run_ok(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        job_id = int(env["NUTCRACKER_QUEUE_JOB_ID"])
        conn = db.connect(engine.db_path)
        try:
            run_id = repository.insert_run(conn, "com.example.testapp", kind="static", status="done")
            repository.link_job_run(conn, job_id, run_id, "com.example.testapp")
        finally:
            conn.close()
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run_ok)

    engine.submit(str(_touch_apk(tmp_path, "sched.apk")), kind="static")
    outcomes = engine.drain()
    assert outcomes[0].ok and outcomes[0].package == "com.example.testapp"

    conn = db.connect(engine.db_path)
    try:
        app = repository.get_app(conn, "com.example.testapp")
        sched = repository.get_schedule(conn, "com.example.testapp")
    finally:
        conn.close()

    assert app["next_due_at"] is not None
    assert sched is not None and sched["interval_days"] == 30  # default_interval_days


# ── enqueue_due_apps ──────────────────────────────────────────────────────────

def test_drain_picks_up_jobs_queued_by_a_different_engine_instance(monkeypatch, tmp_path):
    """Reproduce el bug encontrado en la POC manual: `nutcracker queue add` sin
    --run corre en un proceso CLI separado de `nutcracker queue add --run` (o
    de `nutcracker serve`) — cada uno crea su propia QueueEngine con `_pending`
    vacío. Sin cargar los jobs 'queued' desde SQLite, drain() de la segunda
    instancia nunca vería el job que encoló la primera."""
    db_path = tmp_path / "shared.db"
    apk = _touch_apk(tmp_path, "from_process_a.apk")

    engine_a = QueueEngine(config_path="config.yaml", db_path=str(db_path))
    job = engine_a.submit(str(apk), kind="static")
    # engine_a nunca llama drain(): simula un `queue add` (sin --run) que
    # termina el proceso justo después de encolar.

    engine_b = QueueEngine(config_path="config.yaml", db_path=str(db_path))

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    outcomes = engine_b.drain()

    assert len(outcomes) == 1
    assert outcomes[0].job.db_id == job.db_id
    assert outcomes[0].ok is True

    conn = db.connect(str(db_path))
    try:
        row = repository.get_job(conn, job.db_id)
    finally:
        conn.close()
    assert row["status"] == "done"


def test_drain_does_not_rerun_jobs_already_pending_in_memory(monkeypatch, tmp_path, engine):
    """_load_queued_from_db() no debe duplicar un job que ya está en self._pending
    (mismo proceso: submit() + drain() sin reiniciar)."""
    run_count = {"n": 0}

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        run_count["n"] += 1
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit(str(_touch_apk(tmp_path, "once.apk")), kind="static")
    outcomes = engine.drain()

    assert len(outcomes) == 1
    assert run_count["n"] == 1


# ── Streaming en vivo (Fase 3: dashboard) ───────────────────────────────────

def test_on_line_streams_output_and_does_not_affect_outcome(monkeypatch, tmp_path, engine):
    """engine.on_line (usado por el plugin dashboard para WS en vivo) debe
    recibir cada línea a medida que se produce, sin cambiar el resultado final
    del job frente al camino no-streaming (subprocess.run)."""

    class _FakePopen:
        def __init__(self, cmd, env=None, stdout=None, stderr=None, text=None, bufsize=None):
            self.stdout = iter(["primera línea\n", "segunda línea\n"])
            self.returncode = 0

        def wait(self):
            return self.returncode

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.Popen", _FakePopen)

    received: list[tuple[int, str]] = []
    engine.on_line = lambda job_id, line: received.append((job_id, line))

    job = engine.submit(str(_touch_apk(tmp_path, "stream.apk")), kind="static")
    outcomes = engine.drain()

    assert outcomes[0].ok is True
    assert received == [(job.db_id, "primera línea"), (job.db_id, "segunda línea")]


def test_without_on_line_uses_subprocess_run_unchanged(monkeypatch, tmp_path, engine):
    """Sin on_line asignado (default), debe seguir usando subprocess.run tal
    cual (camino de Fase 1, ya probado) — Popen no debe ni importarse/llamarse."""

    def _fail_if_called(*a, **kw):
        raise AssertionError("Popen no debería llamarse cuando on_line es None")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.Popen", _fail_if_called)
    monkeypatch.setattr(
        "nutcracker_core.queue.engine.subprocess.run",
        lambda cmd, env=None, capture_output=True, text=True: subprocess.CompletedProcess(cmd, 0, "", ""),
    )

    engine.submit(str(_touch_apk(tmp_path, "nostream.apk")), kind="static")
    outcomes = engine.drain()
    assert outcomes[0].ok is True


def test_enqueue_due_apps_only_queues_overdue_packages(tmp_path, engine):
    import datetime

    conn = db.connect(engine.db_path)
    try:
        past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat()
        future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)).isoformat()
        repository.upsert_app(conn, "com.overdue.app")
        repository.touch_app_run(conn, "com.overdue.app", next_due_at=past)
        repository.upsert_app(conn, "com.uptodate.app")
        repository.touch_app_run(conn, "com.uptodate.app", next_due_at=future)
    finally:
        conn.close()

    n = engine.enqueue_due_apps()
    assert n == 1
    assert len(engine._pending) == 1
    assert engine._pending[0].target == "com.overdue.app"
