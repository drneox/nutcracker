"""Tests de nutcracker_core/queue/engine.py (Fase 1 del plan).

subprocess.run se reemplaza por un doble de prueba: lo que se ejercita aquí es
la mecánica de la cola (paralelismo estático, serialización por dispositivo,
transiciones de estado, re-agendado), no el pipeline de análisis real (ya
cubierto por Fase 0 / tests existentes).
"""

from __future__ import annotations

import os
import subprocess
import threading
import time

import pytest

from nutcracker_core.queue.engine import (
    QueueEngine,
    _extract_error_summary,
    _resolve_local_apk,
    _strip_ansi,
)
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


def test_aipwn_jobs_share_device_lock_with_dynamic_jobs(monkeypatch, tmp_path, engine):
    """aipwn (agente de bypass) usa el mismo dispositivo físico que los checks
    dinámicos -- deben serializarse entre sí por serial, igual que dos jobs
    'dynamic' entre sí (Fase 3: wiring del agente en la cola)."""
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

    engine.submit(str(_touch_apk(tmp_path, "dyn.apk")), kind="dynamic", serial="SAME-SERIAL")
    engine.submit("com.example.app", kind="aipwn", serial="SAME-SERIAL")

    outcomes = engine.drain()
    assert len(outcomes) == 2 and all(o.ok for o in outcomes)

    (s1, e1), (s2, e2) = sorted(intervals)
    assert e1 <= s2, "un job aipwn y uno dinámico con el mismo serial se solaparon"


def test_aipwn_job_builds_aipwn_command(monkeypatch, engine):
    seen_cmds = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.tapjacking", kind="aipwn", serial="ZY22GPM27J")
    outcomes = engine.drain()

    assert len(outcomes) == 1 and outcomes[0].ok
    cmd = seen_cmds[0]
    assert "aipwn" in cmd
    assert "com.example.tapjacking" in cmd
    assert "--serial" in cmd and "ZY22GPM27J" in cmd


def test_frida_host_sets_env_var_for_relay_backed_job(monkeypatch, engine):
    """Relay "browser-as-bridge" (plan.md): submit(frida_host=...) debe
    terminar como NUTCRACKER_FRIDA_HOST en el env del subproceso -- es lo que
    lee aipwn.py (override sobre strategies.frida_host del config) para
    apuntar frida al túnel local en vez del host fijo."""
    seen_envs = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_envs.append(env)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit(
        "com.example.tapjacking", kind="aipwn", serial="127.0.0.1:54321",
        frida_host="127.0.0.1:54322",
    )
    outcomes = engine.drain()

    assert len(outcomes) == 1 and outcomes[0].ok
    assert seen_envs[0]["NUTCRACKER_FRIDA_HOST"] == "127.0.0.1:54322"


def test_no_frida_host_means_no_env_var(monkeypatch, engine):
    seen_envs = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_envs.append(env)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.tapjacking", kind="aipwn", serial="ZY22GPM27J")
    engine.drain()

    assert "NUTCRACKER_FRIDA_HOST" not in seen_envs[0]


def test_relay_session_id_sets_env_var_and_prepends_shim_to_path(monkeypatch, engine):
    """FIX de diseño (2026-08-04): el túnel TCP crudo para adb no es viable
    (Android bloquea reenviar tcp: hacia el propio puerto de control de
    adbd) -- el reemplazo es un shim de 'adb' interceptado vía PATH, que
    traduce a RPC. submit(relay_session_id=...) debe: (1) setear
    NUTCRACKER_RELAY_SESSION_ID, y (2) anteponer el directorio del shim al
    PATH del subproceso, para que shutil.which("adb") lo recoja."""
    from nutcracker_core.queue.engine import _RELAY_ADB_SHIM_DIR

    seen_envs = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_envs.append(env)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.tapjacking", kind="aipwn", serial="device-x",
                  relay_session_id="device-x")
    outcomes = engine.drain()

    assert len(outcomes) == 1 and outcomes[0].ok
    env = seen_envs[0]
    assert env["NUTCRACKER_RELAY_SESSION_ID"] == "device-x"
    assert env["PATH"].split(os.pathsep)[0] == _RELAY_ADB_SHIM_DIR


def test_no_relay_session_id_means_no_shim_in_path(monkeypatch, engine):
    from nutcracker_core.queue.engine import _RELAY_ADB_SHIM_DIR

    seen_envs = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_envs.append(env)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.tapjacking", kind="aipwn", serial="ZY22GPM27J")
    engine.drain()

    env = seen_envs[0]
    assert "NUTCRACKER_RELAY_SESSION_ID" not in env
    assert _RELAY_ADB_SHIM_DIR not in env["PATH"].split(os.pathsep)


def test_ensure_transport_skips_network_check_for_relay_backed_job(monkeypatch, engine):
    """Doble resguardo (ver _ensure_transport): aunque un operador elija un
    session_id con forma ip:puerto, un job relay no debe disparar un
    `adb connect` real -- el device está detrás del navegador, no alcanzable
    directo desde el backend."""
    ensure_calls = []
    monkeypatch.setattr(
        "nutcracker_core.queue.engine.adb_transport.ensure_available",
        lambda serial: ensure_calls.append(serial) or True,
    )

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.tapjacking", kind="aipwn", serial="192.168.1.1:5555",
                  relay_session_id="192.168.1.1:5555")
    engine.drain()

    assert ensure_calls == []


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


# ── Borrado de jobs pendientes (delete_job) ─────────────────────────────────

def test_delete_job_removes_queued_job(tmp_path, engine):
    job = engine.submit(str(_touch_apk(tmp_path, "pending.apk")), kind="static")

    conn = db.connect(engine.db_path)
    try:
        deleted = repository.delete_job(conn, job.db_id)
        assert deleted is True
        assert repository.get_job(conn, job.db_id) is None
    finally:
        conn.close()


def test_delete_job_returns_false_for_unknown_id(tmp_path, engine):
    conn = db.connect(engine.db_path)
    try:
        assert repository.delete_job(conn, 999999) is False
    finally:
        conn.close()


def test_delete_job_refuses_to_delete_running_job(monkeypatch, tmp_path, engine):
    """Un job 'running' ya tiene un subproceso real corriendo en algún lado --
    borrar la fila no lo detiene, así que delete_job se niega a tocarlo."""
    release = threading.Event()

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        release.wait(timeout=5)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    job = engine.submit(str(_touch_apk(tmp_path, "running.apk")), kind="static")
    thread = threading.Thread(target=engine.drain, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        conn = db.connect(engine.db_path)
        try:
            while time.monotonic() < deadline:
                row = repository.get_job(conn, job.db_id)
                if row and row["status"] == "running":
                    break
                time.sleep(0.02)
            assert row["status"] == "running"
            assert repository.delete_job(conn, job.db_id) is False
        finally:
            conn.close()
    finally:
        release.set()
        thread.join(timeout=5)


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


# ── _extract_error_summary (fix encontrado en prueba con dispositivo real) ──

def test_extract_error_summary_surfaces_error_line_buried_by_later_output():
    """Reproduce el bug real: 'Failed to spawn: ... No route to host' seguido
    de una tabla larga de hallazgos — un tail[-2000:] ciego lo perdía."""
    noise = "\n".join(f"│ tabla de hallazgos línea {i:03d} sin relación │" for i in range(200))
    output = (
        "Failed to spawn: unable to connect to remote frida-server: "
        "Could not connect to 192.168.1.4: No route to host\n" + noise
    )
    summary = _extract_error_summary(output, max_len=500)
    assert "No route to host" in summary


def test_extract_error_summary_falls_back_to_tail_without_error_markers():
    output = "línea 1\nlínea 2\nlínea 3 sin nada especial"
    assert _extract_error_summary(output) == output


def test_extract_error_summary_empty_output():
    assert _extract_error_summary("") == ""


def test_extract_error_summary_respects_max_len():
    output = "Error: algo salió mal\n" + ("x" * 5000)
    summary = _extract_error_summary(output, max_len=500)
    assert len(summary) <= 500 + len("\n---\n")  # margen del separador


# ── ANSI/color (fix encontrado en el dashboard: banner coloreado de rich ──
# volcado como texto crudo en el panel de logs cuando el entorno padre tiene
# FORCE_COLOR/COLORTERM, p.ej. terminal integrada de VS Code) ───────────────

def test_strip_ansi_removes_color_codes_but_keeps_text():
    raw = "\x1b[38;2;68;68;68m▄\x1b[0m normal \x1b[31mrojo\x1b[0m"
    assert _strip_ansi(raw) == "▄ normal rojo"


def test_strip_ansi_removes_osc8_hyperlinks():
    raw = "\x1b]8;;https://nutcracker.sh\x1b\\nutcracker.sh\x1b]8;;\x1b\\"
    assert _strip_ansi(raw) == "nutcracker.sh"


def test_strip_ansi_noop_on_plain_text():
    assert _strip_ansi("sin nada especial\nsegunda línea") == "sin nada especial\nsegunda línea"


def test_run_job_forces_no_color_and_clears_force_color(monkeypatch, tmp_path, engine):
    """El subproceso de un job nunca escribe a una terminal real (su stdout
    termina en un pipe leído por el motor de la cola) — si el proceso padre
    heredó FORCE_COLOR/COLORTERM=truecolor, rich igual emitiría ANSI real
    hacia ese pipe. NO_COLOR es lo único que rich respeta por encima de
    FORCE_COLOR, así que _run_job debe forzarlo y limpiar FORCE_COLOR."""
    seen_env = {}

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_env.update(env or {})
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("COLORTERM", "truecolor")

    engine.submit(str(_touch_apk(tmp_path, "color.apk")), kind="static")
    outcomes = engine.drain()

    assert outcomes[0].ok is True
    assert seen_env.get("NO_COLOR") == "1"
    assert "FORCE_COLOR" not in seen_env
    # COLORTERM por sí solo no fuerza is_terminal en rich sin isatty(); no hace
    # falta limpiarlo, pero NO_COLOR ya manda por encima de cualquier combinación.


def test_run_streaming_strips_ansi_before_publishing_lines(monkeypatch, tmp_path, engine):
    class _FakePopen:
        def __init__(self, cmd, env=None, stdout=None, stderr=None, text=None, bufsize=None):
            self.stdout = iter(["\x1b[31mlínea con color\x1b[0m\n", "línea normal\n"])
            self.returncode = 0

        def wait(self):
            return self.returncode

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.Popen", _FakePopen)

    received: list[str] = []
    engine.on_line = lambda job_id, line: received.append(line)

    engine.submit(str(_touch_apk(tmp_path, "streamcolor.apk")), kind="static")
    engine.drain()

    assert received == ["línea con color", "línea normal"]


# ── _resolve_local_apk (fix: dashboard no reutilizaba APK descargado) ───────

def test_resolve_local_apk_finds_package_named_apk(tmp_path, monkeypatch):
    """downloads/<package>/<package>.apk (formato apkeep >= 0.18)."""
    pkg = "com.example.app"
    dl_dir = tmp_path / "downloads" / pkg
    dl_dir.mkdir(parents=True)
    apk = dl_dir / f"{pkg}.apk"
    apk.write_bytes(b"PK\x03\x04")

    monkeypatch.chdir(tmp_path)
    import os; result = _resolve_local_apk(pkg); assert result is not None and os.path.basename(result) == f"{pkg}.apk"


def test_resolve_local_apk_finds_base_apk(tmp_path, monkeypatch):
    """downloads/<package>/base.apk (formato App Bundle clásico)."""
    pkg = "com.example.bundle"
    dl_dir = tmp_path / "downloads" / pkg
    dl_dir.mkdir(parents=True)
    apk = dl_dir / "base.apk"
    apk.write_bytes(b"PK\x03\x04")
    # Splits presentes — no deben elegirse
    (dl_dir / "split_config.arm64_v8a.apk").write_bytes(b"PK\x03\x04")

    monkeypatch.chdir(tmp_path)
    import os; result = _resolve_local_apk(pkg); assert result is not None and os.path.basename(result) == "base.apk"


def test_resolve_local_apk_skips_split_and_config_apks(tmp_path, monkeypatch):
    """Si solo hay splits/configs en downloads/<package>/ (sin base ni
    package.apk), la heurística no debe elegirlos — retorna None."""
    pkg = "com.example.splitsonly"
    dl_dir = tmp_path / "downloads" / pkg
    dl_dir.mkdir(parents=True)
    (dl_dir / "split_config.arm64_v8a.apk").write_bytes(b"PK\x03\x04")
    (dl_dir / "split_config.xxhdpi.apk").write_bytes(b"PK\x03\x04")

    monkeypatch.chdir(tmp_path)
    assert _resolve_local_apk(pkg) is None


def test_resolve_local_apk_returns_none_when_no_downloads_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _resolve_local_apk("com.example.notdownloaded") is None


def test_resolve_local_apk_returns_target_for_existing_apk_path(tmp_path):
    """Si target ya es una ruta a un .apk existente, lo devuelve tal cual."""
    apk = tmp_path / "manual.apk"
    apk.write_bytes(b"PK\x03\x04")
    assert _resolve_local_apk(str(apk)) == str(apk)


def test_resolve_local_apk_rejects_non_package_strings():
    """Strings que no son package IDs ni rutas .apk válidas → None."""
    assert _resolve_local_apk("notapackage") is None
    assert _resolve_local_apk("/path/does/not/exist.apk") is None
    assert _resolve_local_apk("") is None


def test_job_with_package_id_reuses_local_apk(monkeypatch, tmp_path, engine):
    """FIX 2026-07-27: un job encolado desde el dashboard con un package ID
    (no una ruta .apk) debe resolver downloads/<package>/<package>.apk y
    construir `analyze <path>` (local) en vez de `scan <package>` (que
    fuerza descarga y falla si no hay credenciales)."""
    pkg = "com.example.app"
    dl_dir = tmp_path / "downloads" / pkg
    dl_dir.mkdir(parents=True)
    apk = dl_dir / f"{pkg}.apk"
    apk.write_bytes(b"PK\x03\x04")

    monkeypatch.chdir(tmp_path)

    seen_cmds = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit(pkg, kind="static")
    outcomes = engine.drain()

    assert len(outcomes) == 1 and outcomes[0].ok
    cmd = seen_cmds[0]
    # Debe ir por analyze (local), no scan (descarga)
    assert "analyze" in cmd
    import os; assert any(os.path.basename(c) == f"{pkg}.apk" for c in cmd)
    assert "scan" not in cmd


def test_job_with_source_device_builds_scan_with_source_and_serial(monkeypatch, engine):
    """batch estático+aipwn con --source device (Fase de encolado desde .txt)."""
    seen_cmds = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.app", kind="static", serial="ZY22GPM27J", source="device")
    outcomes = engine.drain()

    assert len(outcomes) == 1 and outcomes[0].ok
    cmd = seen_cmds[0]
    assert "scan" in cmd
    assert "--source" in cmd and "device" in cmd
    assert "--serial" in cmd and "ZY22GPM27J" in cmd


def test_job_with_explicit_source_skips_local_apk_reuse_heuristic(monkeypatch, tmp_path, engine):
    """FIX: si el usuario pide explícitamente --source device, no debe
    silenciarse con un APK viejo que quedó en downloads/ de un intento previo
    con otra fuente (google-play/apk-pure) -- job.source manda."""
    pkg = "com.example.stale"
    dl_dir = tmp_path / "downloads" / pkg
    dl_dir.mkdir(parents=True)
    (dl_dir / f"{pkg}.apk").write_bytes(b"PK\x03\x04")

    monkeypatch.chdir(tmp_path)

    seen_cmds = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit(pkg, kind="static", source="device", serial="X")
    outcomes = engine.drain()

    assert len(outcomes) == 1 and outcomes[0].ok
    cmd = seen_cmds[0]
    assert "scan" in cmd and "analyze" not in cmd
    assert "--source" in cmd and "device" in cmd


def test_job_with_package_id_falls_back_to_scan_when_no_local_apk(monkeypatch, tmp_path, engine):
    """Si no hay APK local reusable, el job cae al camino original:
    `scan <package>` (descarga)."""
    pkg = "com.example.neverdownloaded"

    monkeypatch.chdir(tmp_path)

    seen_cmds = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit(pkg, kind="static")
    outcomes = engine.drain()

    assert len(outcomes) == 1 and outcomes[0].ok
    cmd = seen_cmds[0]
    assert "scan" in cmd
    assert pkg in cmd

# ── Keepalive del transporte adb-over-wifi (ver nutcracker_core/adb_transport) ─

def test_job_with_network_serial_revives_dropped_transport(monkeypatch, engine):
    """Antes de lanzar el job, el engine reconecta el serial de red si el
    daemon adb lo perdió. Sin esto el job muere con "device '<ip>:5555' not
    found" aunque el teléfono esté perfectamente accesible (visto en uso real
    con el video WebUSB reclamando el cable USB)."""
    ensured = []
    monkeypatch.setattr(
        "nutcracker_core.queue.engine.adb_transport.ensure_available",
        lambda serial, *a, **kw: ensured.append(serial) or True,
    )

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.app", kind="static", source="device",
                  serial="172.20.10.6:5555")
    engine.drain()

    assert ensured == ["172.20.10.6:5555"]


def test_job_with_usb_serial_does_not_touch_transport(monkeypatch, engine):
    ensured = []
    monkeypatch.setattr(
        "nutcracker_core.queue.engine.adb_transport.ensure_available",
        lambda serial, *a, **kw: ensured.append(serial) or True,
    )

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.app", kind="static", source="device", serial="ZY22GPM27J")
    engine.drain()

    assert ensured == []


def test_job_runs_even_if_transport_cannot_be_restored(monkeypatch, engine):
    """El chequeo es best-effort: si no se puede revivir el transporte, el job
    igual se lanza para que falle con su propio mensaje (más específico)."""
    monkeypatch.setattr(
        "nutcracker_core.queue.engine.adb_transport.ensure_available",
        lambda *a, **kw: False,
    )

    seen = []

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.app", kind="static", source="device",
                  serial="172.20.10.6:5555")
    outcomes = engine.drain()

    assert len(seen) == 1
    assert outcomes[0].ok


def test_job_survives_an_exploding_transport_check(monkeypatch, engine):
    def boom(*a, **kw):  # noqa: ANN001
        raise RuntimeError("adb explotó")

    monkeypatch.setattr(
        "nutcracker_core.queue.engine.adb_transport.ensure_available", boom)

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.app", kind="static", source="device",
                  serial="172.20.10.6:5555")
    outcomes = engine.drain()

    assert outcomes[0].ok


def test_job_registers_its_serial_with_the_keepalive(monkeypatch, engine):
    """Un job encolado con un serial distinto al default del config también
    debe quedar cubierto por la vigilancia de fondo."""
    from nutcracker_core import adb_transport

    monkeypatch.setattr(
        "nutcracker_core.queue.engine.adb_transport.ensure_available",
        lambda *a, **kw: True,
    )

    keepalive = adb_transport.TransportKeepAlive()
    engine.transport_keepalive = keepalive

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    engine.submit("com.example.app", kind="static", source="device",
                  serial="10.0.0.5:5555")
    engine.drain()

    assert keepalive.serials == {"10.0.0.5:5555"}


# ── relay_session_id/frida_host sobreviven un reinicio del dashboard ───────
# Bug real reportado en vivo (2026-08-05, job aipwn real contra
# sh.nutcracker.nutbank): estos dos campos del Job vivían SOLO en memoria --
# un job relay-backed que seguía 'queued' cuando el proceso del dashboard se
# reiniciaba (pasó varias veces en la sesión, por otros fixes) los perdía en
# silencio al recargarse desde SQLite, degradando el job a un adb sin
# dispositivo detrás. Síntoma final: "app not installed on device" pese a
# estar instalada de verdad -- sin ningún error que apuntara a la causa real.

def test_relay_session_id_and_frida_host_persist_to_sqlite(engine):
    job = engine.submit(
        "sh.nutcracker.nutbank", kind="aipwn", serial="ZY22GPM27J",
        relay_session_id="ZY22GPM27J", frida_host="127.0.0.1:35207",
    )

    conn = db.connect(engine.db_path)
    try:
        row = repository.get_job(conn, job.db_id)
    finally:
        conn.close()

    assert row["relay_session_id"] == "ZY22GPM27J"
    assert row["frida_host"] == "127.0.0.1:35207"


def test_relay_job_survives_dashboard_restart(tmp_path):
    """Simula el escenario real del bug: un job relay-backed se encola en un
    proceso, el proceso del dashboard se reinicia ANTES de que el job corra
    (_pending vacío en el engine nuevo), y el job se recupera de SQLite vía
    _load_queued_from_db() -- relay_session_id/frida_host deben sobrevivir
    ese ciclo completo, no solo la fila cruda de la DB."""
    db_path = str(tmp_path / "queue_test.db")

    engine_before_restart = QueueEngine(config_path="config.yaml", db_path=db_path, static_workers=1)
    job = engine_before_restart.submit(
        "sh.nutcracker.nutbank", kind="aipwn", serial="ZY22GPM27J",
        relay_session_id="ZY22GPM27J", frida_host="127.0.0.1:35207",
    )
    assert job.relay_session_id == "ZY22GPM27J"  # correcto en memoria, antes del "reinicio"

    # "Reinicio": engine nuevo, mismo db_path, _pending arranca vacío -- como
    # pasa de verdad cuando se relanza el proceso del dashboard.
    engine_after_restart = QueueEngine(config_path="config.yaml", db_path=db_path, static_workers=1)
    assert engine_after_restart._pending == []
    engine_after_restart._load_queued_from_db()

    assert len(engine_after_restart._pending) == 1
    reloaded = engine_after_restart._pending[0]
    assert reloaded.relay_session_id == "ZY22GPM27J", (
        "relay_session_id se perdió al recargar el job desde SQLite tras el reinicio"
    )
    assert reloaded.frida_host == "127.0.0.1:35207", (
        "frida_host se perdió al recargar el job desde SQLite tras el reinicio"
    )


def test_non_relay_job_still_has_none_relay_fields_after_restart(tmp_path):
    """Retrocompatibilidad: un job normal (sin relay) sigue reconstruyéndose
    con relay_session_id/frida_host en None, no algún valor inventado."""
    db_path = str(tmp_path / "queue_test.db")

    e1 = QueueEngine(config_path="config.yaml", db_path=db_path, static_workers=1)
    e1.submit("com.example.app", kind="static")

    e2 = QueueEngine(config_path="config.yaml", db_path=db_path, static_workers=1)
    e2._load_queued_from_db()

    reloaded = e2._pending[0]
    assert reloaded.relay_session_id is None
    assert reloaded.frida_host is None
