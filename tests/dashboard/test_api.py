"""Tests de la API REST del dashboard (Fase 3 del plan), vía TestClient de
FastAPI contra una QueueEngine + SQLite reales (archivo temporal) — sin
levantar un servidor de verdad ni tocar la red."""

from __future__ import annotations

import re
import subprocess
import time

import pytest
from fastapi.testclient import TestClient

from nutcracker_core.plugins.dashboard.server import create_app
from nutcracker_core.queue.engine import QueueEngine
from nutcracker_core.store import db, repository


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "dash_test.db")


@pytest.fixture
def engine(db_path):
    return QueueEngine(config_path="config.yaml", db_path=db_path, static_workers=2)


@pytest.fixture
def client(db_path, engine):
    app = create_app(db_path=db_path, engine=engine)
    return TestClient(app)


def _seed_app_with_run(db_path: str) -> None:
    conn = db.connect(db_path)
    try:
        run_id = repository.insert_run(conn, "com.example.app", kind="full", status="done")
        repository.update_run_status(conn, run_id, status="done", verdict="protected",
                                      masvs_score=80, grade="B")
        repository.record_findings(conn, run_id, [
            repository.FindingRecord(rule_id="AUTH001", title="Token en logs", severity="high",
                                      masvs=["MASVS-STORAGE-2"], maswe=["MASWE-0001"], cwe=["CWE-532"]),
        ])
        repository.touch_app_run(conn, "com.example.app")
    finally:
        conn.close()


def test_summary_empty_db(client):
    r = client.get("/api/summary")
    assert r.status_code == 200
    assert r.json() == {"apps": 0, "runs": 0, "findings": 0, "active_jobs": 0}


def test_default_serial_null_when_not_configured(client):
    r = client.get("/api/config/default-serial")
    assert r.status_code == 200
    assert r.json() == {"serial": None}


def test_default_serial_reflects_configured_value(db_path, engine):
    app = create_app(db_path=db_path, engine=engine, default_serial="172.20.10.6:5555")
    client_with_serial = TestClient(app)
    r = client_with_serial.get("/api/config/default-serial")
    assert r.status_code == 200
    assert r.json() == {"serial": "172.20.10.6:5555"}


def test_adb_kill_server_calls_adb_transport_and_returns_its_result(client, monkeypatch):
    """El endpoint es un pass-through directo a adb_transport.kill_server()
    (WSL + Windows) -- no reimplementa nada acá, ver test_adb_transport.py
    para la lógica real de cada lado."""
    from nutcracker_core.plugins.dashboard import api as dashboard_api

    monkeypatch.setattr(
        dashboard_api.adb_transport, "kill_server",
        lambda: {"wsl": {"ok": True, "detail": "killed"}, "windows": None},
    )

    r = client.post("/api/adb/kill-server")

    assert r.status_code == 200
    assert r.json() == {"wsl": {"ok": True, "detail": "killed"}, "windows": None}


def test_consolidated_findings_dedupes_identical_findings_across_runs(db_path, client):
    """Caso central: dos runs del mismo build (mismo rule_id/file/line) no
    deben aparecer duplicados en el consolidado -- confirmado con datos
    reales (com.bcp.bo.wallet runs #10/#11, idénticos byte a byte)."""
    conn = db.connect(db_path)
    try:
        for _ in range(2):
            run_id = repository.insert_run(conn, "com.example.app", kind="full", status="done")
            repository.update_run_status(conn, run_id, status="done", verdict="protected")
            repository.record_findings(conn, run_id, [
                repository.FindingRecord(rule_id="HC004", title="Firebase key", severity="high",
                                          masvs=[], maswe=[], cwe=[], file="AndroidManifest.xml", line=84),
            ])
    finally:
        conn.close()

    r = client.get("/api/apps/com.example.app/findings")
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) == 1
    assert findings[0]["seen_in_runs"] == 2
    assert findings[0]["status"] == "present"


def test_consolidated_findings_marks_resolved_when_absent_from_latest_run(db_path, client):
    """Un hallazgo que estaba en un run viejo pero ya no en el más reciente
    debe marcarse "resolved", no desaparecer silenciosamente."""
    conn = db.connect(db_path)
    try:
        old_run = repository.insert_run(conn, "com.example.app", kind="full", status="done")
        repository.update_run_status(conn, old_run, status="done", verdict="protected")
        repository.record_findings(conn, old_run, [
            repository.FindingRecord(rule_id="HC001", title="old secret", severity="high",
                                      masvs=[], maswe=[], cwe=[], file="A.java", line=1),
        ])
        new_run = repository.insert_run(conn, "com.example.app", kind="full", status="done")
        repository.update_run_status(conn, new_run, status="done", verdict="protected")
        repository.record_findings(conn, new_run, [
            repository.FindingRecord(rule_id="HC002", title="new secret", severity="high",
                                      masvs=[], maswe=[], cwe=[], file="B.java", line=2),
        ])
    finally:
        conn.close()

    findings = client.get("/api/apps/com.example.app/findings").json()
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["HC001"]["status"] == "resolved"
    assert by_rule["HC002"]["status"] == "present"


def test_consolidated_findings_empty_for_app_without_runs(client):
    r = client.get("/api/apps/com.never.analyzed/findings")
    assert r.status_code == 200
    assert r.json() == []


def test_app_runs_history_includes_artifacts_and_findings_count(db_path, client, tmp_path):
    conn = db.connect(db_path)
    try:
        run_id = repository.insert_run(conn, "com.example.app", kind="full", status="done")
        repository.update_run_status(conn, run_id, status="done", verdict="protected",
                                      masvs_score=80, grade="B")
        repository.record_findings(conn, run_id, [
            repository.FindingRecord(rule_id="AUTH001", title="x", severity="high",
                                      masvs=[], maswe=[], cwe=[]),
        ])
        json_path = tmp_path / "report.json"
        json_path.write_text("{}")
        repository.record_artifact(conn, run_id, "json", str(json_path))
    finally:
        conn.close()

    r = client.get("/api/apps/com.example.app/runs")
    assert r.status_code == 200
    runs = r.json()
    assert len(runs) == 1
    assert runs[0]["findings_count"] == 1
    assert runs[0]["artifacts"] == {"json": str(json_path)}
    assert "pdf" not in runs[0]["artifacts"]


def test_app_runs_history_empty_for_app_without_runs(client):
    r = client.get("/api/apps/com.never.analyzed/runs")
    assert r.status_code == 200
    assert r.json() == []


def test_run_download_serves_the_recorded_file(db_path, client, tmp_path):
    conn = db.connect(db_path)
    try:
        run_id = repository.insert_run(conn, "com.example.app", kind="full", status="done")
        pdf_path = tmp_path / "report.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 fake")
        repository.record_artifact(conn, run_id, "pdf", str(pdf_path))
    finally:
        conn.close()

    r = client.get(f"/api/runs/{run_id}/download/pdf")
    assert r.status_code == 200
    assert r.content == b"%PDF-1.4 fake"


def test_run_download_404_for_missing_artifact_type(db_path, client):
    conn = db.connect(db_path)
    try:
        run_id = repository.insert_run(conn, "com.example.app", kind="full", status="done")
    finally:
        conn.close()

    r = client.get(f"/api/runs/{run_id}/download/pdf")
    assert r.status_code == 404


def test_run_download_404_for_invalid_artifact_type(client):
    r = client.get("/api/runs/1/download/exe")
    assert r.status_code == 404


def test_run_download_404_when_file_deleted_from_disk(db_path, client, tmp_path):
    conn = db.connect(db_path)
    try:
        run_id = repository.insert_run(conn, "com.example.app", kind="full", status="done")
        missing_path = tmp_path / "gone.json"
        repository.record_artifact(conn, run_id, "json", str(missing_path))
    finally:
        conn.close()

    r = client.get(f"/api/runs/{run_id}/download/json")
    assert r.status_code == 404


def test_apps_and_runs_reflect_seeded_data(db_path, client):
    _seed_app_with_run(db_path)

    apps = client.get("/api/apps").json()
    assert len(apps) == 1
    assert apps[0]["package"] == "com.example.app"
    assert apps[0]["last_verdict"] == "protected"
    assert apps[0]["masvs_score"] == 80

    summary = client.get("/api/summary").json()
    assert summary == {"apps": 1, "runs": 1, "findings": 1, "active_jobs": 0}


def test_run_detail_by_id(db_path, client):
    _seed_app_with_run(db_path)
    run_id = client.get("/api/runs").json()[0]["id"]

    detail = client.get(f"/api/runs/{run_id}").json()
    assert detail["package"] == "com.example.app"
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["rule_id"] == "AUTH001"
    assert detail["findings"][0]["maswe"] == "MASWE-0001"


def test_run_detail_404_for_missing_run(client):
    r = client.get("/api/runs/9999")
    assert r.status_code == 404


def test_schedule_set_and_get(client):
    r = client.post("/api/schedule/com.example.app", json={"interval_days": 15, "enabled": True})
    assert r.status_code == 200
    assert r.json()["interval_days"] == 15

    schedules = client.get("/api/schedule").json()
    assert schedules[0]["package"] == "com.example.app"
    assert schedules[0]["interval_days"] == 15


def test_queue_add_local_apk_and_run_now(monkeypatch, tmp_path, client, engine):
    """run_now dispara el drenado en un hilo de fondo (fire-and-forget: la
    respuesta HTTP no espera al job — el progreso se sigue por WS). Para que
    el test sea determinista y no deje un hilo colgando que contamine el
    monkeypatch de tests posteriores, se espera aquí explícitamente a que
    termine antes de retornar."""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    r = client.post("/api/queue", json={"target": str(apk), "kind": "static", "run_now": True})
    assert r.status_code == 200
    assert r.json()["job_id"] is not None

    deadline = time.monotonic() + 5
    while getattr(engine, "_dashboard_draining", False) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not getattr(engine, "_dashboard_draining", False), "el job de fondo no terminó a tiempo"

    r = client.get("/api/queue")
    assert len(r.json()) == 1


def test_queue_add_rejects_dynamic_without_local_apk(client):
    r = client.post("/api/queue", json={"target": "com.example.app", "kind": "dynamic"})
    assert r.status_code == 400


# ── Relay "browser-as-bridge" (plan.md, 2026-08-04) ─────────────────────────
#
# queue_add(relay=True) trata `serial` como el session_id de una sesión de
# relay ya conectada (ver /ws/relay/{session_id} en ws.py) en vez de un
# serial adb directo -- debe resolverla a los puertos locales del túnel antes
# de encolar, o rechazar con 400 si no hay navegador conectado todavía.

import asyncio as _asyncio

from nutcracker_core.plugins.dashboard.relay import relay_manager as _relay_manager


class _FakeRelayWs:
    async def send_json(self, data):
        pass

    async def send_bytes(self, data):
        pass


@pytest.fixture(autouse=True)
def _clean_relay_sessions():
    yield
    for session_id in list(_relay_manager._sessions):
        _asyncio.run(_relay_manager.remove(session_id))


def test_relay_status_404_without_session(client):
    r = client.get("/api/relay/no-existe")
    assert r.status_code == 404


def test_relay_status_returns_ports_when_attached(client):
    session = _asyncio.run(_relay_manager.get_or_create("device-x"))
    session.attach_websocket(_FakeRelayWs())

    r = client.get("/api/relay/device-x")
    assert r.status_code == 200
    body = r.json()
    assert body["attached"] is True
    assert set(body["ports"]) == {"frida", "adb"}


def test_queue_add_relay_requires_serial(client):
    r = client.post("/api/queue", json={"target": "com.example.app", "kind": "aipwn", "relay": True})
    assert r.status_code == 400


def test_queue_add_relay_400_without_relay_session(client):
    r = client.post("/api/queue", json={
        "target": "com.example.app", "kind": "aipwn", "relay": True, "serial": "no-existe",
    })
    assert r.status_code == 400


def test_queue_add_relay_400_when_session_not_attached(client):
    _asyncio.run(_relay_manager.get_or_create("device-y"))  # nunca se le adjunta un navegador

    r = client.post("/api/queue", json={
        "target": "com.example.app", "kind": "aipwn", "relay": True, "serial": "device-y",
    })
    assert r.status_code == 400


def test_queue_add_relay_resolves_frida_port_and_submits_job(client, engine):
    """serial NO se reescribe a una dirección de loopback (queda el
    session_id tal cual -- el shim de adb lo ignora igual, ver
    Job.relay_session_id); solo frida_host usa el puerto real del túnel,
    porque ESE sí sigue siendo un socket TCP crudo válido (27042 no es el
    puerto de control de adbd)."""
    session = _asyncio.run(_relay_manager.get_or_create("device-z"))
    session.attach_websocket(_FakeRelayWs())

    r = client.post("/api/queue", json={
        "target": "com.example.app", "kind": "aipwn", "relay": True, "serial": "device-z",
    })
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    submitted = next(j for j in engine._pending if j.db_id == job_id)
    assert submitted.serial == "device-z"
    assert submitted.relay_session_id == "device-z"
    assert submitted.frida_host == f"127.0.0.1:{session.ports['frida']}"


def test_queue_delete_removes_pending_job(client, engine):
    r = client.post("/api/queue", json={"target": "com.example.app", "kind": "static"})
    job_id = r.json()["job_id"]

    r = client.delete(f"/api/queue/{job_id}")
    assert r.status_code == 200
    assert r.json() == {"deleted": True}

    jobs = client.get("/api/queue").json()
    assert all(j["id"] != job_id for j in jobs)


def test_queue_delete_404_for_unknown_job(client):
    r = client.delete("/api/queue/999999")
    assert r.status_code == 404


# ── Botón "+N iteraciones" (resume de aipwn) ─────────────────────────────────

def test_queue_list_marks_aipwn_job_resumable_when_session_pending(monkeypatch, client, engine):
    from nutcracker_core.plugins.dashboard import api as dashboard_api

    r = client.post("/api/queue", json={"target": "com.example.app", "kind": "aipwn"})
    job_id = r.json()["job_id"]

    monkeypatch.setattr(
        dashboard_api.agent_memory, "has_resume_state",
        lambda target: target == "com.example.app",
    )

    jobs = {j["id"]: j for j in client.get("/api/queue").json()}
    assert jobs[job_id]["resumable"] is True


def test_queue_list_not_resumable_without_pending_session(monkeypatch, client, engine):
    from nutcracker_core.plugins.dashboard import api as dashboard_api

    r = client.post("/api/queue", json={"target": "com.example.app", "kind": "aipwn"})
    job_id = r.json()["job_id"]

    monkeypatch.setattr(dashboard_api.agent_memory, "has_resume_state", lambda target: False)

    jobs = {j["id"]: j for j in client.get("/api/queue").json()}
    assert jobs[job_id]["resumable"] is False


def test_queue_list_static_job_never_resumable(client, engine):
    r = client.post("/api/queue", json={"target": "com.example.app", "kind": "static"})
    job_id = r.json()["job_id"]

    jobs = {j["id"]: j for j in client.get("/api/queue").json()}
    assert jobs[job_id]["resumable"] is False


def test_queue_list_only_marks_the_latest_job_per_target_resumable(monkeypatch, client, engine):
    """Dos jobs aipwn viejos para el mismo target no deben marcarse ambos --
    la sesión guardada en disco es una sola, y corresponde a la corrida más
    reciente."""
    from nutcracker_core.plugins.dashboard import api as dashboard_api

    r1 = client.post("/api/queue", json={"target": "com.example.app", "kind": "aipwn"})
    old_id = r1.json()["job_id"]
    r2 = client.post("/api/queue", json={"target": "com.example.app", "kind": "aipwn"})
    new_id = r2.json()["job_id"]

    monkeypatch.setattr(dashboard_api.agent_memory, "has_resume_state", lambda target: True)

    jobs = {j["id"]: j for j in client.get("/api/queue").json()}
    assert jobs[new_id]["resumable"] is True
    assert jobs[old_id]["resumable"] is False


def test_resume_aipwn_enqueues_new_job_with_resume_flags(monkeypatch, client, engine):
    from nutcracker_core.plugins.dashboard import api as dashboard_api

    r = client.post("/api/queue", json={
        "target": "com.example.app", "kind": "aipwn", "serial": "ZY22GPM27J",
    })
    job_id = r.json()["job_id"]

    monkeypatch.setattr(dashboard_api.agent_memory, "has_resume_state", lambda target: True)

    submitted = []
    real_submit = engine.submit

    def spy_submit(target, kind="static", serial=None, priority=0, source=None,
                    aipwn_resume=False, aipwn_extra_iterations=5):
        submitted.append({
            "target": target, "kind": kind, "serial": serial,
            "aipwn_resume": aipwn_resume, "aipwn_extra_iterations": aipwn_extra_iterations,
        })
        return real_submit(target, kind=kind, serial=serial, priority=priority, source=source,
                            aipwn_resume=aipwn_resume, aipwn_extra_iterations=aipwn_extra_iterations)

    monkeypatch.setattr(engine, "submit", spy_submit)

    r = client.post(f"/api/queue/{job_id}/resume-aipwn")

    assert r.status_code == 200
    assert r.json()["job_id"] is not None
    assert r.json()["job_id"] != job_id
    assert submitted == [{
        "target": "com.example.app", "kind": "aipwn", "serial": "ZY22GPM27J",
        "aipwn_resume": True, "aipwn_extra_iterations": 5,
    }]


def test_resume_aipwn_404_without_pending_session(monkeypatch, client, engine):
    from nutcracker_core.plugins.dashboard import api as dashboard_api

    r = client.post("/api/queue", json={"target": "com.example.app", "kind": "aipwn"})
    job_id = r.json()["job_id"]

    monkeypatch.setattr(dashboard_api.agent_memory, "has_resume_state", lambda target: False)

    r = client.post(f"/api/queue/{job_id}/resume-aipwn")
    assert r.status_code == 404


def test_resume_aipwn_400_for_non_aipwn_job(client, engine):
    r = client.post("/api/queue", json={"target": "com.example.app", "kind": "static"})
    job_id = r.json()["job_id"]

    r = client.post(f"/api/queue/{job_id}/resume-aipwn")
    assert r.status_code == 400


def test_resume_aipwn_404_for_unknown_job(client):
    r = client.post("/api/queue/999999/resume-aipwn")
    assert r.status_code == 404


# ── /api/queue/batch (batch estático+aipwn desde un .txt subido en el frontend) ─

def _wait_for_drain(engine, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while getattr(engine, "_dashboard_draining", False) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not getattr(engine, "_dashboard_draining", False), "el drenado de fondo no terminó a tiempo"


def test_queue_batch_rejects_empty_target_list(client):
    r = client.post("/api/queue/batch", json={"targets": []})
    assert r.status_code == 400


def test_queue_batch_ignores_blank_lines_and_comments(client, engine):
    r = client.post("/api/queue/batch", json={
        "targets": ["com.app.one", "", "  # comentario", "com.app.two"],
        "then_aipwn": False,
    })
    assert r.status_code == 200
    assert r.json()["queued"] == 2
    _wait_for_drain(engine)


def test_queue_batch_chains_aipwn_after_each_successful_static_job(monkeypatch, client, engine):
    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        if "scan" in cmd:
            job_id = int(env["NUTCRACKER_QUEUE_JOB_ID"])
            pkg = cmd[cmd.index("scan") + 1]
            conn = db.connect(engine.db_path)
            try:
                run_id = repository.insert_run(conn, pkg, kind="static", status="done")
                repository.link_job_run(conn, job_id, run_id, pkg)
            finally:
                conn.close()
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    r = client.post("/api/queue/batch", json={
        "targets": ["com.app.one", "com.app.two"], "then_aipwn": True,
    })
    assert r.status_code == 200
    assert r.json()["queued"] == 2

    _wait_for_drain(engine)

    jobs = client.get("/api/queue").json()
    kinds = sorted(j["kind"] for j in jobs)
    assert kinds == ["aipwn", "aipwn", "static", "static"]
    aipwn_targets = {j["target"] for j in jobs if j["kind"] == "aipwn"}
    assert aipwn_targets == {"com.app.one", "com.app.two"}


def test_queue_batch_does_not_chain_after_failed_static_job(monkeypatch, client, engine):
    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    r = client.post("/api/queue/batch", json={"targets": ["com.app.broken"], "then_aipwn": True})
    assert r.status_code == 200

    _wait_for_drain(engine)

    jobs = client.get("/api/queue").json()
    assert all(j["kind"] != "aipwn" for j in jobs)


def test_queue_batch_propagates_source_and_serial_to_every_submit(monkeypatch, client, engine):
    calls = []
    real_submit = engine.submit

    def spy_submit(target, kind="static", serial=None, priority=0, source=None):
        calls.append({"target": target, "kind": kind, "serial": serial, "source": source})
        return real_submit(target, kind=kind, serial=serial, priority=priority, source=source)

    monkeypatch.setattr(engine, "submit", spy_submit)

    def fake_run(cmd, env=None, capture_output=True, text=True):  # noqa: ANN001
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.queue.engine.subprocess.run", fake_run)

    r = client.post("/api/queue/batch", json={
        "targets": ["com.app.one", "com.app.two"],
        "source": "device", "serial": "ZY22GPM27J", "then_aipwn": False,
    })
    assert r.status_code == 200

    _wait_for_drain(engine)

    assert len(calls) == 2
    assert all(c["source"] == "device" for c in calls)
    assert all(c["serial"] == "ZY22GPM27J" for c in calls)




def test_chat_pending_empty_by_default(client):
    r = client.get("/api/chat/com.example.app/pending")
    assert r.status_code == 200
    assert r.json() == {"messages": []}


def test_chat_pending_drains_mailbox(client):
    from nutcracker_core.plugins.dashboard import chat_mailbox
    chat_mailbox.add("com.example.app", "hola desde el operador")

    r = client.get("/api/chat/com.example.app/pending")
    assert r.json() == {"messages": ["hola desde el operador"]}

    # Segunda lectura -- ya se drenó, debe venir vacío.
    r2 = client.get("/api/chat/com.example.app/pending")
    assert r2.json() == {"messages": []}


def test_agent_prompt_response_shape(client):
    # No forzamos el import a fallar (aipwn puede o no estar instalado en el
    # entorno de test) — solo verificamos la forma de la respuesta en ambos casos.
    r = client.get("/api/agent/prompt")
    assert r.status_code == 200
    assert "available" in r.json()


# ── POST /api/relay/{session_id}/rpc/shell (2026-08-04) ─────────────────────
#
# Reemplaza el túnel TCP crudo original para adb (Android bloquea reenviar
# tcp: hacia el propio puerto de control de adbd, ver relay.py). El shim de
# adb hace este POST; el navegador resuelve con adb.subprocess.spawnAndWait().
#
# La mecánica real de correlación request_id/timeout/etc. de session.rpc() ya
# está probada a fondo en tests/dashboard/test_relay.py (asyncio puro, sin
# HTTP). Acá solo importa el mapeo de status codes del endpoint -- se prueba
# con un doble de sesión en vez de una WebSocket real: abrir una WS real +
# mandarle un POST concurrente desde otro hilo choca con una limitación
# conocida del TestClient de Starlette (deadlock del harness, no del código
# real -- confirmado en vivo, se colgaba sin avanzar).

from nutcracker_core.plugins.dashboard import api as api_mod


class _StubRelaySession:
    def __init__(self, attached=True, rpc_result=None, rpc_exception=None):
        self.attached = attached
        self._result = rpc_result
        self._exception = rpc_exception

    async def rpc(self, op, timeout=30.0, **fields):
        if self._exception is not None:
            raise self._exception
        return self._result


def test_relay_rpc_shell_round_trip(client, monkeypatch):
    stub = _StubRelaySession(rpc_result={
        "stdout": "package:com.example.app\n", "stderr": "", "exit_code": 0,
    })
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post(
        "/api/relay/device-shell-1/rpc/shell",
        json={"command": "pm list packages com.example.app"},
    )

    assert r.status_code == 200
    body = r.json()
    assert body["stdout"] == "package:com.example.app\n"
    assert body["exit_code"] == 0


def test_relay_rpc_shell_404_without_connected_session(client):
    r = client.post(
        "/api/relay/no-existe/rpc/shell",
        json={"command": "echo hi"},
    )
    assert r.status_code == 404


def test_relay_rpc_shell_404_when_session_exists_but_not_attached(client, monkeypatch):
    stub = _StubRelaySession(attached=False)
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post("/api/relay/device-x/rpc/shell", json={"command": "echo hi"})
    assert r.status_code == 404


def test_relay_rpc_shell_502_when_browser_reports_failure(client, monkeypatch):
    from nutcracker_core.plugins.dashboard.relay import RpcError
    stub = _StubRelaySession(rpc_exception=RpcError("createSocket falló: device offline"))
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post(
        "/api/relay/device-shell-2/rpc/shell",
        json={"command": "pm install /data/local/tmp/app.apk"},
    )

    assert r.status_code == 502
    assert "device offline" in r.json()["detail"]


def test_relay_rpc_shell_504_on_timeout(client, monkeypatch):
    from nutcracker_core.plugins.dashboard.relay import RpcTimeoutError
    stub = _StubRelaySession(rpc_exception=RpcTimeoutError("timeout (0.2s) esperando respuesta"))
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post(
        "/api/relay/device-shell-3/rpc/shell",
        json={"command": "echo hi", "timeout": 0.2},
    )

    assert r.status_code == 504


def test_relay_rpc_shell_409_on_relay_error(client, monkeypatch):
    from nutcracker_core.plugins.dashboard.relay import RelayError
    stub = _StubRelaySession(rpc_exception=RelayError("el navegador se desconectó antes de responder"))
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post("/api/relay/device-shell-4/rpc/shell", json={"command": "echo hi"})
    assert r.status_code == 409


# ── POST /api/relay/{session_id}/rpc/install|pull|screencap (Etapas 2-4) ────
#
# Mismo enfoque que /rpc/shell: doble de sesión, sin WebSocket real (ver el
# comentario largo sobre el deadlock del TestClient más arriba).

def test_relay_rpc_install_round_trip(client, monkeypatch):
    stub = _StubRelaySession(rpc_result={"stdout": "Success\n", "stderr": "", "exit_code": 0})
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post("/api/relay/device-x/rpc/install", json={
        "apks": [{"name": "app.apk", "data_b64": "UEsDBA=="}],
        "flags": ["-r", "-d"],
        "multi": False,
    })

    assert r.status_code == 200
    assert r.json()["stdout"] == "Success\n"


def test_relay_rpc_install_404_without_connected_session(client):
    r = client.post("/api/relay/no-existe/rpc/install", json={"apks": [{"name": "a.apk", "data_b64": "AA=="}]})
    assert r.status_code == 404


def test_relay_rpc_pull_round_trip(client, monkeypatch):
    stub = _StubRelaySession(rpc_result={"data_b64": "aGVsbG8="})
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post("/api/relay/device-x/rpc/pull", json={"remote_path": "/data/local/tmp/lib.so"})

    assert r.status_code == 200
    assert r.json()["data_b64"] == "aGVsbG8="


def test_relay_rpc_pull_502_when_browser_reports_failure(client, monkeypatch):
    from nutcracker_core.plugins.dashboard.relay import RpcError
    stub = _StubRelaySession(rpc_exception=RpcError("no such file"))
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post("/api/relay/device-x/rpc/pull", json={"remote_path": "/no/existe"})

    assert r.status_code == 502
    assert "no such file" in r.json()["detail"]


def test_relay_rpc_screencap_round_trip(client, monkeypatch):
    stub = _StubRelaySession(rpc_result={"data_b64": "iVBORw0KGgo="})
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post("/api/relay/device-x/rpc/screencap", json={})

    assert r.status_code == 200
    assert r.json()["data_b64"] == "iVBORw0KGgo="


def test_relay_rpc_screencap_504_on_timeout(client, monkeypatch):
    from nutcracker_core.plugins.dashboard.relay import RpcTimeoutError
    stub = _StubRelaySession(rpc_exception=RpcTimeoutError("timeout"))
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post("/api/relay/device-x/rpc/screencap", json={})

    assert r.status_code == 504


def test_relay_rpc_logcat_round_trip(client, monkeypatch):
    stub = _StubRelaySession(rpc_result={"stdout": "W OkHttp: warning\n"})
    monkeypatch.setattr(api_mod.relay_manager, "get", lambda sid: stub)

    r = client.post("/api/relay/device-x/rpc/logcat", json={
        "args": ["-v", "time", "*:W"], "duration_seconds": 15,
    })

    assert r.status_code == 200
    assert r.json()["stdout"] == "W OkHttp: warning\n"


def test_relay_rpc_logcat_404_without_connected_session(client):
    r = client.post("/api/relay/no-existe/rpc/logcat", json={})
    assert r.status_code == 404


# ── POST /api/apks/upload ────────────────────────────────────────────────

_FAKE_APK_BYTES = b"PK\x03\x04" + b"\x00" * 32


def test_upload_apk_saves_to_downloads_and_returns_relative_path(monkeypatch, tmp_path, client):
    monkeypatch.chdir(tmp_path)

    r = client.post(
        "/api/apks/upload",
        files={"file": ("com.example.app.apk", _FAKE_APK_BYTES, "application/octet-stream")},
    )

    assert r.status_code == 200
    body = r.json()
    assert body["path"] == "downloads/com.example.app.apk"
    assert body["filename"] == "com.example.app.apk"
    assert body["size"] == len(_FAKE_APK_BYTES)
    saved = tmp_path / "downloads" / "com.example.app.apk"
    assert saved.read_bytes() == _FAKE_APK_BYTES


def test_upload_apk_rejects_non_apk_extension(monkeypatch, tmp_path, client):
    monkeypatch.chdir(tmp_path)
    r = client.post(
        "/api/apks/upload",
        files={"file": ("malware.exe", b"MZfake", "application/octet-stream")},
    )
    assert r.status_code == 400
    assert not (tmp_path / "downloads").exists()


def test_upload_apk_rejects_bad_magic_bytes(monkeypatch, tmp_path, client):
    """Extensión .apk correcta pero contenido que no es un ZIP real -- no debe
    quedar guardado en disco (ver también que no crea el archivo con nombre
    "fake.apk" antes de validar la firma)."""
    monkeypatch.chdir(tmp_path)
    r = client.post(
        "/api/apks/upload",
        files={"file": ("fake.apk", b"esto no es un zip para nada", "application/octet-stream")},
    )
    assert r.status_code == 400
    assert not (tmp_path / "downloads" / "fake.apk").exists()


def test_upload_apk_sanitizes_path_traversal_in_filename(monkeypatch, tmp_path, client):
    monkeypatch.chdir(tmp_path)
    r = client.post(
        "/api/apks/upload",
        files={"file": ("../../../etc/passwd.apk", _FAKE_APK_BYTES, "application/octet-stream")},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["path"] == "downloads/passwd.apk"
    assert ".." not in body["path"]
    # No escribió nada fuera de tmp_path/downloads.
    assert list((tmp_path / "downloads").iterdir()) == [tmp_path / "downloads" / "passwd.apk"]


def test_upload_apk_does_not_clobber_existing_file(monkeypatch, tmp_path, client):
    monkeypatch.chdir(tmp_path)
    first = client.post(
        "/api/apks/upload",
        files={"file": ("app.apk", _FAKE_APK_BYTES, "application/octet-stream")},
    )
    second_bytes = _FAKE_APK_BYTES + b"more-content"
    second = client.post(
        "/api/apks/upload",
        files={"file": ("app.apk", second_bytes, "application/octet-stream")},
    )

    assert first.json()["path"] == "downloads/app.apk"
    assert second.json()["path"] == "downloads/app_1.apk"
    # Ambos archivos coexisten con su contenido propio -- el segundo upload
    # no pisó al primero.
    assert (tmp_path / "downloads" / "app.apk").read_bytes() == _FAKE_APK_BYTES
    assert (tmp_path / "downloads" / "app_1.apk").read_bytes() == second_bytes


def test_upload_apk_sanitizes_unsafe_characters_in_filename(monkeypatch, tmp_path, client):
    monkeypatch.chdir(tmp_path)
    r = client.post(
        "/api/apks/upload",
        files={"file": ("mi app (v2) #raro!.apk", _FAKE_APK_BYTES, "application/octet-stream")},
    )
    assert r.status_code == 200
    saved_name = r.json()["filename"]
    assert re.fullmatch(r"[A-Za-z0-9._-]+\.apk", saved_name)


def test_upload_apk_requires_auth_when_enabled(tmp_path, monkeypatch, db_path, engine):
    from nutcracker_core.plugins.dashboard.auth import AuthConfig, hash_password
    from nutcracker_core.plugins.dashboard.server import create_app

    monkeypatch.chdir(tmp_path)
    auth = AuthConfig.from_config(
        {"enabled": True, "username": "admin", "password_hash": hash_password("pw"), "secret_key": "k"},
        internal_token="itok", secure_cookie=False,
    )
    app = create_app(db_path=db_path, engine=engine, auth=auth)
    protected_client = TestClient(app)

    r = protected_client.post(
        "/api/apks/upload",
        files={"file": ("app.apk", _FAKE_APK_BYTES, "application/octet-stream")},
    )
    assert r.status_code == 401
