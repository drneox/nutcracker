"""Tests de la API REST del dashboard (Fase 3 del plan), vía TestClient de
FastAPI contra una QueueEngine + SQLite reales (archivo temporal) — sin
levantar un servidor de verdad ni tocar la red."""

from __future__ import annotations

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
