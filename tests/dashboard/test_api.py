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


def test_device_endpoint_reports_no_devices_without_adb(monkeypatch, client):
    monkeypatch.setattr(
        "nutcracker_core.plugins.dashboard.device.subprocess.run",
        lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError()),
    )
    r = client.get("/api/device")
    assert r.status_code == 200
    assert r.json() == {"serials": []}


def test_device_screenshot_503_when_unavailable(monkeypatch, client):
    monkeypatch.setattr("nutcracker_core.plugins.dashboard.device.screenshot_png", lambda serial=None: None)
    r = client.get("/api/device/screenshot")
    assert r.status_code == 503


def test_agent_prompt_response_shape(client):
    # No forzamos el import a fallar (aipwn puede o no estar instalado en el
    # entorno de test) — solo verificamos la forma de la respuesta en ambos casos.
    r = client.get("/api/agent/prompt")
    assert r.status_code == 200
    assert "available" in r.json()
