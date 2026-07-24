"""Tests de nutcracker_core.store.repository sobre una base SQLite en memoria."""

import pytest

from nutcracker_core.store import db, repository


@pytest.fixture
def conn():
    connection = db.connect(":memory:")
    yield connection
    connection.close()


def test_upsert_app_creates_row(conn):
    repository.upsert_app(conn, "com.example.app", source="apkpure")

    row = repository.get_app(conn, "com.example.app")
    assert row is not None
    assert row["source"] == "apkpure"
    assert row["first_seen"] is not None


def test_upsert_app_does_not_overwrite_first_seen(conn):
    repository.upsert_app(conn, "com.example.app")
    first_seen = repository.get_app(conn, "com.example.app")["first_seen"]

    repository.upsert_app(conn, "com.example.app", source="google-play")

    row = repository.get_app(conn, "com.example.app")
    assert row["first_seen"] == first_seen
    assert row["source"] == "google-play"


def test_insert_run_creates_app_and_run(conn):
    run_id = repository.insert_run(conn, "com.example.app", kind="static", status="queued")

    assert run_id > 0
    assert repository.get_app(conn, "com.example.app") is not None
    run = repository.get_run(conn, run_id)
    assert run["package"] == "com.example.app"
    assert run["kind"] == "static"
    assert run["status"] == "queued"


def test_update_run_status_sets_finished_at_on_done(conn):
    run_id = repository.insert_run(conn, "com.example.app")

    repository.update_run_status(conn, run_id, status="done", verdict="protected",
                                   masvs_score=80, grade="B")

    run = repository.get_run(conn, run_id)
    assert run["status"] == "done"
    assert run["verdict"] == "protected"
    assert run["masvs_score"] == 80
    assert run["grade"] == "B"
    assert run["finished_at"] is not None


def test_record_and_fetch_findings(conn):
    run_id = repository.insert_run(conn, "com.example.app")
    findings = [
        repository.FindingRecord(
            rule_id="HC001", title="Hardcoded secret", severity="high",
            category="M9", masvs=["MASVS-STORAGE-2"], file="Foo.java", line=42,
        ),
        repository.FindingRecord(rule_id="COMP001", title="Exported activity", severity="medium"),
    ]

    repository.record_findings(conn, run_id, findings)

    rows = repository.findings_for_run(conn, run_id)
    assert len(rows) == 2
    assert rows[0]["rule_id"] == "HC001"
    assert rows[0]["masvs"] == "MASVS-STORAGE-2"
    assert rows[0]["line"] == 42


def test_record_artifact(conn):
    run_id = repository.insert_run(conn, "com.example.app")

    repository.record_artifact(conn, run_id, "json", "/reports/com.example.app/20260101.json")
    repository.record_artifact(conn, run_id, "pdf", "/reports/com.example.app/report.pdf")

    artifacts = repository.artifacts_for_run(conn, run_id)
    assert {a["type"] for a in artifacts} == {"json", "pdf"}


def test_history_orders_most_recent_first(conn):
    first = repository.insert_run(conn, "com.example.app")
    second = repository.insert_run(conn, "com.example.app")

    rows = repository.history(conn, "com.example.app")

    assert [r["id"] for r in rows] == [second, first]


def test_set_schedule_computes_next_due_at(conn):
    repository.set_schedule(conn, "com.example.app", interval_days=30)

    app = repository.get_app(conn, "com.example.app")
    schedule = repository.get_schedule(conn, "com.example.app")
    assert schedule["interval_days"] == 30
    assert schedule["enabled"] == 1
    assert app["next_due_at"] is not None


def test_apps_due_returns_only_past_due(conn):
    repository.set_schedule(conn, "com.due.app", interval_days=30)
    conn.execute(
        "UPDATE apps SET next_due_at = '2000-01-01T00:00:00+00:00' WHERE package = ?",
        ("com.due.app",),
    )
    conn.commit()
    repository.set_schedule(conn, "com.future.app", interval_days=30)  # vence en 30 días

    due = repository.apps_due(conn)

    assert [row["package"] for row in due] == ["com.due.app"]


def test_list_schedules(conn):
    repository.set_schedule(conn, "com.a", interval_days=15)
    repository.set_schedule(conn, "com.b", interval_days=30)

    schedules = repository.list_schedules(conn)

    assert [s["package"] for s in schedules] == ["com.a", "com.b"]
