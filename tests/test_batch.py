"""Tests de `nutcracker batch` migrado al motor de cola (Fase 1 del plan).

`_summary_for_outcome` se prueba contra una SQLite real (reconstruye el
resumen consolidado desde `runs`/`findings`, ya no desde objetos en memoria);
el comando en sí se prueba con CliRunner + una QueueEngine falsa, sin correr
subprocesos ni tocar red/disco de verdad.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from nutcracker_core.cli.batch import _summary_for_outcome
from nutcracker_core.queue.engine import JobOutcome
from nutcracker_core.queue.job import Job
from nutcracker_core.store import db, repository


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "batch_test.db")


def _seed_run(db_path: str, package: str, verdict: str, findings: list[dict] | None = None) -> int:
    conn = db.connect(db_path)
    try:
        run_id = repository.insert_run(conn, package, kind="full", status="done")
        repository.update_run_status(conn, run_id, status="done", verdict=verdict, masvs_score=70, grade="C")
        if findings:
            repository.record_findings(conn, run_id, [
                repository.FindingRecord(
                    rule_id=f["rule_id"], title=f.get("title", ""), severity=f.get("severity", "info"),
                    category=f.get("category", ""),
                )
                for f in findings
            ])
        return run_id
    finally:
        conn.close()


# ── _summary_for_outcome ─────────────────────────────────────────────────────

def test_summary_for_failed_outcome_has_error_status(db_path):
    job = Job(target="com.broken.app", kind="static")
    job.db_id = 1
    outcome = JobOutcome(job=job, ok=False, returncode=1, error="algo falló", run_id=None, package=None)

    summary = _summary_for_outcome(db_path, outcome)

    assert summary["status"] == "error"
    assert summary["error"] == "algo falló"
    assert summary["target"] == "com.broken.app"


def test_summary_for_successful_outcome_reconstructs_severities_from_db(db_path):
    run_id = _seed_run(db_path, "com.example.app", "protected", findings=[
        {"rule_id": "HC001", "title": "API key hardcodeada", "severity": "high", "category": "M1"},
        {"rule_id": "HC001", "title": "API key hardcodeada", "severity": "high", "category": "M1"},
        {"rule_id": "CRYPTO001", "title": "MD5 en uso", "severity": "medium", "category": "M5"},
        {"rule_id": "GL-001", "title": "Leak de gitleaks", "severity": "critical", "category": "M1"},
    ])
    job = Job(target="com.example.app", kind="static")
    job.db_id = 2
    outcome = JobOutcome(job=job, ok=True, returncode=0, run_id=run_id, package="com.example.app")

    summary = _summary_for_outcome(db_path, outcome)

    assert summary["status"] == "protected"
    assert summary["findings"] == 4
    assert summary["high"] == 2
    assert summary["medium"] == 1
    assert summary["critical"] == 1
    assert summary["leaks"] == 3  # se cuenta por hallazgo, no por rule_id único: 2x HC001 + 1x GL-001
    assert summary["categories"]["M1"] == "critical"  # peor severidad de esa categoría
    # top_findings único por rule_id, ordenado por severidad (critical primero)
    rule_ids = [t[0] for t in summary["top_findings"]]
    assert rule_ids[0] == "GL-001"
    assert rule_ids.count("HC001") == 1


@pytest.mark.parametrize("verdict,expected_status", [
    ("protection_broken", "protected_broken"),
    ("protected", "protected"),
    ("not_protected", "unprotected"),
])
def test_summary_verdict_mapping(db_path, verdict, expected_status):
    run_id = _seed_run(db_path, "com.example.app", verdict)
    job = Job(target="com.example.app", kind="static")
    job.db_id = 3
    outcome = JobOutcome(job=job, ok=True, returncode=0, run_id=run_id, package="com.example.app")

    summary = _summary_for_outcome(db_path, outcome)
    assert summary["status"] == expected_status


# ── comando `batch` end-to-end (QueueEngine mockeada) ────────────────────────

class _FakeEngine:
    """Doble de QueueEngine: no corre subprocesos — cada submit() produce un
    JobOutcome predefinido, entregado a on_result cuando drain() corre."""

    def __init__(self, outcomes_by_target: dict[str, JobOutcome], db_path=None, **kw):
        self.db_path = db_path
        self._outcomes_by_target = outcomes_by_target
        self._pending: list[str] = []
        self.on_line = None

    def submit(self, target, kind="static", **kw):
        self._pending.append(target)
        job = Job(target=target, kind=kind)
        job.db_id = len(self._pending)
        return job

    def submit_many(self, targets, kind="static"):
        return [self.submit(t, kind=kind) for t in targets]

    def drain(self, on_result=None):
        outcomes = []
        for target in self._pending:
            outcome = self._outcomes_by_target[target]
            outcomes.append(outcome)
            if on_result:
                on_result(outcome)
        self._pending = []
        return outcomes


def _fake_outcome(target: str, ok: bool = True, package: str | None = None) -> JobOutcome:
    job = Job(target=target)
    return JobOutcome(job=job, ok=ok, returncode=0 if ok else 1,
                       run_id=None, package=package or (target if ok else None),
                       error="" if ok else "boom")


def test_batch_command_missing_list_file_exits_nonzero(tmp_path, monkeypatch):
    from nutcracker_core.cli import batch as batch_mod

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(batch_mod.batch, ["no_existe.txt"])
    assert result.exit_code != 0


def test_batch_command_runs_targets_through_queue_engine(tmp_path, monkeypatch):
    from nutcracker_core.cli import batch as batch_mod

    list_file = tmp_path / "targets.txt"
    list_file.write_text("com.app.one\ncom.app.two\n# comentario\n\n")

    config_path = tmp_path / "config.yaml"
    config_path.write_text("queue:\n  static_workers: 4\nreports:\n  save_pdf: false\n")

    outcomes = {
        "com.app.one": _fake_outcome("com.app.one", ok=True),
        "com.app.two": _fake_outcome("com.app.two", ok=False),
    }
    monkeypatch.setattr(
        batch_mod, "QueueEngine",
        lambda **kw: _FakeEngine(outcomes, **kw),
    )
    monkeypatch.setattr(batch_mod, "_summary_for_outcome",
                         lambda db_path, outcome: {"target": outcome.job.target,
                                                    "status": "protected" if outcome.ok else "error",
                                                    "error": outcome.error})

    runner = CliRunner()
    result = runner.invoke(batch_mod.batch, [str(list_file), "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "com.app.one" in result.output
    assert "com.app.two" in result.output


def test_batch_sequential_mode_stops_on_error(tmp_path, monkeypatch):
    from nutcracker_core.cli import batch as batch_mod

    list_file = tmp_path / "targets.txt"
    list_file.write_text("com.app.one\ncom.app.two\ncom.app.three\n")

    config_path = tmp_path / "config.yaml"
    config_path.write_text("queue:\n  static_workers: 1\nreports:\n  save_pdf: false\n")

    outcomes = {
        "com.app.one": _fake_outcome("com.app.one", ok=True),
        "com.app.two": _fake_outcome("com.app.two", ok=False),
        "com.app.three": _fake_outcome("com.app.three", ok=True),
    }
    engines: list[_FakeEngine] = []

    def _make_engine(**kw):
        eng = _FakeEngine(outcomes, **kw)
        engines.append(eng)
        return eng

    monkeypatch.setattr(batch_mod, "QueueEngine", _make_engine)
    monkeypatch.setattr(batch_mod, "_summary_for_outcome",
                         lambda db_path, outcome: {"target": outcome.job.target,
                                                    "status": "protected" if outcome.ok else "error",
                                                    "error": outcome.error})

    runner = CliRunner()
    result = runner.invoke(
        batch_mod.batch,
        [str(list_file), "--config", str(config_path), "--stop-on-error"],
    )

    assert result.exit_code == 0, result.output
    assert "com.app.one" in result.output
    assert "com.app.two" in result.output
    # com.app.three nunca debió encolarse: nos detuvimos tras el error en two.
    assert "com.app.three" not in result.output
