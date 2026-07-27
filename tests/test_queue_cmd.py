"""Tests de `nutcracker queue add` (Fase: batch estático+aipwn desde archivo).

Igual que test_batch.py: el comando se prueba con CliRunner + una QueueEngine
falsa (sin subprocesos/red/disco real) -- lo que se ejercita aquí es la
mecánica de --then-aipwn (encadenar aipwn tras cada estático OK) y el flag
global --source/--serial, no el pipeline de análisis real.
"""

from __future__ import annotations

from click.testing import CliRunner

from nutcracker_core.cli import queue_cmd
from nutcracker_core.queue.engine import JobOutcome
from nutcracker_core.queue.job import Job


class _FakeEngine:
    """Doble de QueueEngine: submit() registra la llamada y produce un Job;
    drain() resuelve todos los jobs pendientes (soporta múltiples llamadas,
    a diferencia de test_batch.py, porque --then-aipwn encola una segunda
    tanda tras la primera drain())."""

    def __init__(self, outcomes_by_target: dict[str, JobOutcome], db_path=None, **kw):
        self.db_path = db_path
        self._outcomes_by_target = outcomes_by_target
        self._pending: list[Job] = []
        self.submit_calls: list[dict] = []
        self.on_line = None

    def submit(self, target, kind="static", serial=None, priority=0, source=None):
        self.submit_calls.append({"target": target, "kind": kind, "serial": serial, "source": source})
        job = Job(target=target, kind=kind, serial=serial, source=source)
        job.db_id = len(self.submit_calls)
        self._pending.append(job)
        return job

    def drain(self, on_result=None):
        outcomes = []
        for job in self._pending:
            outcome = self._outcomes_by_target[job.target]
            outcome.job = job  # conserva kind real (static/aipwn) de este submit
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


def test_then_aipwn_chains_aipwn_after_each_successful_static_job(tmp_path, monkeypatch):
    list_file = tmp_path / "targets.txt"
    list_file.write_text("com.app.one\ncom.app.two\n")

    config_path = tmp_path / "config.yaml"
    config_path.write_text("queue:\n  static_workers: 4\n")

    outcomes = {
        "com.app.one": _fake_outcome("com.app.one", ok=True),
        "com.app.two": _fake_outcome("com.app.two", ok=True),
    }
    engine = _FakeEngine(outcomes)
    monkeypatch.setattr(queue_cmd, "_build_engine", lambda config_path: engine)

    runner = CliRunner()
    result = runner.invoke(
        queue_cmd.queue_add,
        [str(list_file), "--config", str(config_path), "--then-aipwn", "--run"],
    )

    assert result.exit_code == 0, result.output
    kinds_submitted = [c["kind"] for c in engine.submit_calls]
    # 2 estáticos encolados primero, luego 2 aipwn encadenados tras drain() de los estáticos.
    assert kinds_submitted == ["static", "static", "aipwn", "aipwn"]
    aipwn_targets = {c["target"] for c in engine.submit_calls if c["kind"] == "aipwn"}
    assert aipwn_targets == {"com.app.one", "com.app.two"}
    assert "4/4 OK" in result.output


def test_then_aipwn_does_not_chain_after_failed_static_job(tmp_path, monkeypatch):
    list_file = tmp_path / "targets.txt"
    list_file.write_text("com.app.broken\ncom.app.ok\n")

    config_path = tmp_path / "config.yaml"
    config_path.write_text("queue:\n  static_workers: 4\n")

    outcomes = {
        "com.app.broken": _fake_outcome("com.app.broken", ok=False),
        "com.app.ok": _fake_outcome("com.app.ok", ok=True),
    }
    engine = _FakeEngine(outcomes)
    monkeypatch.setattr(queue_cmd, "_build_engine", lambda config_path: engine)

    runner = CliRunner()
    result = runner.invoke(
        queue_cmd.queue_add,
        [str(list_file), "--config", str(config_path), "--then-aipwn", "--run"],
    )

    assert result.exit_code == 0, result.output
    aipwn_targets = [c["target"] for c in engine.submit_calls if c["kind"] == "aipwn"]
    assert aipwn_targets == ["com.app.ok"]


def test_then_aipwn_rejects_combination_with_dynamic_flag(tmp_path, monkeypatch):
    list_file = tmp_path / "targets.txt"
    list_file.write_text("com.app.one\n")
    engine = _FakeEngine({})
    monkeypatch.setattr(queue_cmd, "_build_engine", lambda config_path: engine)

    runner = CliRunner()
    result = runner.invoke(queue_cmd.queue_add, [str(list_file), "--then-aipwn", "--dynamic"])

    assert result.exit_code != 0
    assert not engine.submit_calls


def test_source_and_serial_propagate_to_every_submit_call(tmp_path, monkeypatch):
    """--source device --serial X (flag global del archivo, no por línea)."""
    list_file = tmp_path / "targets.txt"
    list_file.write_text("com.app.one\ncom.app.two\n")

    outcomes = {
        "com.app.one": _fake_outcome("com.app.one", ok=True),
        "com.app.two": _fake_outcome("com.app.two", ok=True),
    }
    engine = _FakeEngine(outcomes)
    monkeypatch.setattr(queue_cmd, "_build_engine", lambda config_path: engine)

    runner = CliRunner()
    result = runner.invoke(
        queue_cmd.queue_add,
        [str(list_file), "--source", "device", "--serial", "ZY22GPM27J"],
    )

    assert result.exit_code == 0, result.output
    assert len(engine.submit_calls) == 2
    assert all(c["source"] == "device" for c in engine.submit_calls)
    assert all(c["serial"] == "ZY22GPM27J" for c in engine.submit_calls)
