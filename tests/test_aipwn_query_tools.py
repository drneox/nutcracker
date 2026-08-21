"""Tests de nutcracker_core/plugins/aipwn/query_tools.py -- el catálogo de
herramientas del co-piloto de consulta (query_agent.py::QueryAgent). Cubre las
tools nuevas de store/reportes (list_findings, get_finding_detail,
list_components, list_secrets, get_exploit_results) y de DeviceIO/UI
(screencap+shell en modo serial y relay, ui_tap/ui_input_text/ui_swipe),
todas contra datos reales de archivo (no mocks del formato JSON)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nutcracker_core.plugins.aipwn.frida_agent_tools import ToolContext
from nutcracker_core.plugins.aipwn.query_tools import (
    DeviceIO,
    dispatch_query_tool,
    tool_get_exploit_results,
    tool_get_finding_detail,
    tool_list_components,
    tool_list_findings,
    tool_list_secrets,
)
from nutcracker_core.store import db, repository


def _make_ctx(package: str, decompiled_dir: Path | None = None, runtime_dump_dir: Path | None = None) -> ToolContext:
    return ToolContext(
        package=package,
        decompiled_dir=decompiled_dir,
        analysis_result=None,
        serial=None,
        capture_seconds=15,
        scripts_dir=Path("/tmp"),
        on_frida_run=lambda script_js, rationale, iteration: None,
        runtime_dump_dir=runtime_dump_dir,
    )


# ── list_findings / get_finding_detail ───────────────────────────────────────

@pytest.fixture
def db_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = str(tmp_path / "test.db")
    conn = db.connect(path)
    try:
        run_id = repository.insert_run(conn, "com.example.app", kind="full", status="done")
        repository.update_run_status(conn, run_id, status="done", verdict="protection_broken",
                                      masvs_score=40, grade="D")
        repository.record_findings(conn, run_id, [
            repository.FindingRecord(rule_id="HC002", title="Hardcoded password", severity="high",
                                      category="M1 - Credenciales", file="Secrets.java", line=8,
                                      masvs=["MASVS-STORAGE-1"], maswe=[], cwe=["CWE-798"]),
            repository.FindingRecord(rule_id="COMP008", title="Provider exportado", severity="critical",
                                      category="M6 - Componentes inseguros", file="AndroidManifest.xml", line=0,
                                      masvs=[], maswe=[], cwe=[]),
        ])
        repository.touch_app_run(conn, "com.example.app")
    finally:
        conn.close()
    return path


def _write_vuln_json(package: str) -> None:
    out_dir = Path("reports") / package
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "vuln.json").write_text(json.dumps({
        "files_scanned": 10,
        "total_findings": 2,
        "findings": [
            {
                "rule_id": "HC002", "title": "Hardcoded password", "severity": "high",
                "category": "M1 - Credenciales", "file": "Secrets.java", "line": 8,
                "matched_text": "ACCOUNT_TOKEN = \"sk_live_FAKE\"",
                "description": "Token hardcodeado en el código.",
                "recommendation": "Mover a un secret manager.",
            },
            {
                "rule_id": "COMP008", "title": "Provider exportado", "severity": "critical",
                "category": "M6 - Componentes inseguros", "file": "AndroidManifest.xml", "line": 0,
                "matched_text": "<provider exported=\"true\">",
                "description": "Provider sin permission.",
                "recommendation": "Agregar android:exported=\"false\".",
            },
        ],
    }))


def test_list_findings_returns_rows_from_latest_run(db_path):
    ctx = _make_ctx("com.example.app")
    result = json.loads(tool_list_findings(ctx, db_path))
    assert result["count"] == 2
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert rule_ids == {"HC002", "COMP008"}


def test_list_findings_filters_by_severity(db_path):
    ctx = _make_ctx("com.example.app")
    result = json.loads(tool_list_findings(ctx, db_path, severity="critical"))
    assert result["count"] == 1
    assert result["findings"][0]["rule_id"] == "COMP008"


def test_list_findings_enriches_with_vuln_json_description(db_path):
    _write_vuln_json("com.example.app")
    ctx = _make_ctx("com.example.app")
    result = json.loads(tool_list_findings(ctx, db_path))
    hc = next(f for f in result["findings"] if f["rule_id"] == "HC002")
    assert hc["description"] == "Token hardcodeado en el código."
    assert hc["recommendation"] == "Mover a un secret manager."


def test_list_findings_unknown_package_returns_empty_with_note(db_path):
    ctx = _make_ctx("com.unknown.app")
    result = json.loads(tool_list_findings(ctx, db_path))
    assert result["count"] == 0
    assert "note" in result


def test_get_finding_detail_merges_vuln_json_and_review(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_vuln_json("com.example.app")
    review_path = Path("decompiled") / "vuln_com.example.app_review.json"
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_text(json.dumps({
        "reviews": [{"rule_id": "HC002", "file": "Secrets.java", "line": 8, "verdict": "TRUE_POSITIVE"}],
    }))
    ctx = _make_ctx("com.example.app")

    result = json.loads(tool_get_finding_detail(ctx, "HC002"))

    assert len(result["matches"]) == 1
    assert result["matches"][0]["aireview_verdict"] == "TRUE_POSITIVE"


def test_get_finding_detail_not_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_vuln_json("com.example.app")
    ctx = _make_ctx("com.example.app")

    result = json.loads(tool_get_finding_detail(ctx, "NOPE999"))

    assert "error" in result


# ── list_components (manifest_analyzer real) ─────────────────────────────────

_MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
    <application android:allowBackup="true" android:debuggable="false">
        <provider android:name="com.example.app.LeakyProvider" android:exported="true" />
        <activity android:name="com.example.app.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def test_list_components_parses_real_manifest(tmp_path):
    decompiled_dir = tmp_path / "com.example.app"
    (decompiled_dir / "resources").mkdir(parents=True)
    (decompiled_dir / "resources" / "AndroidManifest.xml").write_text(_MANIFEST_XML)
    ctx = _make_ctx("com.example.app", decompiled_dir=decompiled_dir)

    result = json.loads(tool_list_components(ctx))

    assert result["target_sdk"] == 33
    exported_names = {c["name"] for c in result["exported_components"]}
    assert "com.example.app.LeakyProvider" in exported_names
    # El launcher (MAIN+LAUNCHER) no debe listarse como exportado "sospechoso"
    assert "com.example.app.MainActivity" not in exported_names


def test_list_components_no_decompiled_dir_returns_error():
    ctx = _make_ctx("com.example.app", decompiled_dir=None)
    result = json.loads(tool_list_components(ctx))
    assert "error" in result


# ── list_secrets ──────────────────────────────────────────────────────────────

def test_list_secrets_filters_findings_by_keyword_and_marks_confirmed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_vuln_json("com.example.app")
    reports_dir = Path("reports") / "com.example.app"
    (reports_dir / "exploit_report_com.example.app.json").write_text(json.dumps({
        "package": "com.example.app", "confirmed": 1, "unverifiable": 0, "total_attempted": 1, "skipped": 0,
        "results": [{"rule_id": "HC002", "status": "confirmed"}],
    }))
    ctx = _make_ctx("com.example.app")

    result = json.loads(tool_list_secrets(ctx))

    hc = next(s for s in result["secrets"] if s["rule_id"] == "HC002")
    assert hc["aipwn_confirmed"] is True
    # COMP008 (provider exportado) no matchea keywords de secreto
    assert not any(s["rule_id"] == "COMP008" for s in result["secrets"])


# ── get_exploit_results ───────────────────────────────────────────────────────

def test_get_exploit_results_reads_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reports_dir = Path("reports") / "com.example.app"
    reports_dir.mkdir(parents=True)
    (reports_dir / "exploit_report_com.example.app.json").write_text(json.dumps({
        "package": "com.example.app", "confirmed": 1, "unverifiable": 0,
        "total_attempted": 1, "skipped": 0,
        "results": [{"rule_id": "HC002", "status": "confirmed", "poc_command": "grep ..."}],
    }))
    ctx = _make_ctx("com.example.app")

    result = json.loads(tool_get_exploit_results(ctx))

    assert result["confirmed"] == 1
    assert result["results"][0]["rule_id"] == "HC002"


def test_get_exploit_results_missing_report_returns_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctx = _make_ctx("com.example.app")
    result = json.loads(tool_get_exploit_results(ctx))
    assert "error" in result


# ── DeviceIO (serial + relay) y tools de UI ──────────────────────────────────

class _FakeCompletedProcess:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def test_device_io_serial_screencap_uses_adb_dash_s(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _FakeCompletedProcess(stdout=b"\x89PNGfakedata")

    monkeypatch.setattr("subprocess.run", fake_run)
    device = DeviceIO(serial="ABC123")

    png = device.screencap()

    assert png == b"\x89PNGfakedata"
    assert calls[0] == ["adb", "-s", "ABC123", "exec-out", "screencap", "-p"]


def test_device_io_serial_shell_runs_adb_shell(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return type("R", (), {"stdout": "output-here", "returncode": 0})()

    monkeypatch.setattr("subprocess.run", fake_run)
    device = DeviceIO(serial="ABC123")

    out = device.shell("input tap 100 200")

    assert out == "output-here"
    assert calls[0] == ["adb", "-s", "ABC123", "shell", "input tap 100 200"]


class _FakeRelaySession:
    def __init__(self):
        self.calls = []

    async def rpc(self, op, timeout=30.0, **fields):
        self.calls.append((op, fields))
        if op == "screencap":
            import base64
            return {"data_b64": base64.b64encode(b"\x89PNGrelaydata").decode()}
        if op == "shell":
            return {"stdout": "relay-output"}
        raise AssertionError(f"unexpected op {op}")


def test_device_io_relay_screencap_and_shell(tmp_path):
    import asyncio

    async def _run():
        loop = asyncio.get_running_loop()
        session = _FakeRelaySession()
        device = DeviceIO(relay_session=session, loop=loop)

        # screencap y shell hacen run_coroutine_threadsafe -- corren en el
        # mismo loop en este test, pero el mecanismo es el mismo que en
        # producción (loop real del hilo del WebSocket).
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as ex:
            png = await loop.run_in_executor(ex, device.screencap)
            out = await loop.run_in_executor(ex, device.shell, "input keyevent 4")

        assert png == b"\x89PNGrelaydata"
        assert out == "relay-output"
        assert session.calls[0][0] == "screencap"
        assert session.calls[1] == ("shell", {"command": "input keyevent 4"})

    asyncio.run(_run())


def test_dispatch_query_tool_ui_tap_without_device_reports_error(tmp_path):
    ctx = _make_ctx("com.example.app")
    result = json.loads(dispatch_query_tool(
        ctx, "ui_tap", {"x": 10, "y": 20}, db_path=str(tmp_path / "x.db"), device=None,
    ))
    assert "error" in result


def test_dispatch_query_tool_ui_tap_with_device(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        "subprocess.run",
        lambda cmd, **kw: calls.append(cmd) or type("R", (), {"stdout": "", "returncode": 0})(),
    )
    ctx = _make_ctx("com.example.app")
    device = DeviceIO(serial="ABC")

    result = json.loads(dispatch_query_tool(
        ctx, "ui_tap", {"x": 10, "y": 20}, db_path=str(tmp_path / "x.db"), device=device,
    ))

    assert result["status"] == "ok"
    assert calls[0] == ["adb", "-s", "ABC", "shell", "input tap 10 20"]


def test_dispatch_query_tool_unknown_name_returns_error(tmp_path):
    ctx = _make_ctx("com.example.app")
    result = json.loads(dispatch_query_tool(
        ctx, "nope_not_a_tool", {}, db_path=str(tmp_path / "x.db"), device=None,
    ))
    assert "error" in result


def test_dispatch_query_tool_missing_required_arg_does_not_crash(tmp_path):
    ctx = _make_ctx("com.example.app")
    result = json.loads(dispatch_query_tool(
        ctx, "get_finding_detail", {}, db_path=str(tmp_path / "x.db"), device=None,
    ))
    assert "error" in result
