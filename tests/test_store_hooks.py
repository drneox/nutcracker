"""Tests del post-hook after_analysis -> SQLite (store/hooks.py).

Usa datos simulados (mocks) de AnalysisResult/ScanResult en vez de correr un
análisis real de APK, para verificar la persistencia de forma aislada y rápida.
"""

from pathlib import Path

import pytest

from nutcracker_core.analyzer import AnalysisResult
from nutcracker_core.detectors.base import DetectionResult
from nutcracker_core.store import db, repository
from nutcracker_core.store.hooks import _persist_after_analysis
from nutcracker_core.vuln_scanner import ScanResult, VulnFinding


def _mock_result(protected: bool = True, protection_broken: bool = False) -> AnalysisResult:
    result = AnalysisResult(
        package="com.example.mock",
        version_name="1.0",
        version_code="1",
        min_sdk="21",
        target_sdk="34",
        analyzed_at="2026-07-21T10:00:00",
        results=[DetectionResult(name="RootBeer", detected=protected, strength="high")],
    )
    if protection_broken:
        result.decompilation_info = {"method": "frida-dexdump", "dex_count": 3}
    return result


def _mock_scan(base_dir: Path) -> ScanResult:
    finding = VulnFinding(
        rule_id="HC001",
        title="Hardcoded secret",
        severity="high",
        category="M9",
        file=base_dir / "Foo.java",
        line=42,
        matched_text="API_KEY=...",
        description="desc",
        recommendation="rec",
    )
    return ScanResult(base_dir=base_dir, findings=[finding], files_scanned=1)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "nutcracker.db"


def _write_fake_artifacts(package: str) -> None:
    """Crea JSON/PDF de mentira en ./reports/<package>/, la misma convención hardcodeada
    que usan save_analysis_json()/_generate_pdf() (relativa al cwd), para que
    hooks._find_artifacts() los descubra igual que con un análisis real."""
    pkg_dir = Path("./reports") / package
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "20260721_160530.json").write_text("{}", encoding="utf-8")
    (pkg_dir / f"nutcracker_{package}_report.pdf").write_bytes(b"%PDF-1.4 fake")


def test_persist_after_analysis_writes_run_findings_and_artifacts(db_path, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = _mock_result(protected=True, protection_broken=True)
    scan = _mock_scan(tmp_path)
    _write_fake_artifacts(result.package)
    config = {"store": {"db_path": str(db_path)}}

    _persist_after_analysis(
        package=result.package,
        result=result,
        vuln_scan=scan,
        config=config,
    )

    conn = db.connect(str(db_path))
    try:
        app = repository.get_app(conn, "com.example.mock")
        assert app is not None
        assert app["last_run_at"] is not None

        runs = repository.history(conn, "com.example.mock")
        assert len(runs) == 1
        run = runs[0]
        assert run["status"] == "done"
        assert run["verdict"] == "protection_broken"

        findings = repository.findings_for_run(conn, run["id"])
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "HC001"
        assert findings[0]["masvs"] == "MASVS-STORAGE-2"

        artifacts = repository.artifacts_for_run(conn, run["id"])
        assert {a["type"] for a in artifacts} == {"json", "pdf"}
    finally:
        conn.close()


def test_persist_after_analysis_respects_store_disabled(db_path, tmp_path):
    result = _mock_result(protected=False)
    config = {"store": {"db_path": str(db_path), "enabled": False}}

    _persist_after_analysis(
        package=result.package, result=result, vuln_scan=None, config=config,
    )

    assert not db_path.exists()


def test_persist_after_analysis_verdict_not_protected(db_path, tmp_path):
    result = _mock_result(protected=False)
    config = {"store": {"db_path": str(db_path)}}

    _persist_after_analysis(package=result.package, result=result, vuln_scan=None, config=config)

    conn = db.connect(str(db_path))
    try:
        run = repository.history(conn, "com.example.mock")[0]
        assert run["verdict"] == "not_protected"
    finally:
        conn.close()
