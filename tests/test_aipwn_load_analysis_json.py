"""Tests de nutcracker_core/plugins/aipwn/__init__.py::_load_analysis_json.

Bug encontrado en vivo (job 2823/sh.nutcracker.nutbank, 2026-08-04): la
lista negra de nombres reservados (_SKIP: vuln.json/osint.json/
bypass_result.json) no cubría `exploit_report_<package>.json` (escrito por
el exploit agent) -- ese archivo tiene una key "package" pero no
"detections", y `AnalysisResult.from_dict()` lo aceptaba en silencio como un
análisis VACÍO (results=[]) en vez de tirar KeyError. El agente LLM de aipwn
reportaba entonces "sin protecciones detectadas" pese a que el análisis
estático real (guardado aparte con el patrón <YYYYMMDD>_<HHMMSS>.json de
reporter.save_analysis_json) sí había encontrado RootBeer, anti-Frida, etc.

Afecta a CUALQUIER app con un exploit_report previo -- o sea, después del
primer bypass exitoso, cada corrida siguiente de aipwn perdía la detección
estática por completo.
"""

from __future__ import annotations

import json

from nutcracker_core.plugins.aipwn import _load_analysis_json


def _real_analysis_json(package: str) -> dict:
    """Forma real de lo que reporter.save_analysis_json() escribe -- key
    "detections" presente, aunque sea vacía."""
    return {
        "package": package,
        "version_name": "1.0",
        "version_code": "1",
        "min_sdk": "21",
        "target_sdk": "33",
        "analyzed_at": "2026-08-04T12:00:00",
        "detections": [
            {"name": "Known anti-root libraries", "detected": True, "strength": "high",
             "details": ["[RootBeer] Found: Lcom/scottyab/rootbeer/RootBeer;"]},
        ],
    }


def _exploit_report_json(package: str) -> dict:
    """Forma real de exploit_report_<package>.json -- tiene "package" pero
    NO "detections" (schema completamente distinto a AnalysisResult)."""
    return {
        "package": package,
        "confirmed": True,
        "unverifiable": [],
        "total_attempted": 3,
        "skipped": [],
        "results": [],
    }


def test_ignores_exploit_report_and_loads_real_analysis(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pkg_dir = tmp_path / "reports" / "com.example.app"
    pkg_dir.mkdir(parents=True)

    (pkg_dir / "exploit_report_com.example.app.json").write_text(
        json.dumps(_exploit_report_json("com.example.app"))
    )
    (pkg_dir / "20260804_120000.json").write_text(
        json.dumps(_real_analysis_json("com.example.app"))
    )

    result = _load_analysis_json("com.example.app")

    assert result is not None
    assert result.package == "com.example.app"
    assert len(result.results) == 1
    assert result.results[0].name == "Known anti-root libraries"
    assert result.results[0].detected is True


def test_ignores_other_reserved_reports_too(tmp_path, monkeypatch):
    """vuln.json/osint.json/bypass_result.json tampoco son un
    AnalysisResult -- deben seguir ignorándose (aunque ahora el filtro es
    por patrón positivo de nombre, no lista negra)."""
    monkeypatch.chdir(tmp_path)
    pkg_dir = tmp_path / "reports" / "com.example.app"
    pkg_dir.mkdir(parents=True)

    (pkg_dir / "vuln.json").write_text(json.dumps({"package": "com.example.app"}))
    (pkg_dir / "osint.json").write_text(json.dumps({"package": "com.example.app"}))
    (pkg_dir / "bypass_result.json").write_text(json.dumps({"package": "com.example.app"}))
    (pkg_dir / "20260804_120000.json").write_text(
        json.dumps(_real_analysis_json("com.example.app"))
    )

    result = _load_analysis_json("com.example.app")

    assert result is not None
    assert len(result.results) == 1


def test_picks_most_recent_timestamped_analysis(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pkg_dir = tmp_path / "reports" / "com.example.app"
    pkg_dir.mkdir(parents=True)

    old = _real_analysis_json("com.example.app")
    old["detections"] = []
    (pkg_dir / "20260101_120000.json").write_text(json.dumps(old))

    new = _real_analysis_json("com.example.app")
    (pkg_dir / "20260804_183622.json").write_text(json.dumps(new))

    result = _load_analysis_json("com.example.app")

    assert result is not None
    assert len(result.results) == 1  # el "new" -- el "old" tenía detections=[]


def test_returns_none_without_any_valid_analysis_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pkg_dir = tmp_path / "reports" / "com.example.app"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "exploit_report_com.example.app.json").write_text(
        json.dumps(_exploit_report_json("com.example.app"))
    )

    assert _load_analysis_json("com.example.app") is None


def test_returns_none_without_reports_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _load_analysis_json("com.nonexistent.app") is None


def test_legacy_single_file_also_requires_detections_key(tmp_path, monkeypatch):
    """Formato legado reports/<package>.json (sin subcarpeta) -- mismo
    resguardo de validar "detections" antes de aceptarlo."""
    monkeypatch.chdir(tmp_path)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    (reports_dir / "com.example.app.json").write_text(
        json.dumps(_real_analysis_json("com.example.app"))
    )

    result = _load_analysis_json("com.example.app")

    assert result is not None
    assert len(result.results) == 1
