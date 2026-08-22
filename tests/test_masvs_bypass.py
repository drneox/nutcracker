"""Tests del item de ROADMAP cerrado en Fase 2.4: separar el veredicto de
bypass estático (protection_broken, exige DEX extraído) del bypass dinámico
confirmado por el plugin aipwn (aipwn_bypass_confirmed, sin esa exigencia)."""

from __future__ import annotations

from nutcracker_core.analyzer import AnalysisResult
from nutcracker_core.detectors.base import DetectionResult
from nutcracker_core.masvs import build_masvs_report


def _protected_result(aipwn_bypass_confirmed: bool = False, dex_count: int = 0) -> AnalysisResult:
    result = AnalysisResult(
        package="com.example.app",
        version_name="1.0",
        version_code="1",
        min_sdk="21",
        target_sdk="33",
        analyzed_at="2026-07-24T00:00:00Z",
        results=[DetectionResult(name="Known anti-root libraries", detected=True, strength="high")],
    )
    if dex_count:
        result.decompilation_info = {"method": "frida-dexdump", "dex_count": dex_count}
    result.aipwn_bypass_confirmed = aipwn_bypass_confirmed
    return result


def test_aipwn_bypass_confirmed_flips_resilience_controls_without_dex():
    """Caso central del ROADMAP: bypass confirmado por aipwn SIN dex_count > 0
    (app con anti-root nativo agresivo que mata el proceso antes de FART)
    igual debe marcar bypass_confirmed=True y aplicar la penalización."""
    result = _protected_result(aipwn_bypass_confirmed=True, dex_count=0)
    assert result.protection_broken is False  # exige dex_count > 0

    report = build_masvs_report(result)
    assert report.bypass_confirmed is True
    r1 = next(c for c in report.controls if c.control_id == "MASVS-RESILIENCE-1")
    assert r1.status == "bypass"


def test_protection_broken_alone_still_flips_bypass_confirmed():
    """No regresionar el camino existente: DEX extraído sin aipwn también
    debe seguir marcando bypass_confirmed=True."""
    result = _protected_result(aipwn_bypass_confirmed=False, dex_count=3)
    assert result.protection_broken is True

    report = build_masvs_report(result)
    assert report.bypass_confirmed is True


def test_no_bypass_when_neither_confirmed():
    result = _protected_result(aipwn_bypass_confirmed=False, dex_count=0)
    report = build_masvs_report(result)
    assert report.bypass_confirmed is False
    r1 = next(c for c in report.controls if c.control_id == "MASVS-RESILIENCE-1")
    assert r1.status == "pass"


def test_analysis_result_roundtrips_aipwn_bypass_confirmed_through_dict():
    result = _protected_result(aipwn_bypass_confirmed=True)
    restored = AnalysisResult.from_dict(result.to_dict())
    assert restored.aipwn_bypass_confirmed is True
