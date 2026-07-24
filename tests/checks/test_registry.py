"""Tests del framework de checks (Fase 2.2 del plan): registry + adaptador
estático + metadata OWASP MAS."""

from __future__ import annotations

import pytest

from nutcracker_core import checks
from nutcracker_core.checks import registry


@pytest.fixture(autouse=True)
def _clean_registry():
    """Cada test arranca con el registry vacío para no depender de orden de
    ejecución ni de si otro test ya llamó load_registry()."""
    registry.reset()
    yield
    registry.reset()


def test_load_registry_is_idempotent():
    checks.load_registry()
    n1 = len(checks.all_checks())
    checks.load_registry()
    n2 = len(checks.all_checks())
    assert n1 == n2 > 0


def test_static_adapter_wraps_all_existing_rules():
    from nutcracker_core.vuln_scanner import RULES, EXPORTED_COMPONENT_RULES
    from nutcracker_core.native_scanner import _NATIVE_RULES
    from nutcracker_core.analyzer import ALL_DETECTORS

    checks.load_registry()
    static_ids = {c.meta.id for c in checks.static_checks()}

    # COMP004 colisiona a propósito entre RULES y EXPORTED_COMPONENT_RULES
    # (dos hallazgos distintos comparten id preexistente) — el adaptador solo
    # lo registra una vez, vía RULES.
    manifest_synth_ids = {rid for rid, *_ in EXPORTED_COMPONENT_RULES.values()} | {"INFO001"}
    expected = (
        {r.rule_id for r in RULES}
        | {r.rule_id for r in _NATIVE_RULES}
        | {d.name for d in ALL_DETECTORS}
        | manifest_synth_ids
    )
    assert static_ids == expected


def test_no_duplicate_check_ids():
    checks.load_registry()
    ids = [c.meta.id for c in checks.all_checks()]
    assert len(ids) == len(set(ids)), "hay IDs de check duplicados en el registry"


def test_static_checks_have_static_kind_and_dynamic_have_dynamic_kind():
    checks.load_registry()
    assert all(c.meta.kind == "static" for c in checks.static_checks())
    assert all(c.meta.kind == "dynamic" for c in checks.dynamic_checks())


def test_dynamic_checks_are_registered():
    checks.load_registry()
    dynamic_ids = {c.meta.id for c in checks.dynamic_checks()}
    assert "DYN-DEBUGGABLE" in dynamic_ids
    assert "DYN-CLEARTEXT-TRAFFIC" in dynamic_ids


def test_known_rule_carries_correct_masvs_maswe_cwe_metadata():
    """INFO001 es el caso que motivó el fix de Fase 2 (estaba mal mapeado a
    CODE-2; el control real es RESILIENCE-4 según MASWE-0067)."""
    checks.load_registry()
    info001 = next(c for c in checks.static_checks() if c.meta.id == "INFO001")
    assert info001.meta.masvs == ["MASVS-RESILIENCE-4"]
    assert info001.meta.maswe == ["MASWE-0067"]
    assert info001.meta.cwe == ["CWE-489"]


def test_static_check_run_raises_not_implemented():
    """Los checks estáticos adaptados no ejecutan vía Check.run() — corren por
    su pipeline original (scan_directory/etc); esto debe fallar explícito, no
    en silencio, si alguien intenta invocarlo directamente."""
    checks.load_registry()
    any_static = checks.static_checks()[0]
    with pytest.raises(NotImplementedError):
        any_static.run(None)


def test_detector_checks_carry_masvs_from_detector_to_masvs_not_rule_to_masvs():
    """Regresión: los detectores usan DETECTOR_TO_MASVS (mapeo separado de
    RULE_TO_MASVS por nombre, no por rule_id); un bug previo dejaba esta
    metadata vacía para los 8 detectores de resiliencia."""
    from nutcracker_core.masvs import DETECTOR_TO_MASVS

    checks.load_registry()
    detector_checks = [c for c in checks.static_checks() if c.meta.source == "detector"]
    assert len(detector_checks) == len(DETECTOR_TO_MASVS)
    for c in detector_checks:
        assert c.meta.masvs == DETECTOR_TO_MASVS[c.meta.id]
        assert c.meta.masvs, f"{c.meta.id}: detector sin MASVS asociado"


def test_masvs_maswe_cwe_ids_referenced_actually_exist_in_catalogs():
    """Sanity check anti-typo: todo MASVS/MASWE id usado en la metadata de un
    check debe existir en los catálogos oficiales (masvs.py)."""
    from nutcracker_core.masvs import MASVS_CONTROLS, MASWE_CATALOG

    checks.load_registry()
    for check in checks.all_checks():
        for cid in check.meta.masvs:
            assert cid in MASVS_CONTROLS, f"{check.meta.id}: {cid} no existe en MASVS_CONTROLS"
        for mid in check.meta.maswe:
            assert mid in MASWE_CATALOG, f"{check.meta.id}: {mid} no existe en MASWE_CATALOG"
