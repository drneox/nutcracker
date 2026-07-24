"""Adaptador: expone las reglas ya existentes de vuln_scanner/native_scanner/
detectors como Check unificados con metadata OWASP MAS (Fase 2.2 del plan).

No ejecuta nada nuevo — el análisis real sigue corriendo por
scan_directory()/scan_native_libs()/detector.detect() (orquestado en
orchestrator._do_vuln_scan / _run_builtin_detectors), exactamente como antes.
Migrar cada una de las ~50 reglas existentes a un archivo .py individual
tendría bajo valor marginal (ya son deterministas y ya están probadas) frente
al riesgo de reescribirlas; este adaptador da el registry unificado y la
metadata MASVS/MASWE/CWE (desde nutcracker_core.masvs) sin ese riesgo, y sirve
de base para docs/owasp-mas-coverage.md.
"""

from __future__ import annotations

from ..base import Check, CheckMeta


class _AdaptedCheck(Check):
    """Envuelve una regla/detector ya definido en su módulo de origen.

    No implementa run(): ver docstring de Check.run() y del módulo.
    """

    def __init__(self, meta: CheckMeta) -> None:
        self.meta = meta


def _rule_meta(rule_id: str, title: str, severity: str, source: str) -> CheckMeta:
    from ... import masvs

    return CheckMeta(
        id=rule_id,
        title=title,
        kind="static",
        severity=severity,
        masvs=masvs.RULE_TO_MASVS.get(rule_id, []),
        maswe=masvs.RULE_TO_MASWE.get(rule_id, []),
        cwe=masvs.RULE_TO_CWE.get(rule_id, []),
        source=source,
    )


def _detector_meta(name: str, severity: str) -> CheckMeta:
    """Los detectores de protecciones (analyzer.ALL_DETECTORS) usan un mapeo
    separado (DETECTOR_TO_MASVS), no RULE_TO_MASVS: son indicadores
    *positivos* de protección presente, no reglas de vulnerabilidad — por eso
    no tienen MASWE/CWE asociado (MASWE cataloga debilidades/ausencias, no
    evidencia de controles implementados)."""
    from ... import masvs

    return CheckMeta(
        id=name,
        title=name,
        kind="static",
        severity=severity,
        masvs=masvs.DETECTOR_TO_MASVS.get(name, []),
        source="detector",
    )


def _load_vuln_scanner_checks() -> None:
    from ...vuln_scanner import EXPORTED_COMPONENT_RULES, RULES
    from ..registry import register_static

    for rule in RULES:
        register_static(_AdaptedCheck(_rule_meta(rule.rule_id, rule.title, rule.severity, "vuln_scanner")))

    # Reglas sintetizadas desde el manifest (fuera de la lista RULES): ver
    # vuln_scanner.scan_manifest_components(). COMP004 se excluye porque ese
    # rule_id ya está cubierto arriba vía RULES (colisión preexistente: dos
    # hallazgos distintos — receiver registrado en código vs. exportado en el
    # manifest — comparten el mismo id "COMP004"; no se toca aquí para no
    # romper JSON/reportes históricos que ya usan ese id).
    for tag, (rule_id, title, severity, _category) in EXPORTED_COMPONENT_RULES.items():
        if rule_id == "COMP004":
            continue
        register_static(_AdaptedCheck(_rule_meta(rule_id, title, severity, "vuln_scanner")))

    # INFO001 (android:debuggable="true"): también sintetizado desde el
    # manifest en scan_manifest_components, sin un VulnRule estructurado del
    # que leer título/severidad — se declaran aquí explícitos.
    register_static(_AdaptedCheck(_rule_meta(
        "INFO001", "android:debuggable=\"true\" en el manifest", "high", "vuln_scanner",
    )))


def _load_native_scanner_checks() -> None:
    from ... import native_scanner
    from ..registry import register_static

    for rule in native_scanner._NATIVE_RULES:
        register_static(_AdaptedCheck(_rule_meta(rule.rule_id, rule.title, rule.severity, "native_scanner")))


def _load_detector_checks() -> None:
    from ...analyzer import ALL_DETECTORS
    from ..registry import register_static

    for det in ALL_DETECTORS:
        register_static(_AdaptedCheck(_detector_meta(det.name, det.strength)))


def load_all() -> None:
    """Puebla el registry con los ~50 checks estáticos existentes.

    No es idempotente por sí sola (llamarla dos veces duplica entradas); la
    idempotencia real vive en checks.load_registry(), que solo la invoca si
    el registry está vacío. Ver también registry.reset() para tests.
    """
    _load_vuln_scanner_checks()
    _load_native_scanner_checks()
    _load_detector_checks()
