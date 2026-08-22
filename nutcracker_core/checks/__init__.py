"""Framework de checks deterministas de nutcracker (Fase 2.2 del plan).

    from nutcracker_core.checks import load_registry, all_checks
    load_registry()
    for check in all_checks():
        print(check.meta.id, check.meta.masvs, check.meta.maswe, check.meta.cwe)

Unifica bajo un registry común los ~50 checks estáticos ya existentes
(adaptador sobre vuln_scanner/native_scanner/detectors — siguen corriendo por
su pipeline original) y los checks dinámicos nuevos (corren sobre ADB, sin
LLM). Base para docs/owasp-mas-coverage.md (Fase 2.3).
"""

from __future__ import annotations

from .base import Check, CheckFinding, CheckMeta
from .registry import (
    all_checks,
    dynamic_checks,
    register_dynamic,
    register_static,
    reset,
    static_checks,
)

def load_registry() -> None:
    """Puebla el registry completo: adaptador estático + checks dinámicos.

    Idempotente respecto al estado real del registry (no un flag aparte): si
    ya hay checks registrados, no vuelve a cargar. registry.reset() (usado en
    tests) vacía el registry y por lo tanto reabre la carga en la siguiente
    llamada.
    """
    if all_checks():
        return
    from .dynamic import cleartext_traffic as _cleartext_traffic
    from .dynamic import debuggable as _debuggable
    from .static import adapter as _static_adapter

    _static_adapter.load_all()
    _debuggable.register()
    _cleartext_traffic.register()


__all__ = [
    "Check", "CheckFinding", "CheckMeta",
    "all_checks", "static_checks", "dynamic_checks",
    "register_static", "register_dynamic", "reset",
    "load_registry",
]
