"""Framework de checks deterministas de nutcracker (Fase 2.2 del plan).

Unifica el patrón de extensión hoy fragmentado en tres registros manuales
(``RULES`` en vuln_scanner.py, ``_NATIVE_RULES`` en native_scanner.py,
``ALL_DETECTORS`` en analyzer.py) bajo una interfaz común con metadata OWASP
MAS completa (MASVS + MASWE + CWE). No reemplaza esos registros — el
adaptador en checks/static/adapter.py los envuelve para no duplicar ~50
reglas ya maduras y probadas; los checks *dinámicos* nuevos (sin LLM, corren
sobre ADB) sí se implementan aquí directamente como Check completos.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

CheckKind = Literal["static", "dynamic"]


@dataclass
class CheckMeta:
    """Metadata OWASP MAS de un check: a qué controles/debilidades apunta."""

    id: str
    title: str
    kind: CheckKind
    severity: str = "medium"
    masvs: list[str] = field(default_factory=list)
    maswe: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    # De dónde viene: "vuln_scanner" | "native_scanner" | "detector" | "dynamic"
    source: str = ""


@dataclass
class CheckFinding:
    """Resultado de un check individual — forma homogénea entre static/dynamic."""

    check_id: str
    title: str
    detected: bool
    severity: str = "medium"
    detail: str = ""
    file: str = ""
    line: int = 0
    masvs: list[str] = field(default_factory=list)
    maswe: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)


class Check:
    """Un check determinista individual.

    Los checks *adaptados* (envoltura de vuln_scanner/native_scanner/
    detectors, kind="static") no implementan ``run()``: siguen ejecutándose
    por su camino original (scan_directory(), etc.); el adaptador solo aporta
    metadata unificada para el registry y docs/owasp-mas-coverage.md.

    Los checks *dinámicos* nuevos (kind="dynamic") sí implementan ``run(ctx)``
    de verdad — ver checks/dynamic/.
    """

    meta: CheckMeta

    def run(self, ctx: Any) -> list[CheckFinding]:
        raise NotImplementedError(
            f"{self.meta.id}: este check no ejecuta vía Check.run() — ver "
            "checks/static/adapter.py (corre por su pipeline original) o "
            "implementa run() si es un check dinámico nuevo."
        )
