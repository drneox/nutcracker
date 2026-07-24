"""Dataclasses del pipeline de escaneo de vulnerabilidades (Fase 0.3 del plan).

Extraído de vuln_scanner.py: modelo de dominio compartido por vuln_scanner.py
(regex+semgrep), leak_scanner.py (apkleaks+gitleaks), store/, reporter.py y
pdf_reporter.py — una sola fuente de la verdad para VulnFinding/VulnRule/ScanResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .i18n import t as _t


@dataclass
class VulnFinding:
    """Una vulnerabilidad encontrada en el código fuente."""
    rule_id: str
    title: str
    severity: str          # critical / high / medium / low / info
    category: str          # OWASP M-number o categoría propia
    file: Path
    line: int
    matched_text: str
    description: str
    recommendation: str

    def relative_path(self, base: Path) -> str:
        if self.file is None:
            return "AndroidManifest.xml"
        try:
            return str(self.file.relative_to(base))
        except ValueError:
            return str(self.file)


@dataclass
class VulnRule:
    """Regla de detección basada en regex."""
    rule_id: str
    title: str
    severity: str
    category: str
    pattern: re.Pattern
    description: str
    recommendation: str
    # Si se especifica, solo aplica a archivos cuyo path contenga este substring
    file_filter: str | None = None
    # Líneas a ignorar si contienen alguno de estos strings (reduce falsos positivos)
    ignore_if_contains: list[str] = field(default_factory=list)
    # Si el valor entre comillas capturado por el patrón coincide con este regex, ignorar
    # (útil para filtrar valores que son identificadores, no secretos reales)
    ignore_value_regex: re.Pattern | None = None

    def i18n_title(self) -> str:
        key = f"rule_{self.rule_id.lower()}_title"
        val = _t(key)
        return val if val != key else self.title

    def i18n_desc(self) -> str:
        key = f"rule_{self.rule_id.lower()}_desc"
        val = _t(key)
        return val if val != key else self.description

    def i18n_rec(self) -> str:
        key = f"rule_{self.rule_id.lower()}_rec"
        val = _t(key)
        return val if val != key else self.recommendation


@dataclass
class ScanResult:
    base_dir: Path
    findings: list[VulnFinding]
    files_scanned: int
    scanner_engine: str = "regex"  # "semgrep" | "regex" — motor de vulns
    leak_engine: str = ""          # "apkleaks+gitleaks+native" — motor de leaks

    @property
    def by_severity(self) -> dict[str, list[VulnFinding]]:
        order = ["critical", "high", "medium", "low", "info"]
        result: dict[str, list[VulnFinding]] = {s: [] for s in order}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")
