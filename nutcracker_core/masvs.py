"""Módulo MASVS v2 — mapeo de hallazgos de nutcracker a controles OWASP MASVS.

Genera un MASVSReport con:
  - Estado de cada control (pass / fail / bypass / no_protection / not_tested)
  - Puntuación 0-100 y grado A-F
  - Lista de hallazgos por control

Uso:
    from nutcracker_core.masvs import build_masvs_report
    report = build_masvs_report(analysis_result, scan_result)
    report.to_dict()  # → listo para serializar en el JSON de salida
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .analyzer import AnalysisResult
    from .vuln_scanner import ScanResult
    from .manifest_analyzer import ManifestAnalysisResult


# ── Definición de controles MASVS v2 ─────────────────────────────────────────

MASVS_CONTROLS: dict[str, str] = {
    # STORAGE
    "MASVS-STORAGE-1": "No almacenar datos sensibles sin cifrado en almacenamiento local",
    "MASVS-STORAGE-2": "No almacenar credenciales o secretos en el código o APK",
    # CRYPTO
    "MASVS-CRYPTO-1":  "Sin algoritmos criptográficos débiles ni configuraciones inseguras (MD5, DES, ECB, IV estático)",
    # AUTH
    "MASVS-AUTH-2":    "No exponer tokens de sesión o autenticación en canales inseguros",
    # NETWORK
    "MASVS-NETWORK-1": "Comunicaciones de red cifradas con TLS y certificados válidos",
    "MASVS-NETWORK-2": "Certificate pinning implementado en al menos un cliente HTTP",
    # PLATFORM
    "MASVS-PLATFORM-1": "Mecanismos IPC usados de forma segura (intents, deep links, componentes exportados y permisos mínimos)",
    "MASVS-PLATFORM-2": "WebViews configurados de forma segura (sin JS innecesario, sin acceso a archivos, sin interfaces nativas expuestas)",
    "MASVS-PLATFORM-3": "Interfaz de usuario segura (clipboard, capturas de pantalla, caché de teclado)",
    # CODE
    "MASVS-CODE-2":    "Sin información de debug ni datos sensibles en logs en producción",
    "MASVS-CODE-4":    "Validar y sanitizar toda entrada externa (SQL, comandos, rutas)",
    # RESILIENCE
    "MASVS-RESILIENCE-1": "Detectar y responder ante dispositivos rooteados o comprometidos",
    "MASVS-RESILIENCE-2": "Detectar y responder ante debuggers y entornos de análisis",
    "MASVS-RESILIENCE-3": "Protección ante ingeniería inversa (ofuscación, anti-tamper)",
    "MASVS-RESILIENCE-4": "Detección de manipulación del APK (integridad de firma)",
}

# Peso base de cada categoría en la puntuación final (suma = 100)
_CATEGORY_WEIGHTS: dict[str, int] = {
    "MASVS-STORAGE":    15,
    "MASVS-CRYPTO":     15,
    "MASVS-AUTH":       10,
    "MASVS-NETWORK":    20,
    "MASVS-PLATFORM":   10,
    "MASVS-CODE":       10,
    "MASVS-RESILIENCE": 20,
}


# ── Mapeo reglas vuln_scanner → MASVS ────────────────────────────────────────

RULE_TO_MASVS: dict[str, list[str]] = {
    "HC001":     ["MASVS-STORAGE-2"],
    "HC002":     ["MASVS-STORAGE-2"],
    "HC003":     ["MASVS-STORAGE-2"],
    "HC004":     ["MASVS-STORAGE-2"],
    "HC005":     ["MASVS-STORAGE-2"],
    "HC006":     ["MASVS-CRYPTO-1"],
    "HC007":     ["MASVS-STORAGE-2"],
    "HC008":     ["MASVS-STORAGE-2", "MASVS-NETWORK-1"],
    "ST001":     ["MASVS-STORAGE-1"],
    "ST002":     ["MASVS-STORAGE-1"],
    "ST003":     ["MASVS-STORAGE-1"],
    "ST004":     ["MASVS-STORAGE-1"],
    "ST005":     ["MASVS-PLATFORM-3"],
    "ST006":     ["MASVS-STORAGE-2"],
    "NET001":    ["MASVS-NETWORK-1"],
    "NET002":    ["MASVS-NETWORK-1"],
    "NET003":    ["MASVS-NETWORK-2"],
    "NET004":    ["MASVS-NETWORK-1"],
    "NET005":    ["MASVS-NETWORK-2"],
    "NET006":    ["MASVS-NETWORK-1"],
    "AUTH001":   ["MASVS-AUTH-2"],
    "CRYPTO001": ["MASVS-CRYPTO-1"],
    "CRYPTO002": ["MASVS-CRYPTO-1"],
    "CRYPTO003": ["MASVS-CRYPTO-1"],
    "CRYPTO004": ["MASVS-CRYPTO-1"],
    "CRYPTO005": ["MASVS-CRYPTO-1"],
    "CRYPTO006": ["MASVS-CRYPTO-1"],
    "COMP001":   ["MASVS-PLATFORM-2"],
    "COMP002":   ["MASVS-PLATFORM-2"],
    "COMP003":   ["MASVS-PLATFORM-2"],
    "COMP004":   ["MASVS-PLATFORM-1"],
    "COMP005":   ["MASVS-PLATFORM-2"],
    "INJ001":    ["MASVS-CODE-4"],
    "INJ002":    ["MASVS-CODE-4"],
    "INJ003":    ["MASVS-CODE-4"],
    "INJ004":    ["MASVS-PLATFORM-1"],
    "DBG001":    ["MASVS-CODE-2"],
    "DBG002":    ["MASVS-CODE-2"],
    "DBG003":    ["MASVS-CODE-2"],
    "OBF001":    ["MASVS-RESILIENCE-3"],
    "DESER001":  ["MASVS-CODE-4"],
    "EXTRA001":  ["MASVS-PLATFORM-1"],
}

# ── Mapeo detectores → MASVS ──────────────────────────────────────────────────

DETECTOR_TO_MASVS: dict[str, list[str]] = {
    "Librerías anti-root conocidas":             ["MASVS-RESILIENCE-1"],
    "SafetyNet / Play Integrity API":            ["MASVS-RESILIENCE-1"],
    "Comprobaciones manuales de root":           ["MASVS-RESILIENCE-1"],
    "Anti Magisk / SuperSU / KernelSU / Frida":  ["MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2"],
    "DexGuardDetector":                          ["MASVS-RESILIENCE-3", "MASVS-RESILIENCE-4"],
    "AppDome":                                   ["MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2",
                                                  "MASVS-RESILIENCE-3", "MASVS-RESILIENCE-4"],
    "Verificación de firma del APK":             ["MASVS-RESILIENCE-4"],
    "Certificate pinning":                       ["MASVS-NETWORK-2"],
}

# Detectores que son "solo positivos": si no detectan nada no implica fallo,
# el control queda not_tested (no se flipa a no_protection).
_POSITIVE_ONLY_DETECTORS: frozenset[str] = frozenset({
    "Certificate pinning",
})

# ── Mapeo misconfigs del manifest → MASVS ────────────────────────────────────
# Cada entrada: (prefijo del título de Misconfiguration, [control_ids])
MISCONFIG_TO_MASVS: list[tuple[str, list[str]]] = [
    # ── These titles are the same in both languages ───────────────────────────
    ('android:debuggable="true"',               ["MASVS-CODE-2"]),
    ('android:allowBackup="true"',              ["MASVS-STORAGE-1"]),
    ('android:usesCleartextTraffic="true"',     ["MASVS-NETWORK-1"]),
    ('AWS Access Key',                          ["MASVS-STORAGE-2"]),
    ('Firebase Realtime DB URL',                ["MASVS-STORAGE-2"]),
    ('Firebase API Key',                        ["MASVS-STORAGE-2"]),
    ('Google Maps API Key',                     ["MASVS-STORAGE-2"]),
    # ── Spanish ───────────────────────────────────────────────────────────────
    ('Sin android:networkSecurityConfig',       ["MASVS-NETWORK-1"]),
    ('Sin Network Security Config y cleartext', ["MASVS-NETWORK-1"]),
    ('Conf\u00eda en CAs del usuario',          ["MASVS-NETWORK-2"]),
    ('Cleartext permitido para dominio',        ["MASVS-NETWORK-1"]),
    ('<activity> exportado sin permiso',        ["MASVS-PLATFORM-1"]),
    ('<service> exportado sin permiso',         ["MASVS-PLATFORM-1"]),
    ('<receiver> exportado sin permiso',        ["MASVS-PLATFORM-1"]),
    ('<provider> exportado sin permiso',        ["MASVS-PLATFORM-1"]),
    ('API Key hardcodeada',                     ["MASVS-STORAGE-2"]),
    ('JWT Token hardcodeado',                   ["MASVS-STORAGE-2", "MASVS-AUTH-2"]),
    ('IP privada hardcodeada',                  ["MASVS-NETWORK-1"]),
    ('Posible contrase\u00f1a hardcodeada',     ["MASVS-STORAGE-2"]),
    # ── English ───────────────────────────────────────────────────────────────
    ('No android:networkSecurityConfig',        ["MASVS-NETWORK-1"]),
    ('No Network Security Config and cleartext',["MASVS-NETWORK-1"]),
    ('Trusts user CAs',                         ["MASVS-NETWORK-2"]),
    ('Cleartext allowed for domain',            ["MASVS-NETWORK-1"]),
    ('<activity> exported without permission',  ["MASVS-PLATFORM-1"]),
    ('<service> exported without permission',   ["MASVS-PLATFORM-1"]),
    ('<receiver> exported without permission',  ["MASVS-PLATFORM-1"]),
    ('<provider> exported without permission',  ["MASVS-PLATFORM-1"]),
    ('Hardcoded API Key',                       ["MASVS-STORAGE-2"]),
    ('Hardcoded JWT Token',                     ["MASVS-STORAGE-2", "MASVS-AUTH-2"]),
    ('Hardcoded Private IP',                    ["MASVS-NETWORK-1"]),
    ('Possible hardcoded password',             ["MASVS-STORAGE-2"]),
]

# ── Parámetros de penalización ────────────────────────────────────────────────

_SEVERITY_PENALTY: dict[str, int] = {
    "critical": 8,
    "high":     5,
    "medium":   3,
    "low":      1,
    "info":     0,
}
# Penalización por control individual sin protección detectada (suma = peso categoría RESILIENCE = 20)
_NO_PROTECT_PENALTY: dict[str, int] = {
    "MASVS-RESILIENCE-1": 5,
    "MASVS-RESILIENCE-2": 5,
    "MASVS-RESILIENCE-3": 5,
    "MASVS-RESILIENCE-4": 5,
}

# Penalización por control individual cuando el bypass está confirmado (Frida/FART)
_BYPASS_PENALTY: dict[str, int] = {
    "MASVS-RESILIENCE-1": 4,
    "MASVS-RESILIENCE-2": 4,
    "MASVS-RESILIENCE-3": 4,
    "MASVS-RESILIENCE-4": 3,
}

_MAX_PENALTY_PER_CTRL  = 20   # tope de penalización por control (aplica solo a hallazgos vuln_scanner)


# ── Dataclasses del reporte ───────────────────────────────────────────────────

@dataclass
class MASVSControlResult:
    """Estado de un control MASVS individual."""
    control_id: str
    description: str
    # pass | fail | bypass | no_protection | not_tested
    status: str
    penalty: int
    finding_count: int
    # IDs de reglas del vuln_scanner que apuntan a este control
    finding_rule_ids: list[str] = field(default_factory=list)
    # Nombres de detectores del analyzer que cubren este control
    detector_names: list[str] = field(default_factory=list)
    # Títulos cortos de misconfigs del manifest que afectan este control
    misconfig_titles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "control_id":       self.control_id,
            "description":      self.description,
            "status":           self.status,
            "penalty":          self.penalty,
            "finding_count":    self.finding_count,
            "finding_rule_ids": self.finding_rule_ids,
            "detector_names":   self.detector_names,
            "misconfig_titles": self.misconfig_titles,
        }


@dataclass
class MASVSReport:
    """Reporte completo de cumplimiento MASVS v2."""
    controls: list[MASVSControlResult]
    score: int          # 0-100
    grade: str          # A / B / C / D / F
    bypass_confirmed: bool
    total_findings: int

    @property
    def failed_controls(self) -> list[MASVSControlResult]:
        return [c for c in self.controls if c.status not in ("pass", "not_tested")]

    @property
    def passed_controls(self) -> list[MASVSControlResult]:
        return [c for c in self.controls if c.status == "pass"]

    def to_dict(self) -> dict:
        status_counts: dict[str, int] = {}
        for c in self.controls:
            status_counts[c.status] = status_counts.get(c.status, 0) + 1
        return {
            "score":            self.score,
            "grade":            self.grade,
            "bypass_confirmed": self.bypass_confirmed,
            "total_findings":   self.total_findings,
            "summary": {
                "pass":          status_counts.get("pass", 0),
                "fail":          status_counts.get("fail", 0),
                "bypass":        status_counts.get("bypass", 0),
                "no_protection": status_counts.get("no_protection", 0),
                "not_tested":    status_counts.get("not_tested", 0),
            },
            "controls": [c.to_dict() for c in self.controls],
        }


# ── Constructor del reporte ───────────────────────────────────────────────────

def build_masvs_report(
    analysis: "AnalysisResult",
    scan: "ScanResult | None" = None,
    manifest: "ManifestAnalysisResult | None" = None,
) -> MASVSReport:
    """
    Construye un MASVSReport cruzando AnalysisResult (detectors) + ScanResult (vuln_scanner)
    + ManifestAnalysisResult (misconfigs).

    Algoritmo de puntuación:
      - Arranca en 100 puntos.
      - Cada hallazgo de vuln_scanner descuenta según severidad (máx. _MAX_PENALTY_PER_CTRL
        por control para no hundir un solo control con muchos hallazgos).
      - Control de resilience sin protección detectada: descuento específico por control
        (_NO_PROTECT_PENALTY[cid], por defecto 5 pts).
      - Bypass confirmado (Frida/FART extrajo DEX): descuento específico por control
        (_BYPASS_PENALTY[cid], por defecto 4 pts).
      - Score final = max(0, 100 - suma_de_penalizaciones).

    Grados:
      A (90-100) · B (75-89) · C (50-74) · D (25-49) · F (0-24)
    """

    # 1. Inicializar todos los controles como not_tested
    control_map: dict[str, MASVSControlResult] = {
        cid: MASVSControlResult(
            control_id=cid,
            description=desc,
            status="not_tested",
            penalty=0,
            finding_count=0,
        )
        for cid, desc in MASVS_CONTROLS.items()
    }

    # Controles que pueden ser evaluados por el vuln_scanner (tienen reglas mapeadas)
    _scanner_evaluable: set[str] = {cid for cids in RULE_TO_MASVS.values() for cid in cids}

    # 2. Procesar hallazgos del vuln_scanner
    total_findings = 0
    if scan is not None:
        sev_order = ["critical", "high", "medium", "low", "info"]

        # Agrupar por rule_id para penalizar por grupo, no por hallazgo individual
        findings_by_rule: dict[str, list] = {}
        for f in scan.findings:
            findings_by_rule.setdefault(f.rule_id, []).append(f)

        for rule_id, findings in findings_by_rule.items():
            masvs_ids = RULE_TO_MASVS.get(rule_id, [])
            if not masvs_ids:
                continue

            total_findings += len(findings)

            # Severidad máxima del grupo
            worst_idx = min(
                (sev_order.index(f.severity) for f in findings if f.severity in sev_order),
                default=len(sev_order) - 1,
            )
            penalty_per = _SEVERITY_PENALTY.get(sev_order[worst_idx], 0)

            for cid in masvs_ids:
                ctrl = control_map.get(cid)
                if ctrl is None:
                    continue
                ctrl.status = "fail"
                ctrl.finding_count += len(findings)
                if rule_id not in ctrl.finding_rule_ids:
                    ctrl.finding_rule_ids.append(rule_id)
                ctrl.penalty = min(
                    ctrl.penalty + penalty_per * len(findings),
                    _MAX_PENALTY_PER_CTRL,
                )

        # 2b. Si el scanner corrió y no encontró nada para un control evaluable → pass
        # Excluir controles RESILIENCE y NETWORK-2: requieren confirmación positiva del detector
        _no_autopass = frozenset({"MASVS-NETWORK-2"})
        for cid, ctrl in control_map.items():
            if cid in _scanner_evaluable and ctrl.status == "not_tested":
                if not cid.startswith("MASVS-RESILIENCE") and cid not in _no_autopass:
                    ctrl.status = "pass"

    # 2c. Procesar misconfigurations del manifest
    if manifest is not None:
        for misconfig in manifest.misconfigurations:
            masvs_ids: list[str] = []
            for title_prefix, cids in MISCONFIG_TO_MASVS:
                if misconfig.title.startswith(title_prefix):
                    masvs_ids = cids
                    break
            if not masvs_ids:
                continue
            penalty = _SEVERITY_PENALTY.get(misconfig.severity, 0)
            for cid in masvs_ids:
                ctrl = control_map.get(cid)
                if ctrl is None:
                    continue
                ctrl.status = "fail"
                ctrl.finding_count += 1
                ctrl.penalty = min(ctrl.penalty + penalty, _MAX_PENALTY_PER_CTRL)
                short_title = misconfig.title[:30]
                if short_title not in ctrl.misconfig_titles:
                    ctrl.misconfig_titles.append(short_title)

    # 3. Procesar detecciones del analyzer (resilience)
    for det in analysis.results:
        masvs_ids = DETECTOR_TO_MASVS.get(det.name, [])
        if not masvs_ids:
            continue

        for cid in masvs_ids:
            ctrl = control_map.get(cid)
            if ctrl is None:
                continue

            if det.name not in ctrl.detector_names:
                ctrl.detector_names.append(det.name)

            if det.detected:
                # Protección presente → pass (solo si no hay un fail de vuln_scanner)
                if ctrl.status in ("not_tested", "no_protection"):
                    ctrl.status = "pass"
                    ctrl.penalty = 0
            else:
                # Sin protección para este control de resiliencia
                # Los detectores "solo positivos" no implican fallo si no detectan nada
                if ctrl.status in ("not_tested",) and det.name not in _POSITIVE_ONLY_DETECTORS:
                    ctrl.status = "no_protection"
                    ctrl.penalty = _NO_PROTECT_PENALTY.get(cid, 5)

    # 4. Aplicar bypass si la protección fue rota en runtime
    bypass_confirmed = analysis.protection_broken
    if bypass_confirmed:
        for cid, ctrl in control_map.items():
            if not cid.startswith("MASVS-RESILIENCE"):
                continue
            if ctrl.status in ("pass", "no_protection", "fail"):
                ctrl.status = "bypass"
                ctrl.penalty = _BYPASS_PENALTY.get(cid, 4)

    # 5. Calcular puntuación final
    total_penalty = sum(c.penalty for c in control_map.values())
    score = max(0, 100 - total_penalty)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 25:
        grade = "D"
    else:
        grade = "F"

    return MASVSReport(
        controls=list(control_map.values()),
        score=score,
        grade=grade,
        bypass_confirmed=bypass_confirmed,
        total_findings=total_findings,
    )
