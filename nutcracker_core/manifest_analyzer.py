"""
manifest_analyzer.py — Análisis de misconfigurations en AndroidManifest.xml
y archivos de recursos (network_security_config.xml, strings.xml).

Opera sobre el directorio decompilado producido por jadx.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

from nutcracker_core.i18n import t

# Namespace Android en los XMLs de jadx
_NS = "http://schemas.android.com/apk/res/android"

# Permisos considerados de alto riesgo
_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.RECEIVE_BOOT_COMPLETED",
}

# Patrones para detectar secrets en strings.xml
# Tuple: (rule_id, regex, i18n_key)
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("api_key",         r'(?i)(api[_\-]?key|apikey)\s*=?\s*["\']([A-Za-z0-9_\-]{16,})["\']',  "secret_api_key"),
    ("aws_key",         r'AKIA[0-9A-Z]{16}',                                                     "secret_aws_key"),
    ("firebase_url",    r'https://[a-z0-9\-]+\.firebaseio\.com',                                 "secret_firebase_url"),
    ("firebase_key",    r'AIza[0-9A-Za-z\\-_]{35}',                                             "secret_firebase_key"),
    ("google_maps_key", r'AIza[0-9A-Za-z\\-_]{35}',                                             "secret_google_maps_key"),
    ("jwt_token",       r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',  "secret_jwt_token"),
    ("private_ip",      r'https?://(?:192\.168|10\.\d+|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+',  "secret_private_ip"),
    ("password_field",  r'(?i)<string[^>]+name="[^"]*passw[^"]*"[^>]*>([^\s<]{6,})<',           "secret_password"),
]


@dataclass
class Misconfiguration:
    severity: str        # "critical" | "high" | "medium" | "info"
    category: str        # "manifest" | "network" | "permissions" | "secrets"
    title: str
    description: str
    location: str        # archivo + línea o atributo
    recommendation: str


@dataclass
class ManifestAnalysisResult:
    package: str = ""
    app_label: str = ""
    target_sdk: int = 0
    min_sdk: int = 0
    debuggable: bool = False
    allow_backup: bool = True
    cleartext_traffic: bool = False
    has_network_security_config: bool = False
    exported_components: list[dict] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)
    misconfigurations: list[Misconfiguration] = field(default_factory=list)


def analyze_decompiled_dir(
    decompiled_dir: Path,
    progress_callback=None,
) -> ManifestAnalysisResult:
    """
    Analiza el directorio decompilado por jadx buscando misconfigs en:
      - AndroidManifest.xml
      - res/xml/network_security_config.xml
      - res/values/strings.xml
    """
    result = ManifestAnalysisResult()

    def _cb(msg: str) -> None:
        if progress_callback:
            progress_callback(msg)

    # ── 1. AndroidManifest.xml ────────────────────────────────────────────────
    manifest_path = decompiled_dir / "resources" / "AndroidManifest.xml"
    if not manifest_path.exists():
        # Fallback: jadx a veces lo pone en la raíz
        manifest_path = decompiled_dir / "AndroidManifest.xml"

    if manifest_path.exists():
        _cb(t("analyzing_manifest_progress"))
        _analyze_manifest(manifest_path, result)
    else:
        result.misconfigurations.append(Misconfiguration(
            severity="medium",
            category="manifest",
            title=t("manifest_not_found_title"),
            description=t("manifest_not_found_desc"),
            location=str(decompiled_dir),
            recommendation=t("manifest_not_found_rec"),
        ))

    # ── 2. network_security_config.xml ───────────────────────────────────────
    nsc_candidates = list(decompiled_dir.rglob("network_security_config.xml"))
    if nsc_candidates:
        _cb(t("analyzing_nsc_progress"))
        result.has_network_security_config = True
        _analyze_network_security_config(nsc_candidates[0], result)
    elif result.cleartext_traffic:
        result.misconfigurations.append(Misconfiguration(
            severity="high",
            category="network",
            title=t("no_nsc_cleartext_title"),
            description=t("no_nsc_cleartext_desc"),
            location="AndroidManifest.xml",
            recommendation=t("no_nsc_cleartext_rec"),
        ))

    # ── 3. strings.xml (solo el principal, no i18n) ───────────────────────────
    strings_main = decompiled_dir / "resources" / "res" / "values" / "strings.xml"
    if strings_main.exists():
        _cb(t("scanning_strings_progress"))
        _analyze_strings(strings_main, result)

    return result


# ─────────────────────────────────────────────────────────────────────────────

def _attr(element: ET.Element, name: str) -> str | None:
    """Devuelve el valor del atributo android:name del elemento."""
    return element.get(f"{{{_NS}}}{name}") or element.get(name)


def _resolve_label(raw_label: str, manifest_path: Path) -> str:
    """
    Resuelve el atributo android:label.

    Si es una referencia tipo "@string/app_name", busca el valor en
    res/values/strings.xml relativo al manifest. Si es texto literal,
    lo devuelve tal cual. Devuelve "" si no puede resolverse.
    """
    raw = raw_label.strip()
    if not raw:
        return ""
    if not raw.startswith("@string/"):
        return raw

    key = raw[len("@string/"):]
    # El manifest suele estar en <decompiled>/resources/AndroidManifest.xml
    # y los strings en <decompiled>/resources/res/values/strings.xml
    candidates = [
        manifest_path.parent / "res" / "values" / "strings.xml",
        manifest_path.parent.parent / "resources" / "res" / "values" / "strings.xml",
    ]
    for strings_path in candidates:
        if not strings_path.exists():
            continue
        try:
            tree = ET.parse(strings_path)
        except ET.ParseError:
            continue
        for el in tree.getroot().findall("string"):
            if el.get("name") == key and el.text:
                return el.text.strip()
    return ""


def _analyze_manifest(path: Path, result: ManifestAnalysisResult) -> None:
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        result.misconfigurations.append(Misconfiguration(
            severity="info",
            category="manifest",
            title=t("manifest_parse_error_title"),
            description=t("manifest_parse_error_desc"),
            location=str(path),
            recommendation=t("manifest_parse_error_rec"),
        ))
        return

    root = tree.getroot()
    result.package = root.get("package", "")

    # ── SDK versions ──────────────────────────────────────────────────────────
    sdk_el = root.find("uses-sdk")
    if sdk_el is not None:
        result.min_sdk   = int(_attr(sdk_el, "minSdkVersion") or 0)
        result.target_sdk = int(_attr(sdk_el, "targetSdkVersion") or 0)

    if result.target_sdk and result.target_sdk < 28:
        result.misconfigurations.append(Misconfiguration(
            severity="medium",
            category="manifest",
            title=t("low_target_sdk_title", version=result.target_sdk),
            description=t("low_target_sdk_desc", version=result.target_sdk),
            location="AndroidManifest.xml \u2192 uses-sdk",
            recommendation=t("low_target_sdk_rec"),
        ))

    # ── Permisos peligrosos ───────────────────────────────────────────────────
    for perm_el in root.findall("uses-permission"):
        perm_name = (_attr(perm_el, "name") or "").strip()
        if perm_name in _DANGEROUS_PERMISSIONS:
            result.dangerous_permissions.append(perm_name)

    if result.dangerous_permissions:
        result.misconfigurations.append(Misconfiguration(
            severity="info",
            category="permissions",
            title=t("dangerous_perms_title", count=len(result.dangerous_permissions)),
            description="\n".join(f"  \u2022 {p}" for p in sorted(result.dangerous_permissions)),
            location="AndroidManifest.xml \u2192 uses-permission",
            recommendation=t("dangerous_perms_rec"),
        ))

    # ── Flags de <application> ────────────────────────────────────────────────
    app_el = root.find("application")
    if app_el is None:
        return

    # ── Label de la app (nombre comercial) ────────────────────────────────────
    raw_label = _attr(app_el, "label") or ""
    result.app_label = _resolve_label(raw_label, path) if raw_label else ""

    debuggable = _attr(app_el, "debuggable")
    result.debuggable = debuggable == "true"
    if result.debuggable:
        result.misconfigurations.append(Misconfiguration(
            severity="critical",
            category="manifest",
            title=t("debuggable_title"),
            description=t("debuggable_desc"),
            location="AndroidManifest.xml \u2192 <application>",
            recommendation=t("debuggable_rec"),
        ))

    allow_backup = _attr(app_el, "allowBackup")
    result.allow_backup = allow_backup != "false"
    if result.allow_backup:
        result.misconfigurations.append(Misconfiguration(
            severity="high",
            category="manifest",
            title=t("allow_backup_title"),
            description=t("allow_backup_desc"),
            location="AndroidManifest.xml \u2192 <application>",
            recommendation=t("allow_backup_rec"),
        ))

    cleartext = _attr(app_el, "usesCleartextTraffic")
    result.cleartext_traffic = cleartext == "true"
    if result.cleartext_traffic:
        result.misconfigurations.append(Misconfiguration(
            severity="high",
            category="network",
            title=t("cleartext_title"),
            description=t("cleartext_desc"),
            location="AndroidManifest.xml \u2192 <application>",
            recommendation=t("cleartext_rec"),
        ))

    nsc = _attr(app_el, "networkSecurityConfig")
    if not nsc:
        result.misconfigurations.append(Misconfiguration(
            severity="medium",
            category="network",
            title=t("no_nsc_title"),
            description=t("no_nsc_desc"),
            location="AndroidManifest.xml \u2192 <application>",
            recommendation=t("no_nsc_rec"),
        ))

    # ── Componentes exportados sin permiso ────────────────────────────────────
    _check_exported_components(app_el, result, path)


def _check_exported_components(app_el: ET.Element, result: ManifestAnalysisResult, manifest_path: Path) -> None:
    """Detecta activities, services, receivers y providers exportados sin permiso."""
    component_tags = ["activity", "service", "receiver", "provider"]

    for tag in component_tags:
        for comp in app_el.findall(tag):
            name        = _attr(comp, "name") or "?"
            exported    = _attr(comp, "exported")
            permission  = _attr(comp, "permission")
            has_intent  = comp.find("intent-filter") is not None

            # exported=true explícito sin permiso, o exported implícito (tiene intent-filter, target<31)
            is_exported = exported == "true" or (exported is None and has_intent)
            if is_exported and not permission:
                # Excluir el launcher principal (tiene MAIN + LAUNCHER)
                actions = [
                    _attr(a, "name") or ""
                    for a in comp.findall("intent-filter/action")
                ]
                if "android.intent.action.MAIN" in actions:
                    continue

                severity = "high" if tag in ("provider", "service") else "medium"
                result.exported_components.append({"tag": tag, "name": name})
                result.misconfigurations.append(Misconfiguration(
                    severity=severity,
                    category="manifest",
                    title=t("exported_component_title", tag=tag, name=name.split(".")[-1]),
                    description=t("exported_component_desc", fullname=name),
                    location=f'AndroidManifest.xml \u2192 <{tag} android:name="{name}">',
                    recommendation=t("exported_component_rec"),
                ))


def _analyze_network_security_config(path: Path, result: ManifestAnalysisResult) -> None:
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return

    root = tree.getroot()

    # Verificar si permite CAs del usuario (peligroso en producción)
    for trust_anchors in root.findall(".//trust-anchors"):
        for cert in trust_anchors.findall("certificates"):
            src = cert.get("src", "")
            if src == "user":
                result.misconfigurations.append(Misconfiguration(
                    severity="high",
                    category="network",
                    title=t("user_ca_title"),
                    description=t("user_ca_desc"),
                    location=str(path),
                    recommendation=t("user_ca_rec"),
                ))

    # Verificar cleartext por dominio
    for domain_config in root.findall(".//domain-config"):
        cleartext = domain_config.get("cleartextTrafficPermitted", "").lower()
        if cleartext == "true":
            domains = [d.text for d in domain_config.findall("domain") if d.text]
            result.misconfigurations.append(Misconfiguration(
                severity="medium",
                category="network",
                title=t("cleartext_domain_title", domains=", ".join(domains)),
                description=t("cleartext_domain_desc", domains=", ".join(domains)),
                location=str(path),
                recommendation=t("cleartext_domain_rec"),
            ))

    # Detectar si hay certificate pinning configurado
    pins = root.findall(".//pin-set")
    if not pins:
        result.misconfigurations.append(Misconfiguration(
            severity="medium",
            category="network",
            title=t("no_cert_pinning_title"),
            description=t("no_cert_pinning_desc"),
            location=str(path),
            recommendation=t("no_cert_pinning_rec"),
        ))


def _analyze_strings(path: Path, result: ManifestAnalysisResult) -> None:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = content.splitlines()

    for rule_id, pattern, title_key in _SECRET_PATTERNS:
        seen = False
        for line in lines:
            if seen:
                break
            m = re.search(pattern, line)
            if m:
                seen = True
                # Línea completa (limpia) como evidencia
                evidence = line.strip()[:120]
                result.misconfigurations.append(Misconfiguration(
                    severity="high",
                    category="secrets",
                    title=t(title_key),
                    description=evidence,
                    location="res/values/strings.xml",
                    recommendation=t("secret_rec"),
                ))
