"""
i18n.py — Internationalization for nutcracker.

Supported languages: en (English) | es (Spanish)
Default language:    en

Usage:
    from nutcracker_core.i18n import init, t

    init("en")          # call once at startup from CLI config
    label = t("page")   # → "Page"
    msg   = t("low_target_sdk_title", version=27)  # → "Low targetSdkVersion (27)"
"""

from __future__ import annotations

__all__ = ["init", "t", "SUPPORTED_LANGUAGES"]

SUPPORTED_LANGUAGES: frozenset[str] = frozenset({"en", "es"})

_lang: str = "en"


def init(language: str) -> None:
    """Set the active language. Falls back to 'en' for unsupported values."""
    global _lang
    lang = str(language).strip().lower()
    if lang not in SUPPORTED_LANGUAGES:
        _lang = "en"
    else:
        _lang = lang


def t(key: str, **kwargs) -> str:
    """
    Look up *key* in the active language dict, format with **kwargs**, and
    return the result.  Falls back to English when the key is absent in the
    active language.
    """
    value = STRINGS.get(_lang, {}).get(key) or STRINGS["en"].get(key, key)
    if kwargs:
        try:
            value = value.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return value


# ── Translation tables ────────────────────────────────────────────────────────

STRINGS: dict[str, dict[str, str]] = {
    # ══════════════════════════════════════════════════════════════════════════
    "en": {
        # ── Core metadata labels ───────────────────────────────────────────────
        "package": "Package",
        "version": "Version",
        "min_sdk_target": "Min SDK / Target",
        "analyzed_at": "Analyzed",
        "duration": "Duration",
        "decompiled": "Decompiled",
        "sources": "Sources",
        "vuln_scan_label": "Vuln scan",
        "leak_scan_label": "Leak scan",

        # ── Verdict strings (reporter + pdf) ───────────────────────────────────
        "verdict_protected": "PROTECTED",
        "verdict_no_protection": "NO PROTECTION",
        "verdict_protection_broken": "PROTECTION BROKEN",
        "verdict_protected_subtitle": "Active protections detected.",
        "verdict_no_protection_subtitle": "No anti-root / RASP protection mechanisms detected.",
        "verdict_broken_subtitle": "Protections detected but bypassed via Frida/FART.",

        # ── Reporter column headers ────────────────────────────────────────────
        "detector": "Detector",
        "detected": "Detected",
        "strength": "Strength",
        "evidence": "Evidence found",
        "yes": "YES",
        "no": "NO",
        "and_more": "\u2026and more",

        # ── Reporter verdict text fragments ────────────────────────────────────
        "verdict_protection_broken_banner": "\u26a0  PROTECTION BROKEN \u2014 successful bypass",
        "method_label": "Method",
        "dex_extracted": "DEX extracted",
        "high_strength_detections": "high-strength detections",
        "verdict_protected_banner": "\u2714  PROTECTED against root",
        "confidence_label": "Confidence",
        "verdict_no_protection_banner": "\u2718  NO anti-root PROTECTION detected",
        "no_mechanisms_found": "No known anti-root mechanisms found.",
        "detector_results_title": "Detector results",

        # ── MASVS summary (terminal) ───────────────────────────────────────────
        "masvs_title": "MASVS v2",
        "score_label": "Score",
        "grade_label": "Grade",
        "coverage_label": "Coverage",
        "controls": "controls",
        "bypass_confirmed": "BYPASS CONFIRMED",
        "status_pass": "pass",
        "status_fail": "FAIL",
        "status_bypass": "BYPASS",
        "status_not_tested": "not tested",
        "status_no_protection": "FAIL",
        "masvs_controls_title": "MASVS v2 Controls",
        "control": "Control",
        "status": "Status",
        "description": "Description",

        # ── Reporter save messages ─────────────────────────────────────────────
        "json_report_saved": "JSON report saved at:",
        "analysis_saved": "  Analysis saved:",

        # ── PDF footer / header ────────────────────────────────────────────────
        "generated_on": "Generated on",
        "page": "Page",
        "security_report_header": "nutcracker  \u00b7  Security Report",
        "batch_report_header": "nutcracker  \u00b7  Batch Report",

        # ── PDF cover page ─────────────────────────────────────────────────────
        "android_security_report": "Android Security Analysis Report",
        "no_protection_verdict": "NO PROTECTION",
        "no_protection_verdict_sub": "No active protection mechanisms detected.",
        "protection_broken_verdict": "PROTECTION BROKEN",
        "protection_broken_verdict_sub": "Protections detected but bypassed via Frida/FART.",
        "protected_verdict": "PROTECTED",
        "protected_verdict_sub": "Active protections detected.",
        "sdk_min_target_label": "SDK min / target:",
        "version_label": "Version:",
        "analyzed_label": "Analyzed:",
        "duration_label": "Duration:",
        "decompiled_label": "Decompiled:",
        "sources_label": "Sources:",
        "vuln_scan_engine_label": "Vuln scan:",
        "leak_scan_engine_label": "Leak scan:",
        "protections_card": "Protections",
        "misconfigs_card": "Misconfigs",
        "leaks_card": "Leaks",
        "vulns_card": "Vulns",

        # ── PDF protections section ────────────────────────────────────────────
        "protections_section_title": "Discovered Protections",
        "detected_badge": "DETECTED",
        "not_detected_badge": "NOT DETECTED",
        "bypassed_badge": "BYPASSED",
        "no_evidence": "  No evidence recorded.",
        "no_protection_badge": "  No protection detected.",
        "no_protections_detected": "No active protection mechanisms detected.",
        "protection_bypassed_status": "{count} of {total} protections detected. Protections were bypassed via Frida/FART.",
        "protections_detected_status": "{count} of {total} protections detected.",

        # ── PDF misconfig section ──────────────────────────────────────────────
        "misconfigs_section_title": "Manifest Misconfigurations  ({count} findings)",
        "no_misconfigs": "No misconfigurations detected in manifest.",
        "findings_label": "findings",
        "debuggable_info_label": "Debuggable",
        "allow_backup_info_label": "allowBackup",
        "cleartext_traffic_info_label": "Cleartext Traffic",
        "network_security_config_info_label": "Network Security Config",
        "yes_label": "YES",
        "no_label": "NO",

        # ── PDF findings sections ──────────────────────────────────────────────
        "leaks_section_title": "Leaks",
        "no_leaks": "No leaks found.",
        "vulns_section_title": "Vulnerabilities",
        "no_vulns": "No vulnerabilities found.",

        # ── PDF OSINT section ──────────────────────────────────────────────────
        "osint_subdomains_count": "{count} subdomains",
        "osint_public_leaks_count": "{count} public leaks",
        "osint_no_findings": "no findings",
        "osint_own_domains": "Own domains ({count})",
        "osint_subdomains_title": "Subdomains via crt.sh ({count})",
        "osint_dev_environments": "Dev/QA/staging environments exposed: {count}",
        "osint_and_more": "... and {count} more",
        "osint_public_leaks_title": "Public leaks ({count})",
        "osint_platform": "Platform",
        "osint_title_col": "Title",
        "osint_link": "Link",
        "osint_auth_flows": "Hardcoded auth ({count})",

        # ── PDF MASVS section ──────────────────────────────────────────────────
        "masvs_section_title": "MASVS v2 Compliance  ({covered}/{total} controls evaluated)",
        "grade_label_pdf": "Grade",
        "masvs_ctrl_col": "Control",
        "masvs_status_col": "Status",
        "masvs_desc_col": "Description",
        "masvs_findings_col": "Findings",
        "masvs_penalty_col": "Penalty",
        "masvs_status_no_eval": "NO EVAL.",

        # ── PDF batch report ───────────────────────────────────────────────────
        "batch_security_evaluation": "Security Assessment",
        "batch_application_portfolio": "Application Portfolio",
        "batch_apps_evaluated": "Apps evaluated",
        "batch_successful": "Successful",
        "batch_errors": "Errors",
        "batch_unprotected": "Unprotected",
        "batch_protection_broken": "Protection broken",
        "batch_total_findings": "Total findings",
        "batch_critical_high": "Critical + High",
        "batch_executive_summary": "Executive Summary",
        "batch_app_column": "Application",
        "batch_status_column": "Status",
        "batch_leaks_column": "Leaks",
        "batch_total_column": "Total",
        "batch_status_protected": "Protected",
        "batch_status_unprotected": "Exposed",
        "batch_status_bypass_ok": "Bypass OK",
        "batch_apps_with_error": "Apps with error ({count})",
        "batch_common_findings": "Common Findings",
        "batch_common_findings_desc": "Vulnerabilities appearing in multiple applications",
        "batch_rule_col": "Rule",
        "batch_finding_col": "Finding",
        "batch_severity_col": "Severity",
        "batch_apps_affected_col": "Apps affected",
        "batch_detail_section": "Detail by Application",
        "batch_no_findings": "No findings",
        "batch_critical_count": "{count} critical",
        "batch_high_count": "{count} high",
        "batch_medium_count": "{count} medium",
        "batch_low_count": "{count} low",
        "batch_leaks_count": "{count} leaks",
        "batch_comparative_title": "Comparative Table \u2014 Protection Status",
        "batch_unprotected_label": "Unprotected",
        "batch_protection_broken_label": "Protection broken",
        "batch_with_protection": "With protection",
        "batch_status_col_short": "Protection",
        "batch_bypass_achieved": "Bypass achieved",
        "batch_status_short_unprotected": "Unprotected",
        "batch_status_short_broken": "Bypass achieved",
        "batch_status_short_protected": "Protected",

        # ── manifest_analyzer: Misconfiguration titles ─────────────────────────
        "manifest_not_found_title": "AndroidManifest.xml not found",
        "manifest_not_found_desc": "Could not locate the decompiled manifest.",
        "manifest_not_found_rec": "Make sure to decompile with jadx -d <output> <apk>.",
        "manifest_parse_error_title": "Error parsing AndroidManifest.xml",
        "manifest_parse_error_desc": "The XML could not be parsed correctly.",
        "manifest_parse_error_rec": "Verify that jadx decompiled the APK correctly.",
        "low_target_sdk_title": "Low targetSdkVersion ({version})",
        "low_target_sdk_desc": "targetSdkVersion={version} does not take advantage of Scoped Storage protections, background restrictions, etc. available from API 28+.",
        "low_target_sdk_rec": "Update targetSdkVersion to \u2265 34 (Android 14).",
        "dangerous_perms_title": "{count} high-risk permission(s)",
        "dangerous_perms_rec": "Audit whether each permission is strictly necessary. ACCESS_BACKGROUND_LOCATION, REQUEST_INSTALL_PACKAGES and READ_SMS require special justification on Google Play.",
        "debuggable_title": 'android:debuggable="true"',
        "debuggable_desc": "The app is marked as debuggable. Allows adb shell run-as, attaching a debugger, reading the app sandbox and dumping memory.",
        "debuggable_rec": "Remove android:debuggable or set it to false in production builds.",
        "allow_backup_title": 'android:allowBackup="true" (or not set)',
        "allow_backup_desc": "Allows ADB backup of the app sandbox without root: adb backup -f app.ab com.package \u2192 exposes databases, tokens, etc.",
        "allow_backup_rec": 'Set android:allowBackup="false" or define explicit backup rules.',
        "cleartext_title": 'android:usesCleartextTraffic="true"',
        "cleartext_desc": "The app allows unencrypted HTTP connections. Credentials and sensitive data may travel in plaintext.",
        "cleartext_rec": "Remove usesCleartextTraffic=true and force HTTPS on all endpoints. Use Network Security Config for legacy domains if necessary.",
        "no_nsc_title": "No android:networkSecurityConfig",
        "no_nsc_desc": "No explicit network security policy defined. Since Android 9+ the system applies defaults, but there is no certificate pinning or custom restrictions.",
        "no_nsc_rec": 'Define android:networkSecurityConfig="@xml/network_security_config" with certificate pinning for production domains.',
        "exported_component_title": "<{tag}> exported without permission: {name}",
        "exported_component_desc": "Component {fullname} is accessible from other apps without requiring any permission.",
        "exported_component_rec": 'Add android:exported="false" if not needed externally, or protect it with android:permission="...signature...".',
        "no_nsc_cleartext_title": "No Network Security Config and cleartext active",
        "no_nsc_cleartext_desc": 'The app allows cleartext traffic (usesCleartextTraffic=true) and does not define a network_security_config.xml to restrict it.',
        "no_nsc_cleartext_rec": 'Define res/xml/network_security_config.xml with <base-config cleartextTrafficPermitted="false"> and add android:networkSecurityConfig to <application>.',
        "user_ca_title": "Trusts user CAs (MITM possible)",
        "user_ca_desc": "The Network Security Config trusts certificates installed by the user. An attacker can install their own CA and perform MITM.",
        "user_ca_rec": 'Remove <certificates src="user"/> from the production block. Only use for debug builds with <debug-overrides>.',
        "cleartext_domain_title": "Cleartext allowed for domain(s): {domains}",
        "cleartext_domain_desc": "The network config allows unencrypted HTTP traffic to: {domains}.",
        "cleartext_domain_rec": "Migrate to HTTPS and remove cleartextTrafficPermitted=true.",
        "no_cert_pinning_title": "No certificate pinning in Network Security Config",
        "no_cert_pinning_desc": "network_security_config.xml was found but does not define <pin-set>. Without pinning, any trusted system CA can issue valid certs.",
        "no_cert_pinning_rec": 'Add <pin-set expiration="..."><pin digest="SHA-256">...</pin></pin-set> for production domains.',
        "secret_rec": "Move sensitive values outside the APK. Use Android Keystore, environment variables or a secrets manager.",

        # ── manifest_analyzer: secret pattern titles ───────────────────────────
        "secret_api_key": "Hardcoded API Key",
        "secret_aws_key": "AWS Access Key",
        "secret_firebase_url": "Firebase Realtime DB URL",
        "secret_firebase_key": "Firebase API Key",
        "secret_google_maps_key": "Google Maps API Key",
        "secret_jwt_token": "Hardcoded JWT Token",
        "secret_private_ip": "Hardcoded Private IP",
        "secret_password": "Possible hardcoded password",

        # ── manifest_analyzer: progress messages ───────────────────────────────
        "analyzing_manifest_progress": "Analyzing AndroidManifest.xml...",
        "analyzing_nsc_progress": "Analyzing network_security_config.xml...",
        "scanning_strings_progress": "Scanning strings.xml for secrets...",

        # ── nutcracker.py: terminal verdict / banner ───────────────────────────
        "cli_protected_banner": "PROTECTED",
        "cli_no_protection_banner": "NO PROTECTION",
        "cli_protection_broken_banner": "PROTECTION BROKEN",
        "cli_protection_broken_frida": "Frida/frida-dexdump dumped {dex_count} DEX from the process.\n  The anti-root protections could not prevent bytecode extraction.",
        "cli_no_protection_detail": "No anti-root / RASP protection mechanisms detected.",
        "cli_protected_detail": "Active protections detected. No vulnerabilities found.",
        "cli_protected_vulns_detail": "Active protections detected. Found {count} vulnerability(ies) in static analysis.",
        "cli_bypassed_detail": "Protections detected but bypassed at runtime ({method}, {dex_count} DEX extracted).",
        "cli_app_has_protection": "has",
        "cli_app_no_protection": "does not have",
        "cli_anti_root_label": "anti-root / RASP protection",

        # ── manifest scan terminal ─────────────────────────────────────────────
        "cli_manifest_misconfigs_header": "Manifest misconfigurations:",
        "cli_manifest_sev_col": "Sev.",
        "cli_manifest_finding_col": "Finding",
        "cli_manifest_evidence_col": "Evidence",
        "cli_manifest_location_col": "Location",
        "cli_manifest_recs_header": "Recommendations:",
        "cli_no_manifest_misconfigs": "No misconfigurations detected in manifest.",

        # ── OSINT terminal ─────────────────────────────────────────────────────
        "cli_osint_secrets_header": "OSINT \u2014 BuildConfig secrets: {count} found",
        "cli_osint_field_col": "Field",
        "cli_osint_value_col": "Value",
        "cli_osint_service_col": "Service",
        "cli_osint_file_col": "File",
        "cli_osint_domains_header": "OSINT \u2014 Own domains:",
        "cli_osint_subdomains_header": "OSINT \u2014 Subdomains (crt.sh): {count} found",
        "cli_osint_dev_exposed": "{count} dev/qa/staging environments exposed:",
        "cli_osint_public_leaks_header": "OSINT \u2014 Public leaks: {count} found",
        "cli_osint_auth_header": "OSINT \u2014 Hardcoded auth: {count} detected",
        "cli_osint_saved": "OSINT saved at:",

        # ── Vuln scan terminal ─────────────────────────────────────────────────
        "cli_vuln_scan_enabled": "enabled",
        "cli_vuln_scan_disabled": "disabled",
        "cli_leak_engines_disabled": "disabled",
        "cli_vuln_scan_header": "  Vulnerability scan (code): ",
        "cli_vuln_engine_header": "  Vulnerability scan engine: ",
        "cli_leak_scan_header": "  Leak scan: ",
        "cli_leak_engines_header": "  Leak engines: ",
        "cli_scanner_used_dim": "Scanner used: {engine} \u2014 {files} files, {findings} findings",

        # ── PDF generation terminal ────────────────────────────────────────────
        "cli_generating_pdf": "Generating PDF report...",
        "cli_pdf_saved": "PDF report saved at:",
        "cli_loading_prev_findings": "Loading {count} previous vulnerability findings...",
        "cli_vuln_json_saved": "Vulnerability report saved at:",

        # ── Misc terminal ──────────────────────────────────────────────────────
        "cli_skipping_decompilation": "  features.decompilation=false \u2014 skipping decompilation.",
        "cli_skipping_manifest_scan": "  features.manifest_scan=false \u2014 skipping manifest analysis.",
        "cli_skipping_osint": "  features.osint_scan=false \u2014 skipping OSINT.",
        "cli_skipping_vuln_scan": "  features.vuln_scan=false and features.leak_scan=false \u2014 skipping scan.",
        "cli_decompiling_with": "  Decompiling with {tool} \u2192 {output_dir}/{package}/",
        "cli_source_code_at": "Source code at:",
        "cli_java_files": "   {count} .java files generated",
        "cli_smali_files": "   {count} .smali files generated",
        "cli_clean_source": "Clean source code: {path} ({count} .java files)",
        "cli_batch_scan_header": "Batch scan: {count} target(s) found in {file}",

        "batch_critical_plus_high": "Critical + High",
        "batch_status_bypass": "Bypass OK",
        "batch_common_findings_title": "Common Findings",
        "batch_app_detail_title": "Detail by Application",

        # ── Shared column headers ──────────────────────────────────────────────
        "col_app": "Application",
        "col_status": "Status",
        "col_leaks": "Leaks",
        "col_total": "Total",
        "col_protection": "Protection",
        "col_rule": "Rule",
        "col_finding": "Finding",
        "col_severity": "Severity",
        "col_affected_apps": "Apps affected",

        # ── Batch app card counts ──────────────────────────────────────────────
        "count_critical": "{count} critical",
        "count_high": "{count} high",
        "count_medium": "{count} medium",
        "count_low": "{count} low",
        "count_leaks": "{count} leaks",
        "n_apps": "{count} apps",
        "no_findings": "No findings",

        # ── Language warning (always in English) ───────────────────────────────
        "unsupported_language": "Unsupported language '{lang}', falling back to English.",
    },

    # ══════════════════════════════════════════════════════════════════════════
    "es": {
        # ── Core metadata labels ───────────────────────────────────────────────
        "package": "Package",
        "version": "Versi\u00f3n",
        "min_sdk_target": "SDK m\u00ednimo / objetivo",
        "analyzed_at": "Analizado",
        "duration": "Duraci\u00f3n",
        "decompiled": "Decompilado",
        "sources": "Fuentes",
        "vuln_scan_label": "Escaneo vulns",
        "leak_scan_label": "Escaneo leaks",

        # ── Verdict strings ───────────────────────────────────────────────────
        "verdict_protected": "PROTEGIDA",
        "verdict_no_protection": "SIN PROTECCI\u00d3N",
        "verdict_protection_broken": "PROTECCI\u00d3N ROTA",
        "verdict_protected_subtitle": "Protecciones activas detectadas.",
        "verdict_no_protection_subtitle": "No se detectaron mecanismos anti-root / RASP activos.",
        "verdict_broken_subtitle": "Protecciones detectadas pero eludidas via Frida/FART.",

        # ── Reporter column headers ────────────────────────────────────────────
        "detector": "Detector",
        "detected": "Detectado",
        "strength": "Fortaleza",
        "evidence": "Evidencias encontradas",
        "yes": "S\u00cd",
        "no": "NO",
        "and_more": "\u2026y m\u00e1s",

        # ── Reporter verdict text fragments ────────────────────────────────────
        "verdict_protection_broken_banner": "\u26a0  PROTECCI\u00d3N ROTA \u2014 bypass exitoso",
        "method_label": "M\u00e9todo",
        "dex_extracted": "DEX extra\u00eddos",
        "high_strength_detections": "detecciones de fortaleza alta",
        "verdict_protected_banner": "\u2714  PROTEGIDA contra root",
        "confidence_label": "Confianza",
        "verdict_no_protection_banner": "\u2718  SIN PROTECCI\u00d3N anti-root detectada",
        "no_mechanisms_found": "No se encontraron mecanismos anti-root conocidos.",
        "detector_results_title": "Resultados por detector",

        # ── MASVS summary (terminal) ───────────────────────────────────────────
        "masvs_title": "MASVS v2",
        "score_label": "Score",
        "grade_label": "Grade",
        "coverage_label": "Cobertura",
        "controls": "controles",
        "bypass_confirmed": "BYPASS CONFIRMADO",
        "status_pass": "pass",
        "status_fail": "FAIL",
        "status_bypass": "BYPASS",
        "status_not_tested": "no evaluado",
        "status_no_protection": "FAIL",
        "masvs_controls_title": "Controles MASVS v2",
        "control": "Control",
        "status": "Status",
        "description": "Descripci\u00f3n",

        # ── Reporter save messages ─────────────────────────────────────────────
        "json_report_saved": "Informe JSON guardado en:",
        "analysis_saved": "  An\u00e1lisis guardado:",

        # ── PDF footer / header ────────────────────────────────────────────────
        "generated_on": "Generado el",
        "page": "Pagina",
        "security_report_header": "nutcracker  \u00b7  Security Report",
        "batch_report_header": "nutcracker  \u00b7  Batch Report",

        # ── PDF cover page ─────────────────────────────────────────────────────
        "android_security_report": "Android Security Analysis Report",
        "no_protection_verdict": "SIN PROTECCION",
        "no_protection_verdict_sub": "No se detectaron mecanismos de proteccion activos.",
        "protection_broken_verdict": "PROTECCION ROTA",
        "protection_broken_verdict_sub": "Protecciones detectadas pero eludidas via Frida/FART.",
        "protected_verdict": "PROTEGIDA",
        "protected_verdict_sub": "Protecciones activas detectadas.",
        "sdk_min_target_label": "SDK min / target:",
        "version_label": "Version:",
        "analyzed_label": "Analizado:",
        "duration_label": "Duracion:",
        "decompiled_label": "Decompilado:",
        "sources_label": "Fuentes:",
        "vuln_scan_engine_label": "Escaneo vulns:",
        "leak_scan_engine_label": "Escaneo leaks:",
        "protections_card": "Protecciones",
        "misconfigs_card": "Misconfigs",
        "leaks_card": "Leaks",
        "vulns_card": "Vulns",

        # ── PDF protections section ────────────────────────────────────────────
        "protections_section_title": "Protecciones Descubiertas",
        "detected_badge": "DETECTADO",
        "not_detected_badge": "NO DETECTADO",
        "bypassed_badge": "ELUDIDO",
        "no_evidence": "  Sin evidencias registradas.",
        "no_protection_badge": "  Sin proteccion detectada.",
        "no_protections_detected": "No se detectaron mecanismos de proteccion activos.",
        "protection_bypassed_status": "{count} de {total} protecciones detectadas. Las protecciones fueron eludidas via Frida/FART.",
        "protections_detected_status": "{count} de {total} protecciones detectadas.",

        # ── PDF misconfig section ──────────────────────────────────────────────
        "misconfigs_section_title": "Misconfigurations del Manifest  ({count} hallazgos)",
        "no_misconfigs": "Sin misconfigurations detectadas en el manifest.",
        "findings_label": "hallazgos",
        "debuggable_info_label": "Debuggable",
        "allow_backup_info_label": "allowBackup",
        "cleartext_traffic_info_label": "Cleartext Traffic",
        "network_security_config_info_label": "Network Security Config",
        "yes_label": "SI",
        "no_label": "NO",

        # ── PDF findings sections ──────────────────────────────────────────────
        "leaks_section_title": "Leaks",
        "no_leaks": "No se encontraron leaks.",
        "vulns_section_title": "Vulnerabilidades",
        "no_vulns": "No se encontraron vulnerabilidades.",

        # ── PDF OSINT section ──────────────────────────────────────────────────
        "osint_subdomains_count": "{count} subdominios",
        "osint_public_leaks_count": "{count} leaks publicos",
        "osint_no_findings": "sin hallazgos",
        "osint_own_domains": "Dominios propios ({count})",
        "osint_subdomains_title": "Subdominios via crt.sh ({count})",
        "osint_dev_environments": "Entornos dev/qa/staging expuestos: {count}",
        "osint_and_more": "... y {count} mas",
        "osint_public_leaks_title": "Leaks publicos ({count})",
        "osint_platform": "Plataforma",
        "osint_title_col": "T\u00edtulo",
        "osint_link": "Link",
        "osint_auth_flows": "Auth hardcodeados ({count})",

        # ── PDF MASVS section ──────────────────────────────────────────────────
        "masvs_section_title": "Cumplimiento MASVS v2  ({covered}/{total} controles evaluados)",
        "grade_label_pdf": "Grado",
        "masvs_ctrl_col": "Control",
        "masvs_status_col": "Status",
        "masvs_desc_col": "Descripci\u00f3n",
        "masvs_findings_col": "Hallazgos",
        "masvs_penalty_col": "Penalizaci\u00f3n",
        "masvs_status_no_eval": "NO EVAL.",

        # ── PDF batch report ───────────────────────────────────────────────────
        "batch_security_evaluation": "Evaluacion de Seguridad",
        "batch_application_portfolio": "Portafolio de Aplicaciones",
        "batch_apps_evaluated": "Apps evaluadas",
        "batch_successful": "Exitosas",
        "batch_errors": "Errores",
        "batch_unprotected": "Sin proteccion",
        "batch_protection_broken": "Proteccion rota",
        "batch_total_findings": "Hallazgos totales",
        "batch_critical_high": "Criticos + Altos",
        "batch_executive_summary": "Resumen Ejecutivo",
        "batch_app_column": "Aplicacion",
        "batch_status_column": "Estado",
        "batch_leaks_column": "Leaks",
        "batch_total_column": "Total",
        "batch_status_protected": "Protegida",
        "batch_status_unprotected": "Expuesta",
        "batch_status_bypass_ok": "Bypass OK",
        "batch_apps_with_error": "Apps con error ({count})",
        "batch_common_findings": "Hallazgos Comunes",
        "batch_common_findings_desc": "Vulnerabilidades que se repiten en multiples aplicaciones",
        "batch_rule_col": "Regla",
        "batch_finding_col": "Hallazgo",
        "batch_severity_col": "Severidad",
        "batch_apps_affected_col": "Apps afectadas",
        "batch_detail_section": "Detalle por Aplicacion",
        "batch_no_findings": "Sin hallazgos",
        "batch_critical_count": "{count} criticos",
        "batch_high_count": "{count} altos",
        "batch_medium_count": "{count} medios",
        "batch_low_count": "{count} bajos",
        "batch_leaks_count": "{count} leaks",
        "batch_comparative_title": "Tabla Comparativa \u2014 Estado de Proteccion",
        "batch_unprotected_label": "Sin proteccion",
        "batch_protection_broken_label": "Proteccion rota",
        "batch_with_protection": "Con proteccion",
        "batch_status_col_short": "Proteccion",
        "batch_bypass_achieved": "Bypass logrado",
        "batch_status_short_unprotected": "Sin proteccion",
        "batch_status_short_broken": "Bypass logrado",
        "batch_status_short_protected": "Protegida",

        # ── manifest_analyzer: Misconfiguration titles ─────────────────────────
        "manifest_not_found_title": "AndroidManifest.xml no encontrado",
        "manifest_not_found_desc": "No se pudo localizar el manifest decompilado.",
        "manifest_not_found_rec": "Aseg\u00farate de decompilar con jadx -d <output> <apk>.",
        "manifest_parse_error_title": "Error al parsear AndroidManifest.xml",
        "manifest_parse_error_desc": "El XML no pudo ser parseado correctamente.",
        "manifest_parse_error_rec": "Verifica que jadx decompilara el APK correctamente.",
        "low_target_sdk_title": "targetSdkVersion bajo ({version})",
        "low_target_sdk_desc": "targetSdkVersion={version} no aprovecha las protecciones de Scoped Storage, restricciones de fondo, etc. disponibles desde API 28+.",
        "low_target_sdk_rec": "Actualizar targetSdkVersion a \u2265 34 (Android 14).",
        "dangerous_perms_title": "{count} permiso(s) de alto riesgo",
        "dangerous_perms_rec": "Audita si cada permiso es estrictamente necesario. ACCESS_BACKGROUND_LOCATION, REQUEST_INSTALL_PACKAGES y READ_SMS requieren justificaci\u00f3n especial en Google Play.",
        "debuggable_title": 'android:debuggable="true"',
        "debuggable_desc": "La app est\u00e1 marcada como depurable. Permite adb shell run-as, adjuntar debugger, leer el sandbox de la app y volcar memoria.",
        "debuggable_rec": "Eliminar android:debuggable o establecerlo en false en builds de producci\u00f3n.",
        "allow_backup_title": 'android:allowBackup="true" (o no definido)',
        "allow_backup_desc": "Permite backup ADB del sandbox de la app sin root: adb backup -f app.ab com.package \u2192 expone bases de datos, tokens, etc.",
        "allow_backup_rec": 'Establecer android:allowBackup="false" o definir reglas de backup expl\u00edcitas.',
        "cleartext_title": 'android:usesCleartextTraffic="true"',
        "cleartext_desc": "La app permite conexiones HTTP sin cifrar. Las credenciales y datos sensibles pueden viajar en texto plano.",
        "cleartext_rec": "Eliminar usesCleartextTraffic=true y forzar HTTPS en todos los endpoints. Usar Network Security Config para dominios legacy si es necesario.",
        "no_nsc_title": "Sin android:networkSecurityConfig",
        "no_nsc_desc": "No se define una pol\u00edtica de seguridad de red expl\u00edcita. Desde Android 9+ el sistema aplica defaults, pero no hay certificate pinning ni restricciones custom.",
        "no_nsc_rec": 'Definir android:networkSecurityConfig="@xml/network_security_config" con certificate pinning para los dominios de producci\u00f3n.',
        "exported_component_title": "<{tag}> exportado sin permiso: {name}",
        "exported_component_desc": "El componente {fullname} es accesible desde otras apps sin requerir ning\u00fan permiso.",
        "exported_component_rec": 'A\u00f1adir android:exported="false" si no es necesario externamente, o protegerlo con android:permission="...signature...".',
        "no_nsc_cleartext_title": "Sin Network Security Config y cleartext activo",
        "no_nsc_cleartext_desc": 'La app permite tr\u00e1fico en texto claro (usesCleartextTraffic=true) y no define un network_security_config.xml para restringirlo.',
        "no_nsc_cleartext_rec": 'Define res/xml/network_security_config.xml con <base-config cleartextTrafficPermitted="false"> y a\u00f1ade android:networkSecurityConfig al <application>.',
        "user_ca_title": "Conf\u00eda en CAs del usuario (MITM posible)",
        "user_ca_desc": "La Network Security Config conf\u00eda en certificados instalados por el usuario. Un atacante puede instalar su propia CA y realizar MITM.",
        "user_ca_rec": 'Eliminar <certificates src="user"/> del bloque de producci\u00f3n. Solo usar para debug builds con <debug-overrides>.',
        "cleartext_domain_title": "Cleartext permitido para dominio(s): {domains}",
        "cleartext_domain_desc": "La config de red permite tr\u00e1fico HTTP sin cifrar hacia: {domains}.",
        "cleartext_domain_rec": "Migrar a HTTPS y eliminar cleartextTrafficPermitted=true.",
        "no_cert_pinning_title": "Sin certificate pinning en Network Security Config",
        "no_cert_pinning_desc": "Se encontr\u00f3 network_security_config.xml pero no define <pin-set>. Sin pinning, cualquier CA de confianza del sistema puede emitir certs v\u00e1lidos.",
        "no_cert_pinning_rec": 'Agregar <pin-set expiration="..."><pin digest="SHA-256">...</pin></pin-set> para los dominios de producci\u00f3n.',
        "secret_rec": "Mover valores sensibles fuera del APK. Usar Android Keystore, variables de entorno o un secrets manager.",

        # ── manifest_analyzer: secret pattern titles ───────────────────────────
        "secret_api_key": "API Key hardcodeada",
        "secret_aws_key": "AWS Access Key",
        "secret_firebase_url": "Firebase Realtime DB URL",
        "secret_firebase_key": "Firebase API Key",
        "secret_google_maps_key": "Google Maps API Key",
        "secret_jwt_token": "JWT Token hardcodeado",
        "secret_private_ip": "IP privada hardcodeada",
        "secret_password": "Posible contrase\u00f1a hardcodeada",

        # ── manifest_analyzer: progress messages ───────────────────────────────
        "analyzing_manifest_progress": "Analizando AndroidManifest.xml...",
        "analyzing_nsc_progress": "Analizando network_security_config.xml...",
        "scanning_strings_progress": "Escaneando strings.xml en busca de secrets...",

        # ── nutcracker.py: terminal verdict / banner ───────────────────────────
        "cli_protected_banner": "PROTEGIDA",
        "cli_no_protection_banner": "SIN PROTECCION",
        "cli_protection_broken_banner": "PROTECCION ROTA",
        "cli_protection_broken_frida": "Frida/frida-dexdump volc\u00f3 {dex_count} DEX del proceso.\n  Las protecciones anti-root no pudieron evitar la extracci\u00f3n del bytecode.",
        "cli_no_protection_detail": "No se detectaron mecanismos de proteccion anti-root / RASP activos.",
        "cli_protected_detail": "Protecciones activas detectadas. No se encontraron vulnerabilidades expuestas.",
        "cli_protected_vulns_detail": "Protecciones activas detectadas. Se hallaron {count} vulnerabilidad(es) en analisis estatico.",
        "cli_bypassed_detail": "Protecciones detectadas pero eludidas en runtime ({method}, {dex_count} DEX extraidos).",
        "cli_app_has_protection": "tiene",
        "cli_app_no_protection": "no tiene",
        "cli_anti_root_label": "protecci\u00f3n anti-root / RASP",

        # ── manifest scan terminal ─────────────────────────────────────────────
        "cli_manifest_misconfigs_header": "Misconfigurations del manifest:",
        "cli_manifest_sev_col": "Sev.",
        "cli_manifest_finding_col": "Hallazgo",
        "cli_manifest_evidence_col": "Evidencia",
        "cli_manifest_location_col": "Ubicaci\u00f3n",
        "cli_manifest_recs_header": "Recomendaciones:",
        "cli_no_manifest_misconfigs": "Sin misconfigurations detectadas en el manifest.",

        # ── OSINT terminal ─────────────────────────────────────────────────────
        "cli_osint_secrets_header": "OSINT \u2014 Secretos de BuildConfig: {count} encontrados",
        "cli_osint_field_col": "Campo",
        "cli_osint_value_col": "Valor",
        "cli_osint_service_col": "Servicio",
        "cli_osint_file_col": "Archivo",
        "cli_osint_domains_header": "OSINT \u2014 Dominios propios:",
        "cli_osint_subdomains_header": "OSINT \u2014 Subdominios (crt.sh): {count} encontrados",
        "cli_osint_dev_exposed": "{count} entornos dev/qa/staging expuestos:",
        "cli_osint_public_leaks_header": "OSINT \u2014 Leaks p\u00fablicos: {count} encontrados",
        "cli_osint_auth_header": "OSINT \u2014 Auth hardcodeados: {count} detectados",
        "cli_osint_saved": "OSINT guardado en:",

        # ── Vuln scan terminal ─────────────────────────────────────────────────
        "cli_vuln_scan_enabled": "habilitado",
        "cli_vuln_scan_disabled": "deshabilitado",
        "cli_leak_engines_disabled": "desactivados",
        "cli_vuln_scan_header": "  Vulnerability scan (c\u00f3digo): ",
        "cli_vuln_engine_header": "  Vulnerability scan engine: ",
        "cli_leak_scan_header": "  Leak scan: ",
        "cli_leak_engines_header": "  Leak engines: ",
        "cli_scanner_used_dim": "Esc\u00e1ner usado: {engine} \u2014 {files} archivos, {findings} hallazgos",

        # ── PDF generation terminal ────────────────────────────────────────────
        "cli_generating_pdf": "Generando informe PDF...",
        "cli_pdf_saved": "Informe PDF guardado en:",
        "cli_loading_prev_findings": "Cargando {count} hallazgos de vulnerabilidades previos...",
        "cli_vuln_json_saved": "Informe de vulnerabilidades guardado en:",

        # ── Misc terminal ──────────────────────────────────────────────────────
        "cli_skipping_decompilation": "  features.decompilation=false \u2014 omitiendo decompilaci\u00f3n.",
        "cli_skipping_manifest_scan": "  features.manifest_scan=false \u2014 omitiendo an\u00e1lisis del manifest.",
        "cli_skipping_osint": "  features.osint_scan=false \u2014 omitiendo OSINT.",
        "cli_skipping_vuln_scan": "  features.vuln_scan=false y features.leak_scan=false \u2014 omitiendo escaneo.",
        "cli_decompiling_with": "  Decompilando con {tool} \u2192 {output_dir}/{package}/",
        "cli_source_code_at": "C\u00f3digo fuente en:",
        "cli_java_files": "   {count} archivos .java generados",
        "cli_smali_files": "   {count} archivos .smali generados",
        "cli_clean_source": "C\u00f3digo fuente limpio: {path} ({count} archivos .java)",
        "cli_batch_scan_header": "Batch scan: {count} objetivo(s) encontrado(s) en {file}",

        "batch_critical_plus_high": "Criticos + Altos",
        "batch_status_bypass": "Bypass OK",
        "batch_common_findings_title": "Hallazgos Comunes",
        "batch_app_detail_title": "Detalle por Aplicacion",

        # ── Shared column headers ──────────────────────────────────────────────
        "col_app": "Aplicacion",
        "col_status": "Estado",
        "col_leaks": "Leaks",
        "col_total": "Total",
        "col_protection": "Proteccion",
        "col_rule": "Regla",
        "col_finding": "Hallazgo",
        "col_severity": "Severidad",
        "col_affected_apps": "Apps afectadas",

        # ── Batch app card counts ──────────────────────────────────────────────
        "count_critical": "{count} criticos",
        "count_high": "{count} altos",
        "count_medium": "{count} medios",
        "count_low": "{count} bajos",
        "count_leaks": "{count} leaks",
        "n_apps": "{count} apps",
        "no_findings": "Sin hallazgos",

        # ── Language warning ───────────────────────────────────────────────────
        "unsupported_language": "Unsupported language '{lang}', falling back to English.",
    },
}
