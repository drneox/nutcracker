"""Tests del split de vuln_scanner.py (Fase 0.3): scan_types / vuln_scanner / leak_scanner.

Verifica que la separación en 3 módulos no rompió el comportamiento: las
dataclasses siguen siendo la misma identidad de clase entre módulos y el
scanner regex sigue detectando hallazgos reales sobre código de prueba.
"""

from pathlib import Path

from nutcracker_core import leak_scanner, scan_types, vuln_scanner


def test_vuln_scanner_reexports_same_classes_as_scan_types():
    assert vuln_scanner.VulnFinding is scan_types.VulnFinding
    assert vuln_scanner.VulnRule is scan_types.VulnRule
    assert vuln_scanner.ScanResult is scan_types.ScanResult


def test_vuln_scanner_reexports_same_functions_as_leak_scanner():
    assert vuln_scanner.scan_with_apkleaks is leak_scanner.scan_with_apkleaks
    assert vuln_scanner.scan_with_gitleaks is leak_scanner.scan_with_gitleaks


def test_scan_directory_detects_hardcoded_password(tmp_path):
    java_file = tmp_path / "Login.java"
    java_file.write_text(
        'public class Login {\n'
        '    String password = "hunter2_super_secret";\n'
        '}\n',
        encoding="utf-8",
    )

    result = vuln_scanner.scan_directory(tmp_path)

    assert result.files_scanned == 1
    rule_ids = {f.rule_id for f in result.findings}
    assert "HC002" in rule_ids


def test_scan_directory_ignores_placeholder_values(tmp_path):
    java_file = tmp_path / "Config.java"
    java_file.write_text(
        'public class Config {\n'
        '    String password = "your_password_here_example";\n'
        '}\n',
        encoding="utf-8",
    )

    result = vuln_scanner.scan_directory(tmp_path)

    rule_ids = {f.rule_id for f in result.findings}
    assert "HC002" not in rule_ids


def test_scan_manifest_components_flags_exported_activity(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '  <application android:debuggable="true">\n'
        '    <activity android:name=".LeakyActivity" android:exported="true"/>\n'
        '  </application>\n'
        '</manifest>\n',
        encoding="utf-8",
    )

    findings = vuln_scanner.scan_manifest_components(tmp_path)

    rule_ids = {f.rule_id for f in findings}
    assert "COMP006" in rule_ids  # activity exported sin permission
    assert "INFO001" in rule_ids  # debuggable=true


def test_apkleaks_false_positive_filter():
    assert leak_scanner._is_apkleaks_false_positive("JSON_Web_Token", "version=1.2.3")
    assert not leak_scanner._is_apkleaks_false_positive("Generic_Secret", "sk_live_abcdef123456")


def test_scan_with_gitleaks_returns_empty_without_binary(tmp_path, monkeypatch):
    import shutil as real_shutil
    monkeypatch.setattr(real_shutil, "which", lambda name: None)

    findings = vuln_scanner.scan_with_gitleaks(tmp_path)

    assert findings == []


# ── Reglas nuevas: cierre de cobertura OWASP MAS (2026-07-25) ────────────────

def test_crypto007_detects_key_derived_directly_from_password(tmp_path):
    java_file = tmp_path / "Crypto.java"
    java_file.write_text(
        'public class Crypto {\n'
        '    SecretKeySpec key = new SecretKeySpec(userPassword.getBytes(), "AES");\n'
        '}\n',
        encoding="utf-8",
    )
    result = vuln_scanner.scan_directory(tmp_path)
    assert "CRYPTO007" in {f.rule_id for f in result.findings}


def test_crypto007_ignores_key_from_secure_source(tmp_path):
    java_file = tmp_path / "Crypto.java"
    java_file.write_text(
        'public class Crypto {\n'
        '    SecretKeySpec key = new SecretKeySpec(derivedKeyBytes, "AES");\n'
        '}\n',
        encoding="utf-8",
    )
    result = vuln_scanner.scan_directory(tmp_path)
    assert "CRYPTO007" not in {f.rule_id for f in result.findings}


def test_auth002_detects_deprecated_fingerprint_manager(tmp_path):
    java_file = tmp_path / "Auth.java"
    java_file.write_text(
        'import android.hardware.fingerprint.FingerprintManager;\n'
        'public class Auth {}\n',
        encoding="utf-8",
    )
    result = vuln_scanner.scan_directory(tmp_path)
    assert "AUTH002" in {f.rule_id for f in result.findings}


def test_auth002_ignores_biometric_prompt(tmp_path):
    java_file = tmp_path / "Auth.java"
    java_file.write_text(
        'import androidx.biometric.BiometricPrompt;\n'
        'public class Auth {}\n',
        encoding="utf-8",
    )
    result = vuln_scanner.scan_directory(tmp_path)
    assert "AUTH002" not in {f.rule_id for f in result.findings}


def test_privacy001_detects_imei_tracking(tmp_path):
    java_file = tmp_path / "Device.java"
    java_file.write_text(
        'public class Device {\n'
        '    String id = telephonyManager.getImei();\n'
        '}\n',
        encoding="utf-8",
    )
    result = vuln_scanner.scan_directory(tmp_path)
    assert "PRIVACY001" in {f.rule_id for f in result.findings}


def test_privacy001_ignores_unrelated_getters(tmp_path):
    java_file = tmp_path / "Device.java"
    java_file.write_text(
        'public class Device {\n'
        '    String id = UUID.randomUUID().toString();\n'
        '}\n',
        encoding="utf-8",
    )
    result = vuln_scanner.scan_directory(tmp_path)
    assert "PRIVACY001" not in {f.rule_id for f in result.findings}
