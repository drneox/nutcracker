"""Tests de los checks dinámicos (Fase 2.2 del plan) — deterministas vía un
adb_run inyectado, sin necesitar un dispositivo real conectado."""

from __future__ import annotations

from nutcracker_core.checks.dynamic.cleartext_traffic import CleartextTrafficDynamicCheck
from nutcracker_core.checks.dynamic.context import DynamicCheckContext
from nutcracker_core.checks.dynamic.debuggable import DebuggableDynamicCheck


def _ctx(fake_adb_run) -> DynamicCheckContext:
    return DynamicCheckContext(package="com.example.app", serial="EMULATOR-TEST", adb_run=fake_adb_run)


# ── DebuggableDynamicCheck ────────────────────────────────────────────────────

def test_debuggable_detected_via_run_as():
    def fake_adb_run(args: list[str]) -> str:
        if args[:2] == ["shell", "run-as"]:
            return "uid=10123(com.example.app) gid=10123(com.example.app)\n"
        if args == ["shell", "pidof", "com.example.app"]:
            return "12345\n"
        if args == ["jdwp"]:
            return ""
        return ""

    finding = DebuggableDynamicCheck().run(_ctx(fake_adb_run))[0]
    assert finding.detected is True
    assert finding.severity == "high"
    assert finding.masvs == ["MASVS-RESILIENCE-4"]
    assert finding.maswe == ["MASWE-0067"]
    assert finding.cwe == ["CWE-489"]


def test_debuggable_detected_via_jdwp_only():
    def fake_adb_run(args: list[str]) -> str:
        if args[:2] == ["shell", "run-as"]:
            return "run-as: Package 'com.example.app' is not debuggable\n"
        if args == ["shell", "pidof", "com.example.app"]:
            return "999\n"
        if args == ["jdwp"]:
            return "888\n999\n"
        return ""

    finding = DebuggableDynamicCheck().run(_ctx(fake_adb_run))[0]
    assert finding.detected is True


def test_debuggable_not_detected():
    def fake_adb_run(args: list[str]) -> str:
        if args[:2] == ["shell", "run-as"]:
            return "run-as: Package 'com.example.app' is not debuggable\n"
        if args == ["shell", "pidof", "com.example.app"]:
            return ""
        if args == ["jdwp"]:
            return ""
        return ""

    finding = DebuggableDynamicCheck().run(_ctx(fake_adb_run))[0]
    assert finding.detected is False
    assert finding.severity == "info"


# ── CleartextTrafficDynamicCheck ──────────────────────────────────────────────

def test_cleartext_traffic_detected():
    def fake_adb_run(args: list[str]) -> str:
        if args == ["shell", "logcat", "-c"]:
            return ""
        if args[:3] == ["shell", "logcat", "-d"]:
            return "I/OkHttp: --> GET http://api.example.com/login\nD/Something: unrelated\n"
        return ""

    check = CleartextTrafficDynamicCheck(settle_seconds=0)
    finding = check.run(_ctx(fake_adb_run))[0]
    assert finding.detected is True
    assert "api.example.com" in finding.detail
    assert finding.masvs == ["MASVS-NETWORK-1"]
    assert finding.maswe == ["MASWE-0050"]


def test_cleartext_traffic_not_detected_when_only_https():
    def fake_adb_run(args: list[str]) -> str:
        if args[:3] == ["shell", "logcat", "-d"]:
            return "I/OkHttp: --> GET https://api.example.com/login\n"
        return ""

    check = CleartextTrafficDynamicCheck(settle_seconds=0)
    finding = check.run(_ctx(fake_adb_run))[0]
    assert finding.detected is False
    assert finding.severity == "info"


def test_default_adb_runner_used_when_none_injected():
    """Sin adb_run explícito, DynamicCheckContext debe construir uno real
    (default_adb_runner) en vez de quedar None — evita AttributeError en uso real."""
    ctx = DynamicCheckContext(package="com.example.app")
    assert callable(ctx.adb_run)
