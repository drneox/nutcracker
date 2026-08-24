"""Tests del auto-recovery de emulador (DeadSystemException).

Cubre los helpers de frida_capture.py agregados tras el job 18 (2026-08-24):
el system_server del emulador se murió y todo spawn de frida falló con
DeadSystemException -- el agente quemó 11 iteraciones contra un dispositivo
muerto. La recuperación es rebootear el emulador y esperar el boot.
"""

from __future__ import annotations

from types import SimpleNamespace

import nutcracker_core.plugins.aipwn.frida_capture as fc


def test_looks_like_dead_system_detects_the_markers():
    assert fc._looks_like_dead_system("Failed to spawn: android.os.DeadSystemRuntimeException")
    assert fc._looks_like_dead_system("android.os.DeadSystemException")
    assert not fc._looks_like_dead_system("Failed to spawn: unable to find process")
    assert not fc._looks_like_dead_system("")


def test_check_device_healthy_true_when_system_server_alive_and_booted(monkeypatch):
    responses = {
        "pidof": SimpleNamespace(stdout="6215\n"),
        "getprop": SimpleNamespace(stdout="1\n"),
    }

    def fake_run(cmd, **kwargs):
        return responses["pidof" if "pidof" in cmd else "getprop"]

    monkeypatch.setattr(fc.subprocess, "run", fake_run)
    assert fc.check_device_healthy(["adb", "-s", "emulator-5554"]) is True


def test_check_device_healthy_false_when_system_server_dead(monkeypatch):
    monkeypatch.setattr(
        fc.subprocess, "run",
        lambda cmd, **kwargs: SimpleNamespace(stdout=""),
    )
    assert fc.check_device_healthy(["adb", "-s", "emulator-5554"]) is False


def test_check_device_healthy_false_on_adb_failure(monkeypatch):
    def boom(cmd, **kwargs):
        raise OSError("adb not reachable")

    monkeypatch.setattr(fc.subprocess, "run", boom)
    assert fc.check_device_healthy(["adb"]) is False


def test_reboot_device_and_wait_true_when_boot_completes(monkeypatch):
    monkeypatch.setattr(fc.subprocess, "run", lambda cmd, **kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(fc.time, "sleep", lambda _s: None)
    monkeypatch.setattr(fc, "check_device_healthy", lambda _args: True)

    assert fc.reboot_device_and_wait(["adb", "-s", "emulator-5554"], timeout=30) is True


def test_reboot_device_and_wait_false_on_timeout(monkeypatch):
    monkeypatch.setattr(fc.subprocess, "run", lambda cmd, **kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(fc.time, "sleep", lambda _s: None)
    monkeypatch.setattr(fc, "check_device_healthy", lambda _args: False)

    assert fc.reboot_device_and_wait(["adb", "-s", "emulator-5554"], timeout=0.1) is False


def test_reboot_device_and_wait_false_if_reboot_cmd_fails(monkeypatch):
    def boom(cmd, **kwargs):
        raise OSError("device offline")

    monkeypatch.setattr(fc.subprocess, "run", boom)
    assert fc.reboot_device_and_wait(["adb", "-s", "emulator-5554"]) is False


# ── Auto-start del emulador ──────────────────────────────────────────────────

def test_find_emulator_binary_prefers_android_home(monkeypatch, tmp_path):
    fake = tmp_path / "emulator" / "emulator"
    fake.parent.mkdir(parents=True)
    fake.touch()
    monkeypatch.setenv("ANDROID_HOME", str(tmp_path))
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)

    assert fc.find_emulator_binary() == str(fake)


def test_list_avds_parses_output(monkeypatch):
    monkeypatch.setattr(
        fc.subprocess, "run",
        lambda cmd, **kwargs: SimpleNamespace(stdout="Pixel_6_API_34\n\nResizable_API_34\n"),
    )
    assert fc.list_avds("emulator") == ["Pixel_6_API_34", "Resizable_API_34"]


def test_list_avds_empty_on_error(monkeypatch):
    def boom(cmd, **kwargs):
        raise OSError("no emulator")

    monkeypatch.setattr(fc.subprocess, "run", boom)
    assert fc.list_avds("emulator") == []


def test_any_device_online_only_counts_device_state(monkeypatch):
    monkeypatch.setattr(
        fc.subprocess, "run",
        lambda cmd, **kwargs: SimpleNamespace(stdout=(
            "List of devices attached\n"
            "emulator-5554\tdevice\n"
            "0A12345\tunauthorized\n"
            "emulator-5556\toffline\n"
            "\n"
        )),
    )
    assert fc.any_device_online("adb") == ["emulator-5554"]


def test_start_emulator_and_wait_returns_serial_when_booted(monkeypatch):
    popen_calls = []

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            popen_calls.append(cmd)

    monkeypatch.setattr(fc.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(fc.subprocess, "run", lambda cmd, **kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(fc.time, "sleep", lambda _s: None)
    monkeypatch.setattr(fc, "any_device_online", lambda _adb: ["emulator-5554"])
    monkeypatch.setattr(fc, "check_device_healthy", lambda _args: True)

    serial = fc.start_emulator_and_wait("emulator", "Pixel_6_API_34", "adb", timeout=30)

    assert serial == "emulator-5554"
    assert popen_calls == [["emulator", "-avd", "Pixel_6_API_34"]]


def test_start_emulator_and_wait_none_on_timeout(monkeypatch):
    monkeypatch.setattr(fc.subprocess, "Popen", lambda cmd, **kwargs: None)
    monkeypatch.setattr(fc.subprocess, "run", lambda cmd, **kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(fc.time, "sleep", lambda _s: None)
    monkeypatch.setattr(fc, "any_device_online", lambda _adb: [])

    assert fc.start_emulator_and_wait("emulator", "Pixel_6_API_34", "adb", timeout=0.1) is None
