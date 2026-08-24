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
