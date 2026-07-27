"""Tests de DeviceInstalledDownloader (nutcracker_core/downloader.py).

Extrae el .apk ya instalado en un device conectado vía `adb shell pm path` +
`adb pull`, sin tocar red -- usado por `nutcracker scan --source device` y
por jobs de la cola encolados con --source device (ver test_queue_engine.py /
test_orchestrator.py).
"""

from __future__ import annotations

import subprocess

import pytest

from nutcracker_core.downloader import (
    APKDownloadError,
    DeviceInstalledDownloader,
    _ensure_network_serial_connected,
    _is_daemon_transient_error,
    download_apk_from_config,
)


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


def test_download_single_apk_pulls_base_apk(monkeypatch, tmp_path):
    from pathlib import Path

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        if "path" in cmd:
            return _completed(stdout="package:/data/app/com.example.app/base.apk\n")
        if "pull" in cmd:
            Path(cmd[-1]).write_bytes(b"PK\x03\x04")
            return _completed()
        return _completed()

    monkeypatch.setattr("nutcracker_core.downloader.subprocess.run", fake_run)

    dl = DeviceInstalledDownloader(output_dir=str(tmp_path), serial="ZY22GPM27J")
    result = dl.download("com.example.app")

    assert result.name == "base.apk"
    assert result.exists()
    # -s <serial> antepuesto a cada invocación de adb
    assert all("-s" in c and "ZY22GPM27J" in c for c in calls)


def test_download_app_bundle_splits_identifies_base_apk(monkeypatch, tmp_path):
    from pathlib import Path

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        if "path" in cmd:
            return _completed(stdout=(
                "package:/data/app/com.example.bundle/base.apk\n"
                "package:/data/app/com.example.bundle/split_config.arm64_v8a.apk\n"
            ))
        if "pull" in cmd:
            Path(cmd[-1]).write_bytes(b"PK\x03\x04")
            return _completed()
        return _completed()

    monkeypatch.setattr("nutcracker_core.downloader.subprocess.run", fake_run)

    dl = DeviceInstalledDownloader(output_dir=str(tmp_path))
    result = dl.download("com.example.bundle")

    assert result.name == "base.apk"
    assert (tmp_path / "com.example.bundle" / "split_config.arm64_v8a.apk").exists()


def test_download_raises_when_package_not_installed(monkeypatch, tmp_path):
    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        return _completed(stdout="", stderr="")

    monkeypatch.setattr("nutcracker_core.downloader.subprocess.run", fake_run)

    dl = DeviceInstalledDownloader(output_dir=str(tmp_path), serial="X")
    with pytest.raises(APKDownloadError, match="no está instalado"):
        dl.download("com.example.notinstalled")


def test_download_raises_when_adb_missing(monkeypatch, tmp_path):
    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        raise FileNotFoundError()

    monkeypatch.setattr("nutcracker_core.downloader.subprocess.run", fake_run)

    dl = DeviceInstalledDownloader(output_dir=str(tmp_path))
    with pytest.raises(APKDownloadError, match="adb no está instalado"):
        dl.download("com.example.app")


def test_download_raises_when_pull_fails(monkeypatch, tmp_path):
    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        if "path" in cmd:
            return _completed(stdout="package:/data/app/com.example.app/base.apk\n")
        if "pull" in cmd:
            return _completed(returncode=1, stderr="adb: error: device offline")
        return _completed()

    monkeypatch.setattr("nutcracker_core.downloader.subprocess.run", fake_run)

    dl = DeviceInstalledDownloader(output_dir=str(tmp_path))
    with pytest.raises(APKDownloadError, match="adb pull"):
        dl.download("com.example.app")


# ── Resiliencia ante inestabilidad del daemon adb (conflicto con WebUSB) ────

def test_is_daemon_transient_error_detects_known_markers():
    assert _is_daemon_transient_error("* daemon not running; starting now at tcp:5037")
    assert _is_daemon_transient_error("adb.exe: cannot connect to daemon")
    assert _is_daemon_transient_error("could not read ok from ADB Server")
    assert _is_daemon_transient_error("* failed to start daemon")


def test_is_daemon_transient_error_false_for_real_errors():
    assert not _is_daemon_transient_error("error: device offline")
    assert not _is_daemon_transient_error("adb: error: failed to stat remote object")


def test_ensure_network_serial_connected_noop_for_usb_serial(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "nutcracker_core.downloader.subprocess.run",
        lambda *a, **kw: calls.append(a) or _completed(),
    )
    _ensure_network_serial_connected("ZY22GPM27J")
    assert calls == []


def test_ensure_network_serial_connected_calls_adb_connect_for_ip_serial(monkeypatch):
    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        return _completed(stdout="connected to 172.20.10.6:5555")

    monkeypatch.setattr("nutcracker_core.downloader.subprocess.run", fake_run)
    _ensure_network_serial_connected("172.20.10.6:5555")
    assert calls == [["adb", "connect", "172.20.10.6:5555"]]


def test_ensure_network_serial_connected_retries_on_daemon_transient_error(monkeypatch):
    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        if len(calls) < 3:
            return _completed(stderr="adb.exe: cannot connect to daemon")
        return _completed(stdout="connected to 172.20.10.6:5555")

    monkeypatch.setattr("nutcracker_core.downloader.subprocess.run", fake_run)
    monkeypatch.setattr("nutcracker_core.downloader.time.sleep", lambda *_: None)
    _ensure_network_serial_connected("172.20.10.6:5555")
    assert len(calls) == 3


def test_download_retries_pm_path_on_daemon_transient_error(monkeypatch, tmp_path):
    from pathlib import Path

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(list(cmd))
        if "connect" in cmd:
            return _completed(stdout="connected to 172.20.10.6:5555")
        if "path" in cmd:
            # Primer intento: falla transitoria del daemon. Segundo: éxito real.
            path_calls = [c for c in calls if "path" in c]
            if len(path_calls) < 2:
                return _completed(stderr="could not read ok from ADB Server")
            return _completed(stdout="package:/data/app/com.example.app/base.apk\n")
        if "pull" in cmd:
            Path(cmd[-1]).write_bytes(b"PK\x03\x04")
            return _completed()
        return _completed()

    monkeypatch.setattr("nutcracker_core.downloader.subprocess.run", fake_run)
    monkeypatch.setattr("nutcracker_core.downloader.time.sleep", lambda *_: None)

    dl = DeviceInstalledDownloader(output_dir=str(tmp_path), serial="172.20.10.6:5555")
    result = dl.download("com.example.app")

    assert result.name == "base.apk"
    assert result.exists()


def test_download_apk_from_config_dispatches_to_device_downloader(monkeypatch, tmp_path):
    from pathlib import Path

    calls = {}

    class _FakeDownloader:
        def __init__(self, output_dir, serial=None):
            calls["output_dir"] = output_dir
            calls["serial"] = serial

        def download(self, package_id):
            calls["package_id"] = package_id
            p = Path(calls["output_dir"]) / f"{package_id}.apk"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"PK\x03\x04")
            return p

    monkeypatch.setattr("nutcracker_core.downloader.DeviceInstalledDownloader", _FakeDownloader)

    result = download_apk_from_config(
        "com.example.app", config={}, source="device",
        output_dir=str(tmp_path), serial="ZY22GPM27J",
    )

    assert calls["serial"] == "ZY22GPM27J"
    assert calls["package_id"] == "com.example.app"
    assert result.exists()
