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
