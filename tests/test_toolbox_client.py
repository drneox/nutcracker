"""Tests de nutcracker_core/toolbox/client.py -- la capa de acceso uniforme
al toolbox estático en Docker.

Nada acá levanta un contenedor real: se parchea subprocess.run/shutil.which
del propio módulo, igual que el resto de la suite hace con adb/apktool/jadx.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from nutcracker_core import toolbox
from nutcracker_core.toolbox import client


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


# ── is_enabled / image_name ─────────────────────────────────────────────────

def test_is_enabled_false_by_default():
    assert not toolbox.is_enabled(None)
    assert not toolbox.is_enabled({})
    assert not toolbox.is_enabled({"toolbox": {}})


def test_is_enabled_true_when_configured():
    assert toolbox.is_enabled({"toolbox": {"enabled": True}})


def test_image_name_defaults_and_override():
    assert toolbox.image_name(None) == toolbox.DEFAULT_IMAGE
    assert toolbox.image_name({"toolbox": {"image": "custom:tag"}}) == "custom:tag"


# ── run() sin docker instalado ───────────────────────────────────────────────

def test_run_raises_toolbox_error_without_docker(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: None)

    with pytest.raises(toolbox.ToolboxError, match="docker"):
        toolbox.run("jadx", ["--help"])


def test_ensure_image_raises_toolbox_error_without_docker(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: None)

    with pytest.raises(toolbox.ToolboxError, match="docker"):
        toolbox.ensure_image()


# ── image_exists ─────────────────────────────────────────────────────────────

def test_image_exists_false_without_docker(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: None)
    assert not toolbox.image_exists()


def test_image_exists_checks_docker_image_inspect(monkeypatch):
    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        return _completed(returncode=0)

    monkeypatch.setattr(client.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(client.subprocess, "run", fake_run)

    assert toolbox.image_exists()
    assert calls[0][:3] == ["/usr/bin/docker", "image", "inspect"]
    assert toolbox.DEFAULT_IMAGE in calls[0]


# ── ensure_image (build) ─────────────────────────────────────────────────────

def test_ensure_image_skips_build_when_image_already_exists(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(client, "image_exists", lambda config=None: True)

    calls = []
    monkeypatch.setattr(client.subprocess, "run", lambda *a, **kw: calls.append(a) or _completed())

    toolbox.ensure_image()

    assert calls == [], "no debe intentar build si la imagen ya existe"


def test_ensure_image_builds_when_missing(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(client, "image_exists", lambda config=None: False)

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        return _completed(returncode=0)

    monkeypatch.setattr(client.subprocess, "run", fake_run)

    toolbox.ensure_image()

    assert len(calls) == 1
    cmd = calls[0]
    assert cmd[:2] == ["/usr/bin/docker", "build"]
    assert "-f" in cmd and str(client._DOCKERFILE) in cmd
    assert "-t" in cmd and toolbox.DEFAULT_IMAGE in cmd


def test_ensure_image_raises_on_build_failure(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(client, "image_exists", lambda config=None: False)
    monkeypatch.setattr(
        client.subprocess, "run",
        lambda *a, **kw: _completed(returncode=1, stderr="Dockerfile roto"),
    )

    with pytest.raises(toolbox.ToolboxError, match="Dockerfile roto"):
        toolbox.ensure_image()


# ── run() -- construcción del comando docker run ────────────────────────────

def test_run_builds_expected_docker_command(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(client, "ensure_image", lambda config=None, build_timeout=1800: None)

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        return _completed(returncode=0, stdout="ok")

    monkeypatch.setattr(client.subprocess, "run", fake_run)

    result = toolbox.run("jadx", ["--no-res", "/abs/path/app.apk"], timeout=120)

    assert result.returncode == 0
    cmd = calls[0]
    assert cmd[0] == "/usr/bin/docker"
    assert cmd[1] == "run"
    assert "--rm" in cmd
    assert "-v" in cmd
    mount = cmd[cmd.index("-v") + 1]
    cwd = str(Path.cwd().resolve())
    assert mount == f"{cwd}:{cwd}"
    assert "-w" in cmd and cmd[cmd.index("-w") + 1] == cwd
    assert toolbox.DEFAULT_IMAGE in cmd
    # tool + args van al final, en orden, después de la imagen
    tail = cmd[cmd.index(toolbox.DEFAULT_IMAGE) + 1:]
    assert tail == ["jadx", "--no-res", "/abs/path/app.apk"]


def test_run_calls_ensure_image_by_default(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(client.subprocess, "run", lambda *a, **kw: _completed())

    calls = []
    monkeypatch.setattr(client, "ensure_image", lambda config=None, build_timeout=1800: calls.append(config))

    toolbox.run("jadx", ["--help"])

    assert len(calls) == 1


def test_run_skips_ensure_image_when_build_if_missing_false(monkeypatch):
    monkeypatch.setattr(client.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(client.subprocess, "run", lambda *a, **kw: _completed())

    calls = []
    monkeypatch.setattr(client, "ensure_image", lambda config=None, build_timeout=1800: calls.append(config))

    toolbox.run("jadx", ["--help"], build_if_missing=False)

    assert calls == []
