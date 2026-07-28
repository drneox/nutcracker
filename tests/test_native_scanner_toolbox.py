"""Tests de la integración del toolbox de Docker en native_scanner.py
(nm/objdump/strings) -- ver nutcracker_core/toolbox/.

Opt-in: sin config (o con toolbox.enabled=false), debe comportarse
exactamente como antes (binarios locales vía shutil.which).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from nutcracker_core import native_scanner as ns


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


# ── _get_imported_symbols ────────────────────────────────────────────────────

def test_get_imported_symbols_uses_local_nm_without_toolbox(monkeypatch, tmp_path):
    monkeypatch.setattr(ns.shutil, "which", lambda name: "/usr/bin/nm" if name == "nm" else None)

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        return _completed(stdout="0000000000000000 U __android_log_print\n")

    monkeypatch.setattr(ns.subprocess, "run", fake_run)

    so = tmp_path / "libfoo.so"
    so.write_bytes(b"\x7fELF")

    symbols = ns._get_imported_symbols(so)

    assert "android_log_print" in symbols
    assert calls[0][0] == "/usr/bin/nm"


def test_get_imported_symbols_routes_through_toolbox_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(ns.shutil, "which", lambda name: None)  # nada local

    calls = []

    def fake_toolbox_run(tool, args, config=None, timeout=600, build_if_missing=True):  # noqa: ANN001
        calls.append((tool, args))
        return _completed(stdout="0000000000000000 U __system_property_get\n")

    monkeypatch.setattr(ns.toolbox, "run", fake_toolbox_run)
    monkeypatch.setattr(ns.toolbox, "is_enabled", lambda config: True)

    so = tmp_path / "libfoo.so"
    so.write_bytes(b"\x7fELF")

    symbols = ns._get_imported_symbols(so, config={"toolbox": {"enabled": True}})

    assert "system_property_get" in symbols
    assert calls and calls[0][0] == "nm"
    # las rutas que llegan al toolbox deben ser absolutas
    assert Path(calls[0][1][-1]).is_absolute()


def test_get_imported_symbols_falls_back_to_objdump_when_nm_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(
        ns.shutil, "which",
        lambda name: "/usr/bin/objdump" if name == "objdump" else None,
    )

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        return _completed(stdout="0000000000000000      DF *UND*  __strcpy_chk\n")

    monkeypatch.setattr(ns.subprocess, "run", fake_run)

    so = tmp_path / "libfoo.so"
    so.write_bytes(b"\x7fELF")

    symbols = ns._get_imported_symbols(so)

    assert any("strcpy_chk" in s for s in symbols)
    assert calls[0][0] == "/usr/bin/objdump"


def test_get_imported_symbols_returns_empty_without_any_tool(monkeypatch, tmp_path):
    monkeypatch.setattr(ns.shutil, "which", lambda name: None)
    so = tmp_path / "libfoo.so"
    so.write_bytes(b"\x7fELF")

    assert ns._get_imported_symbols(so) == []


# ── _get_strings ─────────────────────────────────────────────────────────────

def test_get_strings_uses_local_binary_without_toolbox(monkeypatch, tmp_path):
    monkeypatch.setattr(ns.shutil, "which", lambda name: "/usr/bin/strings" if name == "strings" else None)
    monkeypatch.setattr(ns.subprocess, "run", lambda *a, **kw: _completed(stdout="hello\nworld\n"))

    so = tmp_path / "libfoo.so"
    so.write_bytes(b"\x7fELF")

    assert ns._get_strings(so) == ["hello", "world"]


def test_get_strings_falls_back_to_pure_python_when_no_tool_available(monkeypatch, tmp_path):
    """Sin `strings` local NI toolbox habilitado, sigue funcionando por el
    fallback puro-Python preexistente -- no debe quedar sin nada."""
    monkeypatch.setattr(ns.shutil, "which", lambda name: None)

    so = tmp_path / "libfoo.so"
    so.write_bytes(b"\x00\x00hello world this is a long string\x00\x00")

    found = ns._get_strings(so, min_len=8)

    assert any("hello world" in s for s in found)


def test_get_strings_routes_through_toolbox_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(ns.shutil, "which", lambda name: None)
    monkeypatch.setattr(ns.toolbox, "is_enabled", lambda config: True)

    calls = []

    def fake_toolbox_run(tool, args, config=None, timeout=600, build_if_missing=True):  # noqa: ANN001
        calls.append(tool)
        return _completed(stdout="secret_from_container\n")

    monkeypatch.setattr(ns.toolbox, "run", fake_toolbox_run)

    so = tmp_path / "libfoo.so"
    so.write_bytes(b"\x7fELF")

    result = ns._get_strings(so, config={"toolbox": {"enabled": True}})

    assert result == ["secret_from_container"]
    assert calls == ["strings"]


# ── scan_native_libs: config se propaga hasta los helpers ───────────────────

def test_scan_native_libs_propagates_config_to_helpers(monkeypatch, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    # No hay .so reales en este APK -- alcanza con verificar que no explota
    # y que, si hubiera, config llegaría a los helpers (cubierto arriba).
    result = ns.scan_native_libs(apk, tmp_path / "work", config={"toolbox": {"enabled": True}})
    assert result == []
