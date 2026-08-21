"""Tests de nutcracker_core/plugins/aipwn/frida_agent_tools.py -- el soporte
de modo relay en ``_run_frida_query`` (backend de 8 tools de introspección/
acción runtime: enumerate_runtime_classes, get_class_methods,
get_loaded_native_libs, enumerate_native_exports, resolve_native_symbol,
probe_security_violations, sniff_network_calls, trace_method_execution) y en
``_run_frida_spawngated`` (backend de run_frida_script con spawn_gated=True).

Contexto (2026-08-21): ambas funciones shelleaban a un `adb` LOCAL sin ruta
al device cuando el co-piloto de consulta corre en modo relay (celular
conectado por WebUSB al navegador, no por USB al host del dashboard).
``_run_frida_query`` lo hacía por un gate que en realidad nunca usaba
(bug real, no solo limitación); ``_run_frida_spawngated`` sí lo necesitaba
de verdad para logcat/pidof, así que ahora acepta un canal alternativo
(``ToolContext.device_shell``/``device_logcat``) inyectado por QueryAgent en
modo relay."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from nutcracker_core.plugins.aipwn.frida_agent_tools import (
    ToolContext,
    _run_frida_query,
    _run_frida_spawngated,
)


def _make_ctx(frida_host=None, serial=None, device_shell=None, device_logcat=None, capture_seconds=0) -> ToolContext:
    return ToolContext(
        package="com.example.app", decompiled_dir=None, analysis_result=None,
        serial=serial, frida_host=frida_host, capture_seconds=capture_seconds,
        scripts_dir=Path("/tmp"), on_frida_run=lambda *a, **kw: None,
        device_shell=device_shell, device_logcat=device_logcat,
    )


# ── _run_frida_query: el gate de adb solo tenía sentido para -U/-D ─────────

def test_run_frida_query_skips_adb_gate_with_frida_host(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None if name == "adb" else "/usr/bin/frida")
    ctx = _make_ctx(frida_host="127.0.0.1:12345")

    with patch("subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])  # EOF inmediato
        mock_popen.return_value = mock_proc

        result = _run_frida_query(ctx, "console.log(1)", timeout=1)

    # No debe cortar temprano con "ERROR: adb no encontrado" -- debe llegar a
    # intentar lanzar frida de verdad (Popen se llamó).
    assert "adb no encontrado" not in result
    assert mock_popen.called


def test_run_frida_query_still_requires_adb_without_frida_host(monkeypatch):
    """Sin frida_host (modo -U/-D, serial USB directo o nada) -- comportamiento
    de siempre, sin cambios: si no hay adb, corta temprano."""
    monkeypatch.setattr("shutil.which", lambda name: None)
    ctx = _make_ctx(frida_host=None, serial=None)

    with patch("subprocess.Popen") as mock_popen:
        result = _run_frida_query(ctx, "console.log(1)", timeout=1)

    assert result == "ERROR: adb no encontrado"
    mock_popen.assert_not_called()


# ── _run_frida_spawngated: device_shell/device_logcat reemplazan a adb ─────

def _fake_frida_device():
    device = MagicMock()
    device.spawn.return_value = 1234
    session = MagicMock()
    device.attach.return_value = session
    script = MagicMock()
    session.create_script.return_value = script
    return device


def test_run_frida_spawngated_with_device_shell_never_touches_subprocess():
    shell_calls = []
    logcat_calls = []

    def fake_shell(cmd: str) -> str:
        shell_calls.append(cmd)
        return "1234" if cmd.startswith("pidof") else ""

    def fake_logcat(duration: float) -> str:
        logcat_calls.append(duration)
        return "09-01 12:00:00.000 W SSL: warning\n"

    ctx = _make_ctx(frida_host="127.0.0.1:12345", device_shell=fake_shell, device_logcat=fake_logcat)

    fake_device = _fake_frida_device()
    with patch("frida.get_device_manager") as mock_mgr, patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen:
        mock_mgr.return_value.add_remote_device.return_value = fake_device

        result = _run_frida_spawngated(ctx, "console.log(1)", iteration=1)

    mock_run.assert_not_called()
    mock_popen.assert_not_called()  # tampoco Popen para logcat -- todo vía device_logcat
    assert any(c.startswith("logcat -c") for c in shell_calls)
    assert any(c.startswith("pidof") for c in shell_calls)
    assert logcat_calls  # se pidió la ventana de logcat vía device_logcat
    assert result.app_running is True
    assert "SSL: warning" in result.logcat


def test_run_frida_spawngated_without_device_shell_keeps_old_behavior(monkeypatch):
    """Sin device_shell (CLI/FridaAgent normal) -- comportamiento de siempre:
    usa _adb_cmd(ctx), que devuelve [] si no hay adb -- no debería tocar
    subprocess.run/Popen para logcat/pidof si no hay adb instalado."""
    monkeypatch.setattr("shutil.which", lambda name: None)
    ctx = _make_ctx(frida_host="127.0.0.1:12345")  # sin device_shell

    fake_device = _fake_frida_device()
    with patch("frida.get_device_manager") as mock_mgr, patch("subprocess.run") as mock_run:
        mock_mgr.return_value.add_remote_device.return_value = fake_device

        result = _run_frida_spawngated(ctx, "console.log(1)", iteration=1)

    mock_run.assert_not_called()  # _adb_cmd(ctx) devolvió [] -- nada que correr
    assert result.app_running is False
