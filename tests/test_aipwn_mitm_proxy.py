"""Tests de nutcracker_core/plugins/aipwn/query_tools.py::setup_mitm_proxy /
teardown_mitm_proxy -- el pipeline clásico de proxy (Burp/mitmproxy): instala
la CA del operador en el trust store del sistema (device rooteado, confirmado
por el usuario), setea el proxy global del device, y corre el bypass
heurístico de pinning. Pedido explícito del usuario: "quiero que el agente
tenga la capacidad de hacer todo eso dependiendo lo que necesite" (captura
pasiva, MITM activo, Y proxy clásico)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from nutcracker_core.plugins.aipwn.frida_agent_tools import ToolContext
from nutcracker_core.plugins.aipwn.query_tools import (
    DeviceIO,
    _check_device_ready,
    dispatch_query_tool,
    tool_setup_mitm_proxy,
    tool_teardown_mitm_proxy,
)


def _make_ctx(tmp_path: Path, **overrides) -> ToolContext:
    kwargs = dict(
        package="com.example.app", decompiled_dir=None, analysis_result=None,
        serial=None, capture_seconds=15, scripts_dir=tmp_path,
        on_frida_run=lambda script_js, rationale, iteration: None,
    )
    kwargs.update(overrides)
    return ToolContext(**kwargs)


class _RecordingDevice:
    """Duck-types como DeviceIO (incluye is_relay, que _check_device_ready
    necesita en el camino de dispatch_query_tool) grabando cada shell()."""

    is_relay = False

    def __init__(self):
        self.calls: list[str] = []

    def shell(self, cmd: str, timeout: float = 30.0) -> str:
        self.calls.append(cmd)
        if cmd.startswith("ls "):
            # Simula que el archivo quedó instalado -- verificación post-cp.
            return cmd.split()[-1] + "\n"
        return ""


def test_teardown_mitm_proxy_without_device_reports_error(tmp_path):
    result = json.loads(tool_teardown_mitm_proxy(device=None))
    assert "error" in result


def test_teardown_mitm_proxy_removes_global_setting():
    device = _RecordingDevice()
    result = json.loads(tool_teardown_mitm_proxy(device))
    assert result["proxy_removed"] is True
    assert "settings delete global http_proxy" in device.calls[0]


def test_setup_mitm_proxy_without_device_reports_error(tmp_path):
    ctx = _make_ctx(tmp_path)
    result = json.loads(tool_setup_mitm_proxy(ctx, device=None, proxy="1.2.3.4:8080"))
    assert "error" in result


def test_setup_mitm_proxy_missing_proxy_reports_clear_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # sin config.yaml -> sin default de proxy
    ctx = _make_ctx(tmp_path)
    device = _RecordingDevice()

    result = json.loads(tool_setup_mitm_proxy(ctx, device, proxy="", install_ca=False, bypass_pinning=False))

    assert "error" in result
    assert "proxy" in result["error"]
    assert not device.calls  # no se llegó a tocar el device sin saber el proxy


def test_setup_mitm_proxy_sets_global_proxy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctx = _make_ctx(tmp_path)
    device = _RecordingDevice()

    result = json.loads(tool_setup_mitm_proxy(
        ctx, device, proxy="192.168.1.50:8080", install_ca=False, bypass_pinning=False,
    ))

    assert result["proxy"] == "192.168.1.50:8080"
    assert any("settings put global http_proxy 192.168.1.50:8080" in c for c in device.calls)
    assert result["ca_installed"] is False
    assert result["bypass_ran"] is False


def test_setup_mitm_proxy_installs_ca_with_openssl_hash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

    def fake_run(cmd, **kw):
        assert cmd[0] == "openssl"
        return type("R", (), {"stdout": "9a5ba575\n", "returncode": 0})()

    monkeypatch.setattr("subprocess.run", fake_run)

    ctx = _make_ctx(tmp_path)
    device = _RecordingDevice()

    result = json.loads(tool_setup_mitm_proxy(
        ctx, device, proxy="1.2.3.4:8080", ca_cert_path=str(ca_path), bypass_pinning=False,
    ))

    assert result["ca_installed"] is True
    assert result["ca_error"] is None
    assert any("9a5ba575.0" in c for c in device.calls)
    # el cert se sube en base64 vía shell -- no hay ningún push/RPC nuevo
    assert any("base64 -d" in c for c in device.calls)


def test_setup_mitm_proxy_ca_missing_file_reports_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctx = _make_ctx(tmp_path)
    device = _RecordingDevice()

    result = json.loads(tool_setup_mitm_proxy(
        ctx, device, proxy="1.2.3.4:8080", ca_cert_path=str(tmp_path / "no_existe.pem"),
        bypass_pinning=False,
    ))

    assert result["ca_installed"] is False
    assert "no encontrado" in result["ca_error"]


def test_setup_mitm_proxy_runs_pinning_bypass(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    frida_calls = []

    def fake_on_frida_run(script_js, rationale, iteration):
        frida_calls.append((rationale, iteration))
        from nutcracker_core.plugins.aipwn.frida_capture import FridaRunResult
        return FridaRunResult(iteration=iteration, script_js=script_js, output="bypass ok", logcat="")

    class _FakeAnalysisResult:
        package = "com.example.app"
        results = []

    ctx = _make_ctx(tmp_path, on_frida_run=fake_on_frida_run, analysis_result=_FakeAnalysisResult())
    device = _RecordingDevice()

    result = json.loads(tool_setup_mitm_proxy(
        ctx, device, proxy="1.2.3.4:8080", install_ca=False, frida_iteration=5,
    ))

    assert result["bypass_ran"] is True
    assert len(frida_calls) == 1
    assert frida_calls[0][1] == 5  # frida_iteration se propagó


def test_setup_mitm_proxy_reads_defaults_from_config(tmp_path, monkeypatch):
    # load_config() sin path usa una ruta ABSOLUTA fija (relativa al paquete,
    # no al cwd -- ver nutcracker_core/config.py::DEFAULT_CONFIG_PATH), así
    # que un config.yaml en tmp_path no lo intercepta -- hay que mockear
    # load_config directo para simular el bloque aipwn.mitm.
    monkeypatch.setattr(
        "nutcracker_core.config.load_config",
        lambda *a, **kw: {"aipwn": {"mitm": {"proxy": "10.0.0.5:8081"}}},
    )
    ctx = _make_ctx(tmp_path)
    device = _RecordingDevice()

    result = json.loads(tool_setup_mitm_proxy(ctx, device, install_ca=False, bypass_pinning=False))

    assert result["proxy"] == "10.0.0.5:8081"


# ── Wiring: dispatch_query_tool + preflight de relay ────────────────────────

def test_dispatch_query_tool_routes_mitm_tools(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctx = _make_ctx(tmp_path)
    device = _RecordingDevice()

    result = json.loads(dispatch_query_tool(
        ctx, "setup_mitm_proxy", {"proxy": "1.2.3.4:8080", "install_ca": False, "bypass_pinning": False},
        db_path=str(tmp_path / "x.db"), device=device,
    ))
    assert result["proxy"] == "1.2.3.4:8080"

    result2 = json.loads(dispatch_query_tool(
        ctx, "teardown_mitm_proxy", {}, db_path=str(tmp_path / "x.db"), device=device,
    ))
    assert result2["proxy_removed"] is True


def test_check_device_ready_relay_mitm_and_capture_tools_are_ready(tmp_path):
    ctx = ToolContext(
        package="com.example.app", decompiled_dir=None, analysis_result=None,
        serial=None, frida_host="127.0.0.1:12345", capture_seconds=15, scripts_dir=Path("/tmp"),
        on_frida_run=lambda script_js, rationale, iteration: None,
    )
    device = DeviceIO(relay_session=object(), loop=object())

    for name in ("capture_traffic", "intercept_and_modify", "setup_mitm_proxy", "teardown_mitm_proxy"):
        assert _check_device_ready(ctx, device, name=name) is None, f"{name} debería estar listo en relay"
