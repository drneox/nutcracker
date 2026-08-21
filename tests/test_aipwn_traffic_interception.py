"""Tests de las tools nuevas de intercepción de tráfico en
nutcracker_core/plugins/aipwn/frida_agent_tools.py: ``capture_traffic``
(captura pasiva Java+nativa, cubre Flutter/React Native) e
``intercept_and_modify`` (MITM activo). Pedido del usuario, 2026-08-21: el
co-piloto no podía ver tráfico de una app Flutter real (com.example.
example_organizer) porque `sniff_network_calls` solo hookea el stack Java.

Ambas comparten el mismo helper de resolución de símbolos que ya se
estandarizó por el bug de Frida 17 (Module.findExportByName/getExportByName
eliminadas) -- los tests de regresión estática cubren que ninguna de las dos
reintroduzca el patrón roto."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from nutcracker_core.plugins.aipwn.frida_agent import _FRIDA_SLOT_TOOL_NAMES
from nutcracker_core.plugins.aipwn.frida_agent_tools import (
    TOOL_SCHEMAS,
    ToolContext,
    dispatch_tool,
    tool_capture_traffic,
    tool_intercept_and_modify,
)


def _make_ctx(tmp_path: Path, **overrides) -> ToolContext:
    kwargs = dict(
        package="com.example.app", decompiled_dir=None, analysis_result=None,
        serial=None, capture_seconds=15, scripts_dir=tmp_path,
        on_frida_run=lambda script_js, rationale, iteration: None,
    )
    kwargs.update(overrides)
    return ToolContext(**kwargs)


# ── Regresión estática: nunca reintroducir la API de Frida eliminada ────────

def test_capture_traffic_script_never_uses_removed_frida17_api(tmp_path):
    ctx = _make_ctx(tmp_path)
    with patch(
        "nutcracker_core.plugins.aipwn.frida_agent_tools._run_frida_query",
        return_value="",
    ) as mock_query:
        tool_capture_traffic(ctx, duration_seconds=5)
    script = mock_query.call_args[0][1]
    assert "Module.findExportByName(" not in script
    assert "Module.getExportByName(" not in script
    assert "Module.findGlobalExportByName" in script
    assert "Process.findModuleByName" in script


def test_intercept_and_modify_script_never_uses_removed_frida17_api(tmp_path):
    captured = {}

    def fake_on_frida_run(script_js, rationale, iteration):
        captured["script"] = script_js
        from nutcracker_core.plugins.aipwn.frida_capture import FridaRunResult
        return FridaRunResult(iteration=iteration, script_js=script_js, output="", logcat="")

    ctx = _make_ctx(tmp_path, on_frida_run=fake_on_frida_run)
    tool_intercept_and_modify(ctx, rules=[{"match": "login", "action": "log"}], duration_seconds=5)

    assert "Module.findExportByName(" not in captured["script"]
    assert "Module.getExportByName(" not in captured["script"]
    assert "Module.findGlobalExportByName" in captured["script"]


# ── capture_traffic: parseo de eventos ──────────────────────────────────────

def test_capture_traffic_parses_java_and_native_events(tmp_path):
    raw_output = "\n".join([
        '[CAP-JAVA-REQ] ' + json.dumps({"method": "POST", "url": "https://api.example.com/login", "headers": "Auth: x", "body": '{"user":"a"}'}),
        '[CAP-JAVA-RESP] ' + json.dumps({"url": "https://api.example.com/login", "code": 200, "headers": "", "body": '{"token":"t"}'}),
        '[CAP-TLS-OUT] ' + json.dumps({"lib": "libflutter.so", "len": 42, "data": "POST /api/v1/app/oauth/login HTTP/1.1"}),
        '[CAP-TLS-IN] ' + json.dumps({"lib": "libflutter.so", "len": 30, "data": "HTTP/1.1 200 OK"}),
        "[capture] hooks installed",
    ])
    ctx = _make_ctx(tmp_path)
    with patch(
        "nutcracker_core.plugins.aipwn.frida_agent_tools._run_frida_query",
        return_value=raw_output,
    ):
        result = json.loads(tool_capture_traffic(ctx, duration_seconds=10))

    assert result["event_count"] == 4
    kinds = {e["kind"] for e in result["events"]}
    assert kinds == {"java_request", "java_response", "tls_out", "tls_in"}
    java_req = next(e for e in result["events"] if e["kind"] == "java_request")
    assert java_req["url"] == "https://api.example.com/login"
    tls_out = next(e for e in result["events"] if e["kind"] == "tls_out")
    assert "oauth/login" in tls_out["data"]


def test_capture_traffic_no_events_reports_raw_tail(tmp_path):
    ctx = _make_ctx(tmp_path)
    with patch(
        "nutcracker_core.plugins.aipwn.frida_agent_tools._run_frida_query",
        return_value="Frida 17.16.4\nsome banner\n",
    ):
        result = tool_capture_traffic(ctx, duration_seconds=5)

    assert "No traffic captured" in result
    assert "banner" in result


def test_capture_traffic_clamps_duration(tmp_path):
    ctx = _make_ctx(tmp_path)
    with patch(
        "nutcracker_core.plugins.aipwn.frida_agent_tools._run_frida_query",
        return_value="",
    ) as mock_query:
        tool_capture_traffic(ctx, duration_seconds=999)
    assert mock_query.call_args.kwargs["timeout"] == 60


# ── intercept_and_modify ──────────────────────────────────────────────────

def test_intercept_and_modify_embeds_rules_and_consumes_frida_run(tmp_path):
    calls = []

    def fake_on_frida_run(script_js, rationale, iteration):
        calls.append((script_js, rationale, iteration))
        from nutcracker_core.plugins.aipwn.frida_capture import FridaRunResult
        return FridaRunResult(iteration=iteration, script_js=script_js, output="hooks installed", logcat="")

    ctx = _make_ctx(tmp_path, on_frida_run=fake_on_frida_run)
    rules = [{"match": "login", "action": "replace_response_body", "value": '{"pwned":true}'}]

    result = json.loads(tool_intercept_and_modify(ctx, rules=rules, duration_seconds=20, frida_iteration=3))

    assert len(calls) == 1
    script_js, rationale, iteration = calls[0]
    assert "replace_response_body" in script_js
    assert "pwned" in script_js  # el valor de la regla quedó embebido en el script
    assert iteration == 3
    assert "iteration" in result  # forma de FridaRunResult.to_dict()


def test_intercept_and_modify_documents_native_length_limitation(tmp_path):
    """La descripción de la tool (lo que ve el LLM) debe advertir la
    limitación de longitud en el nivel nativo -- ver plan.md."""
    schema = next(s for s in TOOL_SCHEMAS if s["function"]["name"] == "intercept_and_modify")
    assert "ORIGINAL buffer length" in schema["function"]["description"]


# ── Wiring: dispatch_tool + _FRIDA_SLOT_TOOL_NAMES (agente autónomo) ────────

def test_dispatch_tool_routes_capture_traffic(tmp_path):
    ctx = _make_ctx(tmp_path)
    with patch(
        "nutcracker_core.plugins.aipwn.frida_agent_tools._run_frida_query",
        return_value="",
    ):
        result, extra = dispatch_tool(ctx, "capture_traffic", {"duration_seconds": 5}, frida_iteration=1)
    assert extra is None
    assert "No traffic captured" in result


def test_dispatch_tool_routes_intercept_and_modify_with_iteration(tmp_path):
    calls = []

    def fake_on_frida_run(script_js, rationale, iteration):
        calls.append(iteration)
        from nutcracker_core.plugins.aipwn.frida_capture import FridaRunResult
        return FridaRunResult(iteration=iteration, script_js=script_js, output="", logcat="")

    ctx = _make_ctx(tmp_path, on_frida_run=fake_on_frida_run)
    dispatch_tool(ctx, "intercept_and_modify", {"rules": [{"action": "log"}]}, frida_iteration=7)

    assert calls == [7]


def test_frida_slot_tool_names_gates_intercept_and_modify():
    """El loop del agente autónomo (frida_agent.py::FridaAgent.run) debe
    respetar max_frida_runs también para intercept_and_modify -- no solo
    para run_frida_script -- porque también corre vía ctx.on_frida_run."""
    assert "run_frida_script" in _FRIDA_SLOT_TOOL_NAMES
    assert "intercept_and_modify" in _FRIDA_SLOT_TOOL_NAMES
    assert "capture_traffic" not in _FRIDA_SLOT_TOOL_NAMES  # no consume slot
