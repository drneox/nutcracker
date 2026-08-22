"""Tests de nutcracker_core/plugins/aipwn/query_agent.py::QueryAgent -- el
loop ReAct conversacional del co-piloto de pentest interactivo. A diferencia
de FridaAgent (bypass autónomo con budget fijo), QueryAgent responde un turno
por mensaje del operador y termina en cuanto el LLM no pide más tools.

``LLMClient.chat`` se monkeypatchea para controlar exactamente qué responde
el LLM en cada paso, sin llamar a ningún proveedor real."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from nutcracker_core.plugins.aipwn.frida_agent import _LLMResponse, _ToolCall
from nutcracker_core.plugins.aipwn.query_agent import QueryAgent


def _make_agent(tmp_path: Path, device=None) -> QueryAgent:
    return QueryAgent(
        package="com.example.app",
        decompiled_dir=None,
        runtime_dump_dir=None,
        analysis_result=None,
        llm_config={"provider": "openai", "model": "gpt-4o", "api_key": "sk-test"},
        db_path=str(tmp_path / "test.db"),
        device=device,
    )


def _text_response(text: str) -> _LLMResponse:
    return _LLMResponse(
        content=text, thinking="", tool_calls=[],
        raw_message={"role": "assistant", "content": text, "tool_calls": None},
    )


def _tool_call_response(name: str, arguments: dict, call_id: str = "call_1") -> _LLMResponse:
    return _LLMResponse(
        content="", thinking="", tool_calls=[_ToolCall(id=call_id, name=name, arguments=arguments)],
        raw_message={"role": "assistant", "content": "", "tool_calls": [
            {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}},
        ]},
    )


def test_ask_with_pure_text_response_emits_single_assistant_event(tmp_path):
    agent = _make_agent(tmp_path)
    with patch.object(agent.llm, "chat", return_value=_text_response("no hay device conectado ahora mismo")):
        events = list(agent.ask("¿qué componentes exportados tiene?"))

    assert len(events) == 1
    assert events[0].kind == "assistant"
    assert "no hay device" in events[0].data["text"]


def test_ask_runs_tool_then_final_answer(tmp_path):
    """Secuencia típica: LLM pide list_components, ve el resultado, y en el
    siguiente paso responde texto -- sin más tool_calls, el turno termina."""
    agent = _make_agent(tmp_path)
    responses = [
        _tool_call_response("list_components", {}),
        _text_response("Encontré un provider exportado sin permiso: LeakyProvider."),
    ]
    with patch.object(agent.llm, "chat", side_effect=responses):
        events = list(agent.ask("¿qué componentes exportados tiene?"))

    kinds = [e.kind for e in events]
    assert kinds == ["tool", "tool_result", "assistant"]
    assert events[0].data["name"] == "list_components"
    assert "LeakyProvider" in events[2].data["text"]

    # El resultado de la tool quedó en el historial como mensaje role=tool
    tool_msgs = [m for m in agent.messages if m.get("role") == "tool"]
    assert len(tool_msgs) == 1


def test_ask_does_not_call_frida_tools_when_device_is_none(tmp_path):
    """Con device=None, una tool dinámica (ui_tap) debe devolver su propio
    error de 'no hay dispositivo' -- el agente sigue funcionando, no crashea."""
    agent = _make_agent(tmp_path, device=None)
    responses = [
        _tool_call_response("ui_tap", {"x": 10, "y": 20}),
        _text_response("No pude tocar la pantalla porque no hay dispositivo conectado."),
    ]
    with patch.object(agent.llm, "chat", side_effect=responses):
        events = list(agent.ask("tocá el botón de login"))

    tool_result = next(e for e in events if e.kind == "tool_result")
    assert "error" in tool_result.data["result"]


def test_ask_stops_after_max_steps_without_looping_forever(tmp_path):
    agent = _make_agent(tmp_path)

    def _always_calls_tool(*args, **kwargs):
        return _tool_call_response("get_app_analysis", {})

    with patch.object(agent.llm, "chat", side_effect=_always_calls_tool):
        events = list(agent.ask("segui investigando", max_steps=3))

    assert events[-1].kind == "error"
    assert "3 pasos" in events[-1].data["text"]


def test_ask_llm_error_yields_error_event_and_stops(tmp_path):
    agent = _make_agent(tmp_path)
    with patch.object(agent.llm, "chat", side_effect=RuntimeError("boom")):
        events = list(agent.ask("hola"))

    assert len(events) == 1
    assert events[0].kind == "error"
    assert "boom" in events[0].data["text"]


# ── _execute_frida: wiring de shell_fn/logcat_fn en modo relay ─────────────
#
# Bug encontrado en vivo (2026-08-21): en modo relay no hay ningún `adb`
# local con ruta al device -- el mecanismo que lo arregla para jobs de la
# cola (toolbox/relay_adb_shim/adb, PATH del SUBPROCESO) nunca se activa acá
# porque QueryAgent corre in-process. _execute_frida debe inyectar
# shell_fn/logcat_fn (respaldados por DeviceIO -> RPC del relay) en ese caso,
# y NO inyectar nada en modo serial/sin device (comportamiento de siempre).

def test_execute_frida_wires_shell_fn_in_relay_mode(tmp_path):
    from nutcracker_core.plugins.aipwn.query_tools import DeviceIO

    device = DeviceIO(relay_session=object(), loop=object())
    agent = _make_agent(tmp_path, device=device)

    captured = {}

    def fake_launch(**kwargs):
        captured.update(kwargs)
        from nutcracker_core.plugins.aipwn.frida_capture import FridaRunResult
        return FridaRunResult(iteration=1, script_js="", output="", logcat="")

    with patch("nutcracker_core.plugins.aipwn.frida_capture.launch_frida_capture", fake_launch):
        agent._execute_frida("console.log(1)", "test", 1)

    assert captured["shell_fn"] == device.shell
    assert callable(captured["logcat_fn"])


def test_execute_frida_does_not_wire_shell_fn_without_relay(tmp_path):
    agent = _make_agent(tmp_path, device=None)  # sin device -- modo estático/serial

    captured = {}

    def fake_launch(**kwargs):
        captured.update(kwargs)
        from nutcracker_core.plugins.aipwn.frida_capture import FridaRunResult
        return FridaRunResult(iteration=1, script_js="", output="", logcat="")

    with patch("nutcracker_core.plugins.aipwn.frida_capture.launch_frida_capture", fake_launch):
        agent._execute_frida("console.log(1)", "test", 1)

    assert captured["shell_fn"] is None
    assert captured["logcat_fn"] is None


def test_second_ask_call_continues_same_conversation(tmp_path):
    """Cada ``ask()`` agrega al mismo self.messages -- la conversación
    persiste entre turnos (a diferencia de una request/response sin estado)."""
    agent = _make_agent(tmp_path)
    with patch.object(agent.llm, "chat", return_value=_text_response("primera respuesta")):
        list(agent.ask("primer mensaje"))
    with patch.object(agent.llm, "chat", return_value=_text_response("segunda respuesta")):
        list(agent.ask("segundo mensaje"))

    user_messages = [m["content"] for m in agent.messages if m.get("role") == "user"]
    assert user_messages == ["primer mensaje", "segundo mensaje"]
