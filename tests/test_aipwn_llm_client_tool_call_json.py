"""Tests de nutcracker_core/plugins/aipwn/frida_agent.py::LLMClient._do_completion.

Bug encontrado en vivo (job 2809, 2026-08-03): cuando el LLM devuelve JSON
truncado para un tool call (típicamente por quedarse sin max_tokens a mitad de
generar un script_js largo), _do_completion ya detectaba el JSONDecodeError y
caía a ``arguments = {}`` -- pero solo para el _ToolCall usado en el despacho
local. El ``raw_message`` que se guarda en el historial (self.messages)
releía ``tc.function.arguments`` crudo directo del objeto del SDK, sin pasar
por ese try/except, así que el string inválido quedaba guardado ahí para
siempre. Cada llamada siguiente al LLM reenviaba ese mensaje roto en el
historial, y el proveedor (Azure) lo rechazaba con
`"Assistant tool call function.arguments must be valid JSON"` en TODOS los
reintentos por igual -- irrecuperable, mataba el job entero (visto en vivo:
3/3 reintentos fallando idéntico, "Bypass failed").
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from nutcracker_core.plugins.aipwn import frida_agent


def _fake_response(tool_call_arguments: str, tool_call_id: str = "call_1", name: str = "run_frida_script"):
    tc = SimpleNamespace(
        id=tool_call_id,
        function=SimpleNamespace(name=name, arguments=tool_call_arguments),
    )
    message = SimpleNamespace(content=None, tool_calls=[tc], reasoning=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _make_client() -> frida_agent.LLMClient:
    return frida_agent.LLMClient({"provider": "openai", "model": "gpt-4o", "api_key": "sk-test"})


def test_raw_message_keeps_valid_json_arguments_untouched(monkeypatch):
    valid_args = json.dumps({"script_js": "console.log('ok')", "rationale": "test"})
    monkeypatch.setattr(frida_agent, "_llm_completion", lambda **kw: _fake_response(valid_args))

    client = _make_client()
    response = client.chat(messages=[], tools=[])

    stored = response.raw_message["tool_calls"][0]["function"]["arguments"]
    assert json.loads(stored) == json.loads(valid_args)


def test_raw_message_sanitizes_truncated_json_instead_of_storing_it_verbatim(monkeypatch):
    truncated_args = '{"script_js": "Java.perform(function() { Interceptor.attach('  # sin cerrar
    monkeypatch.setattr(frida_agent, "_llm_completion", lambda **kw: _fake_response(truncated_args))

    client = _make_client()
    response = client.chat(messages=[], tools=[])

    stored = response.raw_message["tool_calls"][0]["function"]["arguments"]
    # El punto central del fix: lo que queda en el historial debe ser JSON
    # válido (parseable), nunca el string truncado tal cual vino del modelo --
    # de lo contrario el próximo self.llm.chat(self.messages, ...) reenvía un
    # mensaje estructuralmente inválido y el proveedor lo rechaza siempre.
    assert json.loads(stored) == {}
    assert stored != truncated_args


def test_local_tool_dispatch_and_stored_history_agree_on_sanitized_args(monkeypatch):
    """El _ToolCall usado para despachar la herramienta y lo que se guarda en
    self.messages deben venir de la MISMA sanitización -- no de dos lecturas
    independientes de tc.function.arguments que puedan divergir."""
    truncated_args = '{"pattern": "unterminated'
    monkeypatch.setattr(frida_agent, "_llm_completion", lambda **kw: _fake_response(truncated_args))

    client = _make_client()
    response = client.chat(messages=[], tools=[])

    assert response.tool_calls[0].arguments == {}
    stored = response.raw_message["tool_calls"][0]["function"]["arguments"]
    assert json.loads(stored) == {}
