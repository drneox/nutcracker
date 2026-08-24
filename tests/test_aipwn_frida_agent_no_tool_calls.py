"""Tests del nudge-retry cuando el LLM responde sin tool calls.

Cubre el fix de frida_agent.py: antes, UNA respuesta sin tool_calls abortaba
la corrida entera con el mensaje engañoso "Agent did not return a result
within the iteration limit" (visto en vivo, job 18 del 2026-08-24: cortó en
la llamada 11 con max_llm_iterations=40 configurado — el modelo volcó el
script como texto plano en vez de llamar run_frida_script). Ahora se le hace
un nudge y el loop continúa; solo se corta tras _MAX_NO_TOOLCALL_STREAK
respuestas consecutivas sin herramientas, con un mensaje que dice la causa
real.
"""

from __future__ import annotations

from types import SimpleNamespace

import nutcracker_core.plugins.aipwn.frida_agent as fa
from nutcracker_core import i18n
from nutcracker_core.plugins.aipwn.frida_agent import _MAX_NO_TOOLCALL_STREAK, FridaAgent
from nutcracker_core.plugins.aipwn.i18n_strings import STRINGS as _AIPWN_STRINGS

# El registro de strings del plugin ocurre en _init_i18n() al correr por CLI;
# en tests hay que hacerlo a mano o t() devuelve la clave literal.
i18n.register(_AIPWN_STRINGS)


def _make_agent(tmp_path, **kwargs):
    defaults = dict(
        package="com.example.app",
        decompiled_dir=None,
        analysis_result=None,
        config={"llm": {"provider": "openai", "model": "gpt-4o", "api_key": "fake"}, "aipwn": {}},
        serial=None,
        max_frida_runs=5,
        max_llm_iterations=30,
        capture_seconds=15,
        scripts_dir=tmp_path,
    )
    defaults.update(kwargs)
    return FridaAgent(**defaults)


def _resp(content: str, tool_calls: list | None = None):
    """Respuesta mínima del LLM con la forma que espera el loop."""
    return SimpleNamespace(
        raw_message={"role": "assistant", "content": content},
        thinking="",
        content=content,
        tool_calls=tool_calls or [],
    )


def _tc(name: str, arguments: dict):
    return SimpleNamespace(name=name, arguments=arguments, id="call-1")


def _patch_env(monkeypatch, tmp_path, chat_responses):
    """App "instalada", writes contenidos en tmp_path, LLM mockeado."""
    monkeypatch.setattr(fa, "check_app_installed", lambda _adb_args, _pkg: True)
    monkeypatch.chdir(tmp_path)  # reports/ y aipwn_memory/ caen acá, no en el repo
    calls = iter(chat_responses)
    seen = {"n": 0}

    def _fake_chat(messages, tools=None):
        seen["n"] += 1
        return next(calls)

    return _fake_chat, seen


def test_no_tool_call_response_gets_a_nudge_and_the_run_continues(monkeypatch, tmp_path):
    """Una respuesta sin tools ya no aborta: se nudgea y el agente puede
    concluir después (acá con report_failure en la 3ra llamada)."""
    agent = _make_agent(tmp_path)
    fake_chat, seen = _patch_env(monkeypatch, tmp_path, [
        _resp("acá va el script: Java.use(...)"),           # sin tools — nudge 1
        _resp("ahora sí, lo ejecuto"),                      # sin tools — nudge 2
        _resp("me rindo", [_tc("report_failure", {"reason": "no pude"})]),
    ])
    monkeypatch.setattr(agent.llm, "chat", fake_chat)

    result = agent.run()

    assert seen["n"] == 3  # no cortó en la primera respuesta sin tools
    assert result.failure_reason == "no pude"
    # los nudges quedaron en la conversación como mensajes user [SYSTEM]
    nudges = [m for m in agent.messages
              if m.get("role") == "user" and "NO tool call" in str(m.get("content", ""))]
    assert len(nudges) == 2


def test_streak_of_empty_responses_aborts_with_an_honest_message(monkeypatch, tmp_path):
    """_MAX_NO_TOOLCALL_STREAK respuestas sin tools seguidas sí cortan — y el
    mensaje dice la causa real (sin tool calls), no "iteration limit"."""
    agent = _make_agent(tmp_path)
    fake_chat, seen = _patch_env(monkeypatch, tmp_path, [
        _resp(f"texto plano {i}") for i in range(_MAX_NO_TOOLCALL_STREAK + 2)
    ])
    monkeypatch.setattr(agent.llm, "chat", fake_chat)

    result = agent.run()

    assert seen["n"] == _MAX_NO_TOOLCALL_STREAK
    assert result.success is False
    assert "without tool calls" in result.failure_reason
    assert "iteration limit" not in result.failure_reason
    assert result.iterations == _MAX_NO_TOOLCALL_STREAK  # muy por debajo del límite 30
