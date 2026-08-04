"""Tests de FridaAgent con resume_state (botón "+N iteraciones" del dashboard).

Solo ejercita el constructor -- FridaAgent.run() necesita un LLM real/mockeado
a fondo (LLMClient.chat, TOOL_SCHEMAS, etc.), fuera de alcance acá. Lo que
importa verificar sin eso: que resume_state efectivamente reemplaza la
conversación desde cero por la guardada, y que el presupuesto de iteraciones
se extiende relativo a donde se cortó (no se resetea al default).
"""

from __future__ import annotations

from pathlib import Path

from nutcracker_core.plugins.aipwn.frida_agent import FridaAgent


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


def test_without_resume_state_builds_a_fresh_conversation(tmp_path):
    agent = _make_agent(tmp_path)

    assert agent.iteration == 0
    assert agent.frida_runs_used == 0
    assert agent.max_llm_iterations == 30
    assert agent.messages[0]["role"] == "system"
    # el mensaje inicial con contexto de la app se agrega siempre
    assert any("com.example.app" in str(m.get("content", "")) for m in agent.messages)


def test_with_resume_state_restores_the_saved_conversation_verbatim(tmp_path):
    saved_messages = [
        {"role": "system", "content": "custom system prompt from a previous session"},
        {"role": "user", "content": "previous task description"},
        {"role": "assistant", "content": "reasoning that got cut off"},
    ]
    resume_state = {
        "messages": saved_messages,
        "frida_runs_used": 2,
        "iteration": 31,
        "saved_at": "2026-08-03T21:00:00+00:00",
    }

    agent = _make_agent(tmp_path, resume_state=resume_state, extra_iterations=5)

    # la conversación es EXACTAMENTE la guardada -- no se reconstruye el
    # prompt inicial ni se vuelve a inyectar memoria encima.
    assert agent.messages == saved_messages
    assert agent.frida_runs_used == 2
    assert agent.iteration == 31


def test_with_resume_state_extends_budget_relative_to_where_it_stopped(tmp_path):
    """El caso central del pedido: "darle 5 iteraciones más" -- el tope nuevo
    debe ser iteración_guardada + extra, no volver al default de config."""
    resume_state = {"messages": [{"role": "system", "content": "x"}], "frida_runs_used": 0, "iteration": 31}

    agent = _make_agent(tmp_path, resume_state=resume_state, extra_iterations=5,
                         max_llm_iterations=30)  # el default de config, ignorado al reanudar

    assert agent.max_llm_iterations == 36  # 31 + 5, no 30+5 ni 30


def test_with_resume_state_extra_iterations_has_a_floor_of_one(tmp_path):
    resume_state = {"messages": [{"role": "system", "content": "x"}], "frida_runs_used": 0, "iteration": 10}

    agent = _make_agent(tmp_path, resume_state=resume_state, extra_iterations=0)

    # extra_iterations=0 no debe dejar el agente sin ningún margen para correr
    assert agent.max_llm_iterations > agent.iteration


def test_resume_state_with_missing_keys_defaults_safely(tmp_path):
    """Un resume_state incompleto (p.ej. archivo viejo de un formato anterior)
    no debe crashear -- debe caer a 0 para los contadores ausentes."""
    agent = _make_agent(tmp_path, resume_state={"messages": []}, extra_iterations=5)

    assert agent.frida_runs_used == 0
    assert agent.iteration == 0
    assert agent.max_llm_iterations == 5
