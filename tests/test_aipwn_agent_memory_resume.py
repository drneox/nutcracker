"""Tests de nutcracker_core/plugins/aipwn/agent_memory.py -- estado de
reanudación (botón "+N iteraciones" del dashboard).

Distinto de save_session()/load_sessions() (un resumen para sesiones nuevas):
esto persiste la conversación completa para poder continuarla literalmente
donde quedó -- ver frida_agent.py::FridaAgent.run().
"""

from __future__ import annotations

from nutcracker_core.plugins.aipwn import agent_memory


def test_load_resume_state_none_when_nothing_saved(tmp_path):
    assert agent_memory.load_resume_state("com.example.app", memory_dir=tmp_path) is None
    assert not agent_memory.has_resume_state("com.example.app", memory_dir=tmp_path)


def test_save_and_load_resume_state_roundtrip(tmp_path):
    messages = [
        {"role": "system", "content": "..."},
        {"role": "user", "content": "..."},
        {"role": "assistant", "content": "thinking...", "tool_calls": []},
    ]
    agent_memory.save_resume_state(
        "com.example.app", messages=messages, frida_runs_used=2, iteration=31,
        memory_dir=tmp_path,
    )

    assert agent_memory.has_resume_state("com.example.app", memory_dir=tmp_path)
    state = agent_memory.load_resume_state("com.example.app", memory_dir=tmp_path)

    assert state["messages"] == messages
    assert state["frida_runs_used"] == 2
    assert state["iteration"] == 31
    assert "saved_at" in state


def test_save_resume_state_creates_memory_dir_if_missing(tmp_path):
    memory_dir = tmp_path / "nested" / "aipwn_memory"
    assert not memory_dir.exists()

    agent_memory.save_resume_state(
        "com.example.app", messages=[], frida_runs_used=0, iteration=1,
        memory_dir=memory_dir,
    )

    assert memory_dir.exists()
    assert agent_memory.has_resume_state("com.example.app", memory_dir=memory_dir)


def test_clear_resume_state_removes_the_file(tmp_path):
    agent_memory.save_resume_state(
        "com.example.app", messages=[], frida_runs_used=0, iteration=1,
        memory_dir=tmp_path,
    )
    assert agent_memory.has_resume_state("com.example.app", memory_dir=tmp_path)

    agent_memory.clear_resume_state("com.example.app", memory_dir=tmp_path)

    assert not agent_memory.has_resume_state("com.example.app", memory_dir=tmp_path)


def test_clear_resume_state_is_safe_when_nothing_to_clear(tmp_path):
    agent_memory.clear_resume_state("com.never.saved", memory_dir=tmp_path)  # no debe lanzar


def test_load_resume_state_survives_corrupt_file(tmp_path):
    memory_dir = tmp_path
    memory_dir.mkdir(parents=True, exist_ok=True)
    (memory_dir / "com.example.app_resume_state.json").write_text("{not valid json")

    assert agent_memory.load_resume_state("com.example.app", memory_dir=memory_dir) is None


def test_resume_state_is_isolated_per_package(tmp_path):
    agent_memory.save_resume_state(
        "com.app.a", messages=[{"role": "user", "content": "a"}], frida_runs_used=1, iteration=5,
        memory_dir=tmp_path,
    )
    agent_memory.save_resume_state(
        "com.app.b", messages=[{"role": "user", "content": "b"}], frida_runs_used=2, iteration=9,
        memory_dir=tmp_path,
    )

    state_a = agent_memory.load_resume_state("com.app.a", memory_dir=tmp_path)
    state_b = agent_memory.load_resume_state("com.app.b", memory_dir=tmp_path)

    assert state_a["messages"] == [{"role": "user", "content": "a"}]
    assert state_b["messages"] == [{"role": "user", "content": "b"}]
    assert state_a["iteration"] == 5
    assert state_b["iteration"] == 9
