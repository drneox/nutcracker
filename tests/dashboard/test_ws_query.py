"""Tests de integración de /ws/query/{package} -- el co-piloto de pentest
interactivo (ver plugins/aipwn/query_agent.py::QueryAgent), a través de
FastAPI TestClient. ``LLMClient.chat`` se monkeypatchea para no hacer ninguna
llamada de red real -- estos tests verifican el wiring del WebSocket
(conexión, auth, resolución serial/relay, forwarding de eventos), no el LLM."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from nutcracker_core.plugins.aipwn.frida_agent import LLMClient, _LLMResponse
from nutcracker_core.plugins.dashboard.events import bus as global_bus
from nutcracker_core.plugins.dashboard.relay import relay_manager
from nutcracker_core.plugins.dashboard.server import create_app
from nutcracker_core.queue.engine import QueueEngine

_FAKE_LLM_CONFIG = {"provider": "openai", "model": "gpt-4o", "api_key": "sk-test"}


@pytest.fixture(autouse=True)
def _clean_bus():
    global_bus._subscribers.clear()
    global_bus._history.clear()
    yield
    global_bus._subscribers.clear()
    global_bus._history.clear()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = QueueEngine(config_path="config.yaml", db_path=str(tmp_path / "query_ws.db"))
    app = create_app(
        db_path=str(tmp_path / "query_ws.db"), engine=engine, llm_config=_FAKE_LLM_CONFIG,
    )
    return TestClient(app)


def _text_response(text: str) -> _LLMResponse:
    return _LLMResponse(
        content=text, thinking="", tool_calls=[],
        raw_message={"role": "assistant", "content": text, "tool_calls": None},
    )


def test_query_ws_static_mode_roundtrip(client):
    """Sin serial ni relay -- modo estático puro, no requiere ningún device
    conectado ni job corriendo (la diferencia central con /ws/chat)."""
    with patch.object(LLMClient, "chat", return_value=_text_response("no veo secretos reales acá")):
        with client.websocket_connect("/ws/query/com.example.app") as ws:
            ws.send_json({"serial": None, "relay": False})
            ws.send_text("¿hay secretos reales?")
            msg = ws.receive_json()

    assert msg["kind"] == "assistant"
    assert "no veo secretos reales" in msg["data"]["text"]


def test_query_ws_forwards_tool_events(client):
    from nutcracker_core.plugins.aipwn.frida_agent import _ToolCall

    responses = [
        _LLMResponse(
            content="", thinking="", tool_calls=[_ToolCall(id="c1", name="get_app_analysis", arguments={})],
            raw_message={"role": "assistant", "content": "", "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "get_app_analysis", "arguments": "{}"}},
            ]},
        ),
        _text_response("listo"),
    ]
    with patch.object(LLMClient, "chat", side_effect=responses):
        with client.websocket_connect("/ws/query/com.example.app") as ws:
            ws.send_json({"serial": None, "relay": False})
            ws.send_text("analizá la app")
            kinds = [ws.receive_json()["kind"] for _ in range(3)]

    assert kinds == ["tool", "tool_result", "assistant"]


def test_query_ws_unavailable_without_llm_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = QueueEngine(config_path="config.yaml", db_path=str(tmp_path / "no_llm.db"))
    app = create_app(db_path=str(tmp_path / "no_llm.db"), engine=engine, llm_config=None)
    no_llm_client = TestClient(app)

    with no_llm_client.websocket_connect("/ws/query/com.example.app") as ws:
        msg = ws.receive_json()

    assert msg["kind"] == "error"
    assert "no está disponible" in msg["data"]["text"]


def test_query_ws_relay_without_attached_session_reports_error(client):
    assert relay_manager.get("no-such-session") is None
    with client.websocket_connect("/ws/query/com.example.app") as ws:
        ws.send_json({"serial": "no-such-session", "relay": True})
        msg = ws.receive_json()

    assert msg["kind"] == "error"
    assert "no hay un navegador" in msg["data"]["text"]


def test_query_available_endpoint_reflects_llm_config(client, tmp_path, monkeypatch):
    r = client.get("/api/query/available")
    assert r.status_code == 200
    assert r.json() == {"available": True}

    monkeypatch.chdir(tmp_path)
    engine = QueueEngine(config_path="config.yaml", db_path=str(tmp_path / "no_llm2.db"))
    app_no_llm = create_app(db_path=str(tmp_path / "no_llm2.db"), engine=engine, llm_config=None)
    r2 = TestClient(app_no_llm).get("/api/query/available")
    assert r2.json() == {"available": False}
