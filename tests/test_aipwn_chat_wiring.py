"""Tests del wiring del chat operador→agente (Fase 3, follow-up de plan.md):
FridaAgent._check_operator_chat hace polling best-effort de
NUTCRACKER_DASHBOARD_URL/api/chat/{package}/pending e inyecta lo que
encuentra en la conversación real del agente.

FridaAgent.__init__ requiere un LLM real, ToolContext, decompiled dir, etc. —
para testear un único método en aislamiento se construye la instancia con
__new__ (sin __init__) y se setean a mano los atributos que el método usa
(self.package, self.messages) — técnica estándar para testear un método sin
pagar el costo/dependencias del constructor completo de una clase grande.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nutcracker_core.plugins.aipwn.frida_agent import FridaAgent


def _make_agent(package: str = "com.example.tapjacking") -> FridaAgent:
    agent = FridaAgent.__new__(FridaAgent)
    agent.package = package
    agent.messages = []
    return agent


def test_noop_without_dashboard_url_env(monkeypatch):
    monkeypatch.delenv("NUTCRACKER_DASHBOARD_URL", raising=False)
    agent = _make_agent()
    with patch("requests.get") as mock_get:
        agent._check_operator_chat()
    mock_get.assert_not_called()
    assert agent.messages == []


def test_injects_pending_messages_as_user_turn(monkeypatch):
    monkeypatch.setenv("NUTCRACKER_DASHBOARD_URL", "http://127.0.0.1:8765")
    agent = _make_agent("com.example.tapjacking")

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"messages": ["toma un screenshot", "prueba el hook de SSL pinning"]}

    with patch("requests.get", return_value=fake_resp) as mock_get:
        agent._check_operator_chat()

    called_url = mock_get.call_args[0][0]
    assert called_url == "http://127.0.0.1:8765/api/chat/com.example.tapjacking/pending"
    assert len(agent.messages) == 2
    assert agent.messages[0]["role"] == "user"
    assert "toma un screenshot" in agent.messages[0]["content"]
    assert "prueba el hook de SSL pinning" in agent.messages[1]["content"]


def test_url_encodes_package_with_special_characters(monkeypatch):
    monkeypatch.setenv("NUTCRACKER_DASHBOARD_URL", "http://127.0.0.1:8765")
    agent = _make_agent("com.example.app+test")
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"messages": []}
    with patch("requests.get", return_value=fake_resp) as mock_get:
        agent._check_operator_chat()
    called_url = mock_get.call_args[0][0]
    assert "com.example.app+test" not in called_url  # el '+' debe quedar codificado
    assert "com.example.app%2Btest" in called_url


def test_strips_trailing_slash_from_dashboard_url(monkeypatch):
    monkeypatch.setenv("NUTCRACKER_DASHBOARD_URL", "http://127.0.0.1:8765/")
    agent = _make_agent()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"messages": []}
    with patch("requests.get", return_value=fake_resp) as mock_get:
        agent._check_operator_chat()
    called_url = mock_get.call_args[0][0]
    assert "//api" not in called_url


@pytest.mark.parametrize("side_effect", [
    ConnectionError("dashboard caído"),
    TimeoutError("timeout"),
])
def test_never_raises_when_dashboard_unreachable(monkeypatch, side_effect):
    monkeypatch.setenv("NUTCRACKER_DASHBOARD_URL", "http://127.0.0.1:8765")
    agent = _make_agent()
    with patch("requests.get", side_effect=side_effect):
        agent._check_operator_chat()  # no debe propagar la excepción
    assert agent.messages == []


def test_ignores_non_200_response(monkeypatch):
    monkeypatch.setenv("NUTCRACKER_DASHBOARD_URL", "http://127.0.0.1:8765")
    agent = _make_agent()
    fake_resp = MagicMock()
    fake_resp.status_code = 503
    with patch("requests.get", return_value=fake_resp):
        agent._check_operator_chat()
    assert agent.messages == []
