"""Tests de los WebSockets del dashboard (Fase 3 del plan) — verifica que un
evento publicado en el EventBus llega de verdad al cliente WS, incluyendo el
historial para quien se conecta tarde."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from nutcracker_core.plugins.dashboard.events import bus as global_bus
from nutcracker_core.plugins.dashboard.server import create_app
from nutcracker_core.queue.engine import QueueEngine


@pytest.fixture(autouse=True)
def _clean_bus():
    # events.bus es una instancia de proceso compartida (la usa el comando
    # `dashboard` real); en tests hay que limpiarla entre casos.
    global_bus._subscribers.clear()
    global_bus._history.clear()
    yield
    global_bus._subscribers.clear()
    global_bus._history.clear()


@pytest.fixture
def client(tmp_path):
    engine = QueueEngine(config_path="config.yaml", db_path=str(tmp_path / "ws_test.db"))
    app = create_app(db_path=str(tmp_path / "ws_test.db"), engine=engine)
    return TestClient(app)


def test_job_ws_receives_live_published_events(client):
    with client.websocket_connect("/ws/jobs/42") as ws:
        global_bus.publish("42", "log", "línea en vivo")
        msg = ws.receive_json()
        assert msg["kind"] == "log"
        assert msg["data"] == "línea en vivo"


def test_job_ws_replays_history_on_connect(client):
    global_bus.publish("42", "log", "línea anterior a la conexión")
    with client.websocket_connect("/ws/jobs/42") as ws:
        msg = ws.receive_json()
        assert msg["data"] == "línea anterior a la conexión"


def test_job_ws_channels_are_isolated(client):
    global_bus.publish("other-job", "log", "no debería aparecer en el 42")
    global_bus.publish("42", "log", "sí debería aparecer")
    with client.websocket_connect("/ws/jobs/42") as ws:
        msg = ws.receive_json()
        assert msg["data"] == "sí debería aparecer"


def test_chat_ws_echoes_message_to_subscribers(client):
    with client.websocket_connect("/ws/chat/com.example.app") as ws:
        ws.send_text("hola agente")
        msg = ws.receive_json()
        assert msg["kind"] == "chat"
        assert msg["data"]["from"] == "operator"
        assert msg["data"]["text"] == "hola agente"


def test_chat_ws_also_writes_to_mailbox_for_aipwn_polling(client):
    """Fase 3 follow-up: además de hacer eco por WS, el mensaje debe quedar
    disponible para que un job aipwn (subproceso, no cliente WS) lo recoja
    vía GET /api/chat/{package}/pending -- ver chat_mailbox.py."""
    from nutcracker_core.plugins.dashboard import chat_mailbox
    chat_mailbox._pending.clear()

    with client.websocket_connect("/ws/chat/com.example.app") as ws:
        ws.send_text("toma un screenshot")
        ws.receive_json()  # esperar el eco antes de leer el mailbox (evita carrera)

    assert chat_mailbox.drain("com.example.app") == ["toma un screenshot"]
