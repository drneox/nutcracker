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


# ── FIX (2026-08-03): RuntimeError al mandar tras un cierre en mal momento ──
#
# Reproducido en vivo: "RuntimeError: Unexpected ASGI message 'websocket.send',
# after sending 'websocket.close'." -- un cliente que cierra la conexión justo
# cuando el servidor está por mandar un evento no siempre produce
# WebSocketDisconnect (lo único que ws.py atrapaba antes de este fix); a veces
# Starlette/uvicorn ya cerró el transporte y levanta RuntimeError al intentar
# mandar después. TestClient.websocket_connect no reproduce esa carrera real
# de forma determinística, así que estos tests invocan las corrutinas
# directo con un WebSocket falso que fuerza el mismo RuntimeError.

class _FakeWebSocketThatDisconnectsOnSend:
    """send_json() explota con el RuntimeError real visto en producción --
    simula al cliente yéndose justo cuando el servidor manda un evento."""

    def __init__(self, incoming_texts: list[str] | None = None):
        self._incoming = list(incoming_texts or [])

    async def accept(self):
        pass

    async def send_json(self, data):
        raise RuntimeError(
            "Unexpected ASGI message 'websocket.send', after sending 'websocket.close'."
        )

    async def receive_text(self):
        if self._incoming:
            return self._incoming.pop(0)
        raise RuntimeError(
            "Unexpected ASGI message 'websocket.send', after sending 'websocket.close'."
        )


def test_ws_job_survives_runtime_error_on_send_during_history_replay():
    import asyncio
    from nutcracker_core.plugins.dashboard import ws as ws_mod

    global_bus.publish("77", "log", "línea vieja, se manda en el replay")

    fake_ws = _FakeWebSocketThatDisconnectsOnSend()
    asyncio.run(ws_mod.ws_job(fake_ws, "77"))  # no debe propagar el RuntimeError

    # unsubscribe debe haber corrido igual (el finally no debe saltarse)
    assert global_bus._subscribers.get("77", []) == []


def test_ws_job_survives_runtime_error_on_send_during_live_streaming():
    """Mismo caso, pero el RuntimeError llega durante el streaming en vivo
    (después del replay de historial), no durante el replay en sí."""
    import asyncio
    from nutcracker_core.plugins.dashboard import ws as ws_mod

    class _FakeWebSocketFailsOnSecondSend:
        def __init__(self):
            self.sent = []

        async def accept(self):
            pass

        async def send_json(self, data):
            self.sent.append(data)
            if len(self.sent) >= 1:
                raise RuntimeError(
                    "Unexpected ASGI message 'websocket.send', after sending 'websocket.close'."
                )

    fake_ws = _FakeWebSocketFailsOnSecondSend()
    # Sin historial: el primer send_json ocurre recién en el loop de streaming.
    global_bus.publish("78", "log", "evento en vivo")
    asyncio.run(ws_mod.ws_job(fake_ws, "78"))

    assert global_bus._subscribers.get("78", []) == []


def test_ws_chat_survives_runtime_error_on_send():
    import asyncio
    from nutcracker_core.plugins.dashboard import ws as ws_mod

    fake_ws = _FakeWebSocketThatDisconnectsOnSend(incoming_texts=["hola"])
    asyncio.run(ws_mod.ws_chat(fake_ws, "com.example.app"))  # no debe propagar


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
