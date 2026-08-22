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


# ── /ws/relay/{session_id} -- integración real vía TestClient (2026-08-04) ──
#
# Complementa tests/dashboard/test_relay.py (unit, sin WebSocket real): acá se
# valida el endpoint completo -- TestClient corre la app ASGI real en un hilo
# aparte con su propio loop, así que una conexión TCP real desde el hilo del
# test contra el puerto anunciado por el relay ejercita el mismo camino que
# usaría el proceso `frida`/`adb` real en producción.

import socket as _socket_mod
import time as _time_mod

from nutcracker_core.plugins.dashboard.relay import relay_manager as _relay_manager


@pytest.fixture(autouse=True)
def _clean_relay_sessions():
    yield
    import asyncio as _asyncio
    for session_id in list(_relay_manager._sessions):
        _asyncio.run(_relay_manager.remove(session_id))


def _open_tcp(port: int, timeout: float = 2.0) -> _socket_mod.socket:
    deadline = _time_mod.monotonic() + timeout
    last_exc: Exception | None = None
    while _time_mod.monotonic() < deadline:
        try:
            return _socket_mod.create_connection(("127.0.0.1", port), timeout=1.0)
        except OSError as exc:  # noqa: PERF203 -- puerto puede tardar en estar listo
            last_exc = exc
            _time_mod.sleep(0.02)
    raise AssertionError(f"no se pudo conectar a 127.0.0.1:{port}: {last_exc}")


def test_ws_relay_sends_ready_message_with_tunnel_ports(client):
    with client.websocket_connect("/ws/relay/test-target-1") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "ready"
        assert set(msg["ports"]) == {"frida", "adb"}
        assert all(isinstance(p, int) and p > 0 for p in msg["ports"].values())


def test_ws_relay_forwards_local_tcp_connection_to_client_as_open_then_bytes(client):
    with client.websocket_connect("/ws/relay/test-target-2") as ws:
        ready = ws.receive_json()
        frida_port = ready["ports"]["frida"]

        sock = _open_tcp(frida_port)
        try:
            sock.sendall(b"process real de frida conectando")

            open_msg = ws.receive_json()
            assert open_msg["type"] == "open"
            assert open_msg["tunnel"] == "frida"
            conn_id = open_msg["conn_id"]

            frame = ws.receive_bytes()
            got_id = int.from_bytes(frame[:4], "big")
            assert got_id == conn_id
            assert frame[4:] == b"process real de frida conectando"
        finally:
            sock.close()


def test_ws_relay_client_bytes_reach_local_tcp_connection(client):
    with client.websocket_connect("/ws/relay/test-target-3") as ws:
        ready = ws.receive_json()
        adb_port = ready["ports"]["adb"]

        sock = _open_tcp(adb_port)
        try:
            sock.sendall(b"hola")  # dispara el "open" del lado navegador
            open_msg = ws.receive_json()
            conn_id = open_msg["conn_id"]
            ws.receive_bytes()  # el frame con "hola" -- no es lo que estamos probando acá

            frame_back = conn_id.to_bytes(4, "big") + b"respuesta simulada del device"
            ws.send_bytes(frame_back)

            sock.settimeout(2.0)
            received = sock.recv(1024)
            assert received == b"respuesta simulada del device"
        finally:
            sock.close()
