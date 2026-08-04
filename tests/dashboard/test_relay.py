"""Tests de nutcracker_core/plugins/dashboard/relay.py -- el tunnel manager
del relay "browser-as-bridge" (plan.md: frida/adb hacia un device detrás del
navegador, cuando el dashboard corre en un servidor remoto).

No hay navegador real ni device real acá -- se usan conexiones TCP loopback
reales (jugando el papel de los procesos `frida`/`adb` del backend) contra
los listeners que RelaySession abre, y un doble simple de WebSocket que
graba lo que se le manda (jugando el papel del navegador)."""

from __future__ import annotations

import asyncio
import struct

from nutcracker_core.plugins.dashboard.relay import (
    RelayError,
    RelayManager,
    RelaySession,
    RpcError,
    RpcTimeoutError,
    _HEADER,
)


class _FakeWebSocket:
    """Doble de WebSocket -- graba cada send_json/send_bytes en orden."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, object]] = []

    async def send_json(self, data: dict) -> None:
        self.sent.append(("json", data))

    async def send_bytes(self, data: bytes) -> None:
        self.sent.append(("bytes", data))


async def _wait_until(predicate, timeout: float = 2.0) -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError("timeout esperando condición")
        await asyncio.sleep(0.01)


def _run(coro):
    asyncio.run(coro)


# ── start()/stop() ──────────────────────────────────────────────────────────

def test_start_opens_one_listener_per_tunnel_with_distinct_ports():
    async def body():
        session = RelaySession("s1")
        try:
            await session.start()
            assert set(session.ports) == {"frida", "adb"}
            assert session.ports["frida"] != session.ports["adb"]
            assert all(isinstance(p, int) and p > 0 for p in session.ports.values())
        finally:
            await session.stop()

    _run(body())


def test_stop_closes_listeners_new_connections_refused():
    async def body():
        session = RelaySession("s1")
        await session.start()
        port = session.ports["frida"]
        await session.stop()

        with __import__("pytest").raises((ConnectionRefusedError, OSError)):
            await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=1.0
            )

    _run(body())


# ── flujo local -> navegador (frida/adb reales -> WS) ──────────────────────

def test_local_connection_announces_open_then_streams_data_to_browser():
    async def body():
        session = RelaySession("s1")
        await session.start()
        ws = _FakeWebSocket()
        session.attach_websocket(ws)
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", session.ports["frida"]
            )
            try:
                writer.write(b"hola-frida-server")
                await writer.drain()

                await _wait_until(lambda: len(ws.sent) >= 2)

                kind, msg = ws.sent[0]
                assert kind == "json"
                assert msg["type"] == "open"
                assert msg["tunnel"] == "frida"
                conn_id = msg["conn_id"]

                kind, frame = ws.sent[1]
                assert kind == "bytes"
                (got_id,) = _HEADER.unpack_from(frame, 0)
                assert got_id == conn_id
                assert frame[_HEADER.size :] == b"hola-frida-server"
            finally:
                writer.close()
        finally:
            await session.stop()

    _run(body())


def test_local_connection_close_notifies_browser_with_close_message():
    async def body():
        session = RelaySession("s1")
        await session.start()
        ws = _FakeWebSocket()
        session.attach_websocket(ws)
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", session.ports["adb"]
            )
            await _wait_until(lambda: len(ws.sent) >= 1)
            conn_id = ws.sent[0][1]["conn_id"]

            writer.close()
            await writer.wait_closed()

            await _wait_until(
                lambda: any(
                    k == "json" and m.get("type") == "close" for k, m in ws.sent
                )
            )
            close_msgs = [m for k, m in ws.sent if k == "json" and m["type"] == "close"]
            assert close_msgs[0]["conn_id"] == conn_id
            assert conn_id not in session._connections
        finally:
            await session.stop()

    _run(body())


def test_no_websocket_attached_does_not_crash_data_is_dropped():
    """Orden documentado en relay.py: si frida/adb conectan antes de que el
    navegador se adjunte, sus bytes se descartan en silencio -- no debe
    explotar ni bloquear la conexión local."""

    async def body():
        session = RelaySession("s1")
        await session.start()
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", session.ports["frida"]
            )
            try:
                writer.write(b"nadie esta escuchando todavia")
                await writer.drain()
                await asyncio.sleep(0.05)  # dar tiempo al pump task, no debe crashear
            finally:
                writer.close()
        finally:
            await session.stop()

    _run(body())


# ── flujo navegador -> local (bytes del device hacia frida/adb reales) ─────

def test_handle_browser_data_writes_to_local_connection():
    async def body():
        session = RelaySession("s1")
        await session.start()
        ws = _FakeWebSocket()
        session.attach_websocket(ws)
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", session.ports["frida"]
            )
            try:
                await _wait_until(lambda: len(ws.sent) >= 1)
                conn_id = ws.sent[0][1]["conn_id"]

                frame = _HEADER.pack(conn_id) + b"respuesta-del-device"
                await session.handle_browser_data(frame)

                received = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                assert received == b"respuesta-del-device"
            finally:
                writer.close()
        finally:
            await session.stop()

    _run(body())


def test_handle_browser_data_unknown_conn_id_is_ignored():
    async def body():
        session = RelaySession("s1")
        await session.start()
        session.attach_websocket(_FakeWebSocket())
        try:
            frame = _HEADER.pack(9999) + b"payload huerfano"
            await session.handle_browser_data(frame)  # no debe explotar
        finally:
            await session.stop()

    _run(body())


def test_handle_browser_data_short_frame_is_ignored():
    async def body():
        session = RelaySession("s1")
        await session.start()
        try:
            await session.handle_browser_data(b"\x00\x01")  # menos que el header
        finally:
            await session.stop()

    _run(body())


def test_handle_browser_control_closed_closes_local_connection_without_reannouncing():
    async def body():
        session = RelaySession("s1")
        await session.start()
        ws = _FakeWebSocket()
        session.attach_websocket(ws)
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", session.ports["adb"]
            )
            await _wait_until(lambda: len(ws.sent) >= 1)
            conn_id = ws.sent[0][1]["conn_id"]

            await session.handle_browser_control({"type": "closed", "conn_id": conn_id})

            assert conn_id not in session._connections
            # El navegador ya sabe que cerró -- no debe recibir un "close" de vuelta.
            assert not any(
                k == "json" and m.get("type") == "close" for k, m in ws.sent
            )
        finally:
            await session.stop()

    _run(body())


# ── multiplexado: varias conexiones concurrentes al mismo túnel ───────────

def test_multiple_concurrent_connections_get_distinct_conn_ids():
    async def body():
        session = RelaySession("s1")
        await session.start()
        ws = _FakeWebSocket()
        session.attach_websocket(ws)
        try:
            r1, w1 = await asyncio.open_connection("127.0.0.1", session.ports["frida"])
            r2, w2 = await asyncio.open_connection("127.0.0.1", session.ports["frida"])
            try:
                await _wait_until(
                    lambda: sum(1 for k, m in ws.sent if k == "json" and m.get("type") == "open") >= 2
                )
                opens = [m for k, m in ws.sent if k == "json" and m["type"] == "open"]
                ids = {m["conn_id"] for m in opens}
                assert len(ids) == 2

                w1.write(b"canal-1")
                await w1.drain()
                w2.write(b"canal-2")
                await w2.drain()

                await _wait_until(lambda: sum(1 for k, _ in ws.sent if k == "bytes") >= 2)
                frames = {
                    struct.unpack_from(">I", f, 0)[0]: f[_HEADER.size :]
                    for k, f in ws.sent
                    if k == "bytes"
                }
                assert set(frames.values()) == {b"canal-1", b"canal-2"}
                assert set(frames.keys()) == ids
            finally:
                w1.close()
                w2.close()
        finally:
            await session.stop()

    _run(body())


# ── RelayManager ─────────────────────────────────────────────────────────

def test_manager_get_or_create_returns_same_session_for_same_id():
    async def body():
        manager = RelayManager()
        s1 = await manager.get_or_create("target-a")
        s2 = await manager.get_or_create("target-a")
        try:
            assert s1 is s2
        finally:
            await manager.remove("target-a")

    _run(body())


def test_manager_different_ids_get_different_sessions_with_different_ports():
    async def body():
        manager = RelayManager()
        s1 = await manager.get_or_create("target-a")
        s2 = await manager.get_or_create("target-b")
        try:
            assert s1 is not s2
            assert s1.ports["frida"] != s2.ports["frida"]
        finally:
            await manager.remove("target-a")
            await manager.remove("target-b")

    _run(body())


def test_manager_remove_stops_session_and_forgets_it():
    async def body():
        manager = RelayManager()
        session = await manager.get_or_create("target-a")
        port = session.ports["frida"]

        await manager.remove("target-a")

        assert manager.get("target-a") is None
        with __import__("pytest").raises((ConnectionRefusedError, OSError)):
            await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=1.0
            )

    _run(body())


# ── RPC (shell/install/... -- reemplazo del túnel crudo de adb, 2026-08-04) ──
#
# FIX de diseño: el túnel crudo original para adb (createSocket("tcp:5555"))
# no es viable -- Android bloquea el reenvío hacia el propio puerto de
# control de adbd (confirmado en vivo). El reemplazo es RPC estructurado
# sobre la misma WebSocket: rpc_request/rpc_response correlacionados por
# request_id, que el navegador resuelve con los métodos nativos de Tango.

async def _reply_to_next_rpc(
    ws: _FakeWebSocket, session: RelaySession, response_fields: dict,
    already_replied: set[int] | None = None,
) -> int:
    """Espera al próximo rpc_request en ws.sent que todavía no se contestó
    (según ``already_replied``, propio de cada test), y le inyecta una
    respuesta -- simula al navegador contestando. Devuelve el request_id."""
    seen = already_replied if already_replied is not None else set()

    def _pending_request_ids():
        return [
            m["request_id"] for k, m in ws.sent
            if k == "json" and m.get("type") == "rpc_request" and m["request_id"] not in seen
        ]

    await _wait_until(lambda: bool(_pending_request_ids()))
    request_id = _pending_request_ids()[0]
    seen.add(request_id)
    await session.handle_browser_control({"type": "rpc_response", "request_id": request_id, **response_fields})
    return request_id


def test_rpc_shell_round_trip_returns_browser_response():
    async def body():
        session = RelaySession("s1")
        await session.start()
        ws = _FakeWebSocket()
        session.attach_websocket(ws)
        try:
            rpc_task = asyncio.create_task(session.rpc("shell", command="pm list packages"))
            request_id = await _reply_to_next_rpc(
                ws, session, {"ok": True, "stdout": "package:com.example.app\n", "stderr": "", "exit_code": 0}
            )

            result = await asyncio.wait_for(rpc_task, timeout=2.0)

            assert result["request_id"] == request_id
            assert result["stdout"] == "package:com.example.app\n"
            assert result["exit_code"] == 0

            sent_request = next(m for k, m in ws.sent if k == "json" and m["type"] == "rpc_request")
            assert sent_request["op"] == "shell"
            assert sent_request["command"] == "pm list packages"
        finally:
            await session.stop()

    _run(body())


def test_rpc_raises_rpc_error_when_browser_reports_failure():
    async def body():
        session = RelaySession("s1")
        await session.start()
        ws = _FakeWebSocket()
        session.attach_websocket(ws)
        try:
            rpc_task = asyncio.create_task(session.rpc("shell", command="false"))
            await _reply_to_next_rpc(ws, session, {"ok": False, "error": "createSocket falló: device offline"})

            with __import__("pytest").raises(RpcError, match="device offline"):
                await asyncio.wait_for(rpc_task, timeout=2.0)
        finally:
            await session.stop()

    _run(body())


def test_rpc_times_out_if_browser_never_responds():
    async def body():
        session = RelaySession("s1")
        await session.start()
        session.attach_websocket(_FakeWebSocket())
        try:
            with __import__("pytest").raises(RpcTimeoutError):
                await session.rpc("shell", command="echo hi", timeout=0.05)
        finally:
            await session.stop()

    _run(body())


def test_rpc_raises_immediately_without_attached_websocket():
    async def body():
        session = RelaySession("s1")
        await session.start()
        try:
            with __import__("pytest").raises(RelayError, match="sin navegador conectado"):
                await session.rpc("shell", command="echo hi", timeout=1.0)
        finally:
            await session.stop()

    _run(body())


def test_rpc_fails_fast_when_browser_detaches_mid_request():
    """Si el navegador se desconecta mientras hay un rpc() en vuelo, no debe
    quedar colgado hasta agotar el timeout completo -- debe fallar ya."""

    async def body():
        session = RelaySession("s1")
        await session.start()
        session.attach_websocket(_FakeWebSocket())
        try:
            rpc_task = asyncio.create_task(session.rpc("shell", command="echo hi", timeout=30.0))
            await asyncio.sleep(0.05)  # dar tiempo a que el rpc_request salga
            session.detach_websocket()

            with __import__("pytest").raises(RelayError, match="desconectó"):
                await asyncio.wait_for(rpc_task, timeout=2.0)
        finally:
            await session.stop()

    _run(body())


def test_two_concurrent_rpcs_get_independent_request_ids_and_responses():
    async def body():
        session = RelaySession("s1")
        await session.start()
        ws = _FakeWebSocket()
        session.attach_websocket(ws)
        seen: set[int] = set()
        try:
            task_a = asyncio.create_task(session.rpc("shell", command="cmd-a"))
            id_a = await _reply_to_next_rpc(
                ws, session, {"ok": True, "stdout": "resultado-a", "exit_code": 0}, seen,
            )

            task_b = asyncio.create_task(session.rpc("shell", command="cmd-b"))
            id_b = await _reply_to_next_rpc(
                ws, session, {"ok": True, "stdout": "resultado-b", "exit_code": 0}, seen,
            )

            result_a = await asyncio.wait_for(task_a, timeout=2.0)
            result_b = await asyncio.wait_for(task_b, timeout=2.0)

            assert id_a != id_b
            assert result_a["stdout"] == "resultado-a"
            assert result_b["stdout"] == "resultado-b"
        finally:
            await session.stop()

    _run(body())
