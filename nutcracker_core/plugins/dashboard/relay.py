"""Túnel WebSocket <-> TCP local para el relay "browser-as-bridge" (plan:
frida/adb hacia un device físico detrás del navegador del operador, cuando el
dashboard corre en un servidor remoto que no puede alcanzar ese USB).

Arquitectura: los procesos reales `frida` y `adb` en el backend conectan a
listeners TCP locales (127.0.0.1:PF para frida, 127.0.0.1:PA para adb) que
este módulo abre por sesión. Cada conexión TCP aceptada ahí se multiplexa
como un "canal" dentro de UNA sola WebSocket hacia el navegador (mensajes de
control en JSON + frames binarios con un header de 4 bytes = conn_id). El
navegador reenvía esos bytes al device real vía su handle Adb (Tango/
ya-webadb, ya autenticado por USB en webusb/src/main.ts) usando
`adb.createSocket("tcp:PORT")`.

Por qué multiplexar y no un socket 1:1: frida abre varias conexiones TCP
concurrentes contra frida-server (control + por sesión de script), así que un
solo socket del lado navegador no alcanza -- cada conexión aceptada localmente
necesita su propio "canal" lógico dentro de la misma WebSocket.

Orden esperado (M1): el navegador se conecta a `/ws/relay/{session_id}`
ANTES de que el backend lance `frida`/`adb` apuntando a estos puertos --
si un proceso local conecta sin navegador adjunto, sus bytes se descartan en
silencio (no hay a quién reenviarlos) hasta que el navegador se adjunte.

FIX de diseño (verificado en vivo, 2026-08-04): el túnel de adb tal como se
diseñó originalmente (reenviar bytes crudos del protocolo adb hacia el propio
`tcp:5555` del device) NO es viable -- confirmado en vivo que Android bloquea
que una sesión adb ya autorizada reenvíe tráfico hacia el puerto de CONTROL
del propio adbd (evita que una app con depuración USB se cuele al canal
completo de adb sin la RSA key de una PC autorizada). `createSocket("tcp:5555")`
resuelve OK (el OPEN se acepta) pero después no fluye un solo byte -- ni
siquiera un error, silencio total. Confirmado que NO es un problema del
mecanismo `tcp:` en general: scrcpy (video, ya funcionando) usa exactamente
`createSocket("tcp:<puerto-scrcpy-server>")` sin problema, porque ese puerto
es un proceso de terceros, no el control de adbd. Mismo motivo por el que
frida (27042) sí funciona por túnel crudo -- frida-server tampoco es adbd.

Para las operaciones que antes iban a pasar por el túnel crudo de adb (shell,
install, pull, screenshot), el reemplazo es RPC estructurado sobre esta MISMA
WebSocket: el backend manda `{"type": "rpc_request", "request_id": N, "op":
..., ...}` y espera `{"type": "rpc_response", "request_id": N, ...}` de
vuelta -- el navegador ejecuta la operación con los métodos nativos de Tango
(`adb.subprocess`, `adb.sync()`), el mismo mecanismo que ya usa scrcpy y que
usa app.webadb.com (construida sobre la misma librería ya-webadb/Tango) para
shell/install/pull -- no una técnica nueva sin probar."""

from __future__ import annotations

import asyncio
import os
import struct
import time

_HEADER = struct.Struct(">I")  # conn_id, big-endian uint32, precede a cada frame binario

# Instrumentación byte-a-byte del túnel -- la que encontró en vivo (2026-08-04)
# que Tango no sostenía el handshake WebSocket de frida (llegaban los 177
# bytes del "GET /ws" exactos, pero la conexión se cerraba ~13ms después) y
# confirmó el fix (bridge WS nativo, ver relay.ts). Apagada por defecto --
# loguear cada chunk en producción sería ruido/IO innecesario; se activa con
# NUTCRACKER_RELAY_DEBUG=1 para volver a diagnosticar si hace falta. Archivo
# aparte (no logging.getLogger) para no depender de cómo esté configurado el
# logging del proceso del dashboard ni de a dónde vaya su stdout.
_DEBUG_LOG_PATH = "/tmp/nutcracker_relay_debug.log"
_DEBUG_ENABLED = os.environ.get("NUTCRACKER_RELAY_DEBUG") == "1"


def _debug_log(message: str) -> None:
    if not _DEBUG_ENABLED:
        return
    try:
        with open(_DEBUG_LOG_PATH, "a") as f:
            f.write(f"{time.time():.3f} {message}\n")
    except OSError:
        pass

# Tuneles que soporta una sesión -- ver plan.md M1 (frida) / M2 (adb).
TUNNELS = ("frida", "adb")


class RelayError(Exception):
    pass


class RpcTimeoutError(RelayError):
    """El navegador no respondió un rpc_request dentro del timeout."""


class RpcError(RelayError):
    """El navegador respondió con ok=False (la operación falló del lado device)."""


class _Connection:
    __slots__ = ("conn_id", "tunnel", "reader", "writer", "pump_task")

    def __init__(
        self,
        conn_id: int,
        tunnel: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.conn_id = conn_id
        self.tunnel = tunnel
        self.reader = reader
        self.writer = writer
        self.pump_task: asyncio.Task | None = None


class RelayWebSocketLike:
    """Protocolo mínimo que RelaySession necesita del objeto WebSocket --
    documentativo, para tests con dobles simples (ver test_relay.py)."""

    async def send_json(self, data: dict) -> None: ...
    async def send_bytes(self, data: bytes) -> None: ...


class RelaySession:
    """Una sesión = un navegador conectado a un device. Abre listeners TCP
    locales para cada túnel en TUNNELS; cada conexión aceptada ahí se anuncia
    al navegador (mensaje de control "open") y se multiplexa por conn_id."""

    def __init__(self, session_id: str, tunnels: tuple[str, ...] = TUNNELS) -> None:
        self.session_id = session_id
        self._tunnels = tunnels
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self.ports: dict[str, int] = {}
        self._connections: dict[int, _Connection] = {}
        self._next_conn_id = 1
        self._websocket: RelayWebSocketLike | None = None
        self._ws_lock = asyncio.Lock()
        # RPC (shell/install/... -- ver docstring del módulo): correlación de
        # request_id -> Future que se resuelve cuando llega el rpc_response.
        self._next_request_id = 1
        self._pending_rpc: dict[int, asyncio.Future] = {}

    @property
    def attached(self) -> bool:
        return self._websocket is not None

    async def start(self) -> None:
        for tunnel in self._tunnels:
            server = await asyncio.start_server(
                lambda r, w, t=tunnel: self._on_local_connection(t, r, w),
                host="127.0.0.1",
                port=0,
            )
            self._servers[tunnel] = server
            sockname = server.sockets[0].getsockname()
            self.ports[tunnel] = sockname[1]

    async def stop(self) -> None:
        for server in self._servers.values():
            server.close()
        for server in self._servers.values():
            await server.wait_closed()
        for conn_id in list(self._connections):
            await self._close_local(conn_id, notify_browser=False)
        self._fail_pending_rpc("sesión de relay detenida")

    def attach_websocket(self, websocket: RelayWebSocketLike) -> None:
        self._websocket = websocket

    def detach_websocket(self) -> None:
        self._websocket = None
        # Sin navegador no va a llegar ningún rpc_response -- fallar ya en vez
        # de dejar a rpc() colgado hasta su timeout completo.
        self._fail_pending_rpc("el navegador se desconectó antes de responder")

    def _fail_pending_rpc(self, reason: str) -> None:
        pending = list(self._pending_rpc.items())
        self._pending_rpc.clear()
        for _request_id, future in pending:
            if not future.done():
                future.set_exception(RelayError(reason))

    # ── Local (backend) side: frida/adb reales conectan acá ────────────────

    async def _on_local_connection(
        self,
        tunnel: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        conn_id = self._next_conn_id
        self._next_conn_id += 1
        conn = _Connection(conn_id, tunnel, reader, writer)
        self._connections[conn_id] = conn
        _debug_log(f"conn={conn_id} tunnel={tunnel} NUEVA conexión local aceptada, mandando 'open' al navegador")
        await self._send_control({"type": "open", "tunnel": tunnel, "conn_id": conn_id})
        conn.pump_task = asyncio.create_task(self._pump_local_to_ws(conn))

    async def _pump_local_to_ws(self, conn: _Connection) -> None:
        try:
            while True:
                data = await conn.reader.read(65536)
                if not data:
                    _debug_log(f"conn={conn.conn_id} tunnel={conn.tunnel} EOF del lado local (backend)")
                    break
                _debug_log(f"conn={conn.conn_id} tunnel={conn.tunnel} local->ws {len(data)} bytes: {data[:64]!r}")
                await self._send_data(conn.conn_id, data)
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            await self._close_local(conn.conn_id, notify_browser=True)

    async def _send_control(self, message: dict) -> None:
        ws = self._websocket
        if ws is None:
            return
        async with self._ws_lock:
            await ws.send_json(message)

    async def _send_data(self, conn_id: int, payload: bytes) -> None:
        ws = self._websocket
        if ws is None:
            return
        async with self._ws_lock:
            await ws.send_bytes(_HEADER.pack(conn_id) + payload)

    # ── RPC (shell/install/... -- ver docstring del módulo) ─────────────────

    async def rpc(self, op: str, timeout: float = 30.0, **fields) -> dict:
        """Manda ``{"type": "rpc_request", "op": op, ...fields}`` al navegador
        y espera su ``rpc_response`` correlacionado por ``request_id``.

        Usado por el shim de adb (ver toolbox/relay_adb_shim.py) para
        ejecutar operaciones adb con los métodos nativos de Tango
        (`adb.subprocess`, `adb.sync()`) en vez del túnel crudo -- el propio
        puerto de control de adbd (5555) bloquea reenvío `tcp:` hacia sí
        mismo (confirmado en vivo), así que esto NO puede ser un socket
        crudo; tiene que ser un pedido estructurado que el navegador resuelve
        con su handle Adb ya autenticado."""
        if not self.attached:
            raise RelayError(f"sesión '{self.session_id}' sin navegador conectado")
        request_id = self._next_request_id
        self._next_request_id += 1
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_rpc[request_id] = future
        try:
            await self._send_control({"type": "rpc_request", "request_id": request_id, "op": op, **fields})
            try:
                result = await asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                raise RpcTimeoutError(
                    f"timeout ({timeout}s) esperando respuesta del navegador para rpc '{op}'"
                ) from None
        finally:
            self._pending_rpc.pop(request_id, None)
        if not result.get("ok", False):
            raise RpcError(result.get("error", f"rpc '{op}' falló sin mensaje de error"))
        return result

    # ── Navegador side: mensajes que llegan por la WebSocket ───────────────

    async def handle_browser_control(self, message: dict) -> None:
        mtype = message.get("type")
        _debug_log(f"control del navegador: {message}")
        if mtype == "rpc_response":
            request_id = message.get("request_id")
            future = self._pending_rpc.get(request_id)
            if future is not None and not future.done():
                future.set_result(message)
            return
        conn_id = message.get("conn_id")
        if mtype in ("closed", "error") and conn_id is not None:
            await self._close_local(conn_id, notify_browser=False)
        # "opened" es solo un ack informativo -- el conn_id ya está activo
        # del lado local desde que se aceptó la conexión TCP entrante.

    async def handle_browser_data(self, frame: bytes) -> None:
        if len(frame) < _HEADER.size:
            return
        (conn_id,) = _HEADER.unpack_from(frame, 0)
        payload = frame[_HEADER.size :]
        conn = self._connections.get(conn_id)
        if conn is None:
            _debug_log(f"conn={conn_id} ws->local: conn_id desconocido, payload de {len(payload)} bytes DESCARTADO")
            return
        _debug_log(f"conn={conn_id} tunnel={conn.tunnel} ws->local {len(payload)} bytes: {payload[:64]!r}")
        try:
            conn.writer.write(payload)
            await conn.writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            await self._close_local(conn_id, notify_browser=True)

    async def _close_local(self, conn_id: int, notify_browser: bool) -> None:
        conn = self._connections.pop(conn_id, None)
        if conn is None:
            return
        task = conn.pump_task
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()
        try:
            conn.writer.close()
        except Exception:
            pass
        if notify_browser:
            await self._send_control({"type": "close", "conn_id": conn_id})


class RelayManager:
    """Registro de sesiones activas, keyed por session_id (hoy: el serial/
    target del device asociado a la sesión de navegador)."""

    def __init__(self) -> None:
        self._sessions: dict[str, RelaySession] = {}
        self._lock = asyncio.Lock()

    async def get_or_create(self, session_id: str) -> RelaySession:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = RelaySession(session_id)
                await session.start()
                self._sessions[session_id] = session
            return session

    def get(self, session_id: str) -> RelaySession | None:
        return self._sessions.get(session_id)

    async def remove(self, session_id: str) -> None:
        async with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is not None:
            await session.stop()


relay_manager = RelayManager()
