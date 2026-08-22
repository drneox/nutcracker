"""WebSockets del dashboard (Fase 3 del plan): logs en vivo de un job de la
cola (`/ws/jobs/{id}`), chat operador→agente (`/ws/chat/{package}`), y el
co-piloto de pentest interactivo (`/ws/query/{package}`, ver
plugins/aipwn/query_agent.py)."""

from __future__ import annotations

import asyncio
import json
import queue as queue_mod
import threading

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from . import chat_mailbox
from .auth import AuthConfig, websocket_authenticated
from .events import bus
from .relay import relay_manager

router = APIRouter()

# Config de auth del dashboard, seteada por server.create_app(). None = sin
# protección (uso local/dev). Módulo-global a propósito: el router se define a
# nivel de módulo, así que no puede recibir la config por parámetro.
_auth: AuthConfig | None = None

# Config del co-piloto de consulta (/ws/query), seteada por
# server.create_app() -- llm_config es el bloque `llm:` de config.yaml (el
# mismo que usa aipwn) y db_path el mismo sqlite del resto del dashboard.
# None = plugin aipwn no disponible o sin LLM configurado (ver api.py::query_available).
_query_llm_config: dict | None = None
_query_db_path: str | None = None


def set_auth(auth: "AuthConfig | None") -> None:
    global _auth
    _auth = auth


def set_query_config(llm_config: dict | None, db_path: str | None) -> None:
    global _query_llm_config, _query_db_path
    _query_llm_config = llm_config
    _query_db_path = db_path


async def _reject_if_unauthenticated(websocket: WebSocket) -> bool:
    """Cierra el WS con 1008 (policy violation) si no hay sesión válida.
    Devuelve True si rechazó (el caller debe cortar). El middleware ya rechaza
    el handshake no autenticado antes de llegar acá; esto es defensa en
    profundidad y cubre los tests que montan el endpoint sin el middleware."""
    if websocket_authenticated(websocket, _auth):
        return False
    await websocket.close(code=1008)
    return True

# q.get() sin timeout bloquearía el hilo del threadpool para siempre tras el
# último evento -- si el cliente se desconecta mientras tanto, la tarea async
# que lo espera se cancela, pero el hilo de verdad (OS thread) seguiría
# bloqueado indefinidamente esperando un item que ya nunca llega (encontrado
# en pruebas: pytest se colgaba en el primer test de WS). Con un timeout
# acotado, el hilo vuelve al pool como máximo cada _POLL_TIMEOUT_S segundos.
_POLL_TIMEOUT_S = 0.5


@router.websocket("/ws/jobs/{job_id}")
async def ws_job(websocket: WebSocket, job_id: str) -> None:
    """Replay del historial del job (para quien se conecta tarde) seguido de
    streaming en vivo de cada línea de log / cambio de estado publicado en el
    canal ``job_id`` del EventBus (ver queue/engine.py::on_line y api.py).

    FIX (encontrado en vivo, 2026-08-03): un cliente que cierra la conexión
    justo mientras el servidor está por mandar un evento (p.ej. el frontend
    cierra el socket viejo al hacer clic en otra fila del historial y abre
    uno nuevo, ver goToJobLog() en index.html) no siempre produce
    WebSocketDisconnect -- a veces Starlette/uvicorn ya procesó el cierre del
    lado transporte y levanta un RuntimeError genérico
    ("Unexpected ASGI message 'websocket.send', after sending
    'websocket.close'") al intentar mandar después. Ambos significan lo
    mismo acá: el cliente ya no está, hay que cortar en silencio."""
    if await _reject_if_unauthenticated(websocket):
        return
    await websocket.accept()
    q = bus.subscribe(job_id)
    try:
        for event in bus.history(job_id):
            await websocket.send_json({"kind": event.kind, "data": event.data})

        while True:
            try:
                event = await run_in_threadpool(q.get, True, _POLL_TIMEOUT_S)
            except queue_mod.Empty:
                continue
            await websocket.send_json({"kind": event.kind, "data": event.data})
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        bus.unsubscribe(job_id, q)


@router.websocket("/ws/chat/{package}")
async def ws_chat(websocket: WebSocket, package: str) -> None:
    """Cada mensaje del operador se: (1) escribe al mailbox pull-based que
    consume un job ``aipwn`` corriendo como subproceso aislado (ver
    chat_mailbox.py / plugins/aipwn/frida_agent.py::_check_operator_chat),
    (2) publica en el EventBus (canal=package, para que futuros viewers vean
    el historial vía bus.history), y (3) se hace eco directo al remitente."""
    if await _reject_if_unauthenticated(websocket):
        return
    await websocket.accept()
    try:
        while True:
            text = await websocket.receive_text()
            chat_mailbox.add(package, text)
            data = {"from": "operator", "text": text}
            bus.publish(package, "chat", data)
            await websocket.send_json({"kind": "chat", "data": data})
    except (WebSocketDisconnect, RuntimeError):
        # Ver el comentario equivalente en ws_job -- un cierre en mal momento
        # puede llegar como RuntimeError en vez de WebSocketDisconnect.
        pass


@router.websocket("/ws/relay/{session_id}")
async def ws_relay(websocket: WebSocket, session_id: str) -> None:
    """Punto de entrada del navegador al túnel frida/adb (ver relay.py y
    plan.md, sección "Browser-as-relay"). El navegador se conecta acá y:

    - recibe control en JSON (frame de texto) por cada conexión TCP local
      nueva que `frida`/`adb` reales (en el backend) abrieron contra los
      puertos de la sesión (``{"type": "open", "tunnel": "frida"|"adb",
      "conn_id": N}``) o que se cerraron (``{"type": "close", "conn_id": N}``);
    - manda/recibe los bytes de cada conexión como frames BINARIOS con un
      header de 4 bytes big-endian = conn_id (ver relay._HEADER) -- necesario
      porque frida abre varias conexiones concurrentes a frida-server, así
      que un solo socket no alcanza, hay que multiplexar por conn_id dentro
      de esta única WebSocket.

    Se usa ``websocket.receive()`` de bajo nivel (en vez de receive_text/
    receive_bytes) porque esta WebSocket mezcla ambos tipos de frame -- las
    variantes tipadas solo aceptan uno de los dos y explotan con el otro."""
    if await _reject_if_unauthenticated(websocket):
        return
    await websocket.accept()
    session = await relay_manager.get_or_create(session_id)
    session.attach_websocket(websocket)
    try:
        await websocket.send_json({"type": "ready", "ports": session.ports})
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            text = message.get("text")
            if text is not None:
                await session.handle_browser_control(json.loads(text))
                continue
            data = message.get("bytes")
            if data is not None:
                await session.handle_browser_data(data)
    except (WebSocketDisconnect, RuntimeError):
        # Ver el comentario equivalente en ws_job -- un cierre en mal momento
        # puede llegar como RuntimeError en vez de WebSocketDisconnect.
        pass
    finally:
        session.detach_websocket()


@router.websocket("/ws/query/{package}")
async def ws_query(websocket: WebSocket, package: str) -> None:
    """Co-piloto de pentest interactivo (ver plugins/aipwn/query_agent.py) --
    a diferencia de ``/ws/chat`` (inyección en un job aipwn autónomo ya
    corriendo), esta conexión ES la conversación: cada mensaje del operador
    corre un turno completo del agente (que puede llamar tools estáticas y/o
    dinámicas) y la respuesta se transmite como una secuencia de eventos
    (tool/tool_result/image/assistant/error).

    Primer frame del cliente (antes de cualquier mensaje de chat) = JSON de
    conexión ``{"serial": str|None, "relay": bool}`` -- mismo significado que
    ``QueuePayload.serial``/``.relay`` en api.py: si ``relay`` es True,
    ``serial`` es el session_id de una sesión de relay YA conectada (WebUSB),
    no un serial adb directo."""
    if await _reject_if_unauthenticated(websocket):
        return
    await websocket.accept()

    if not _query_llm_config:
        await websocket.send_json({
            "kind": "error",
            "data": {"text": "el co-piloto de consulta no está disponible (plugin aipwn "
                              "no instalado, o falta el bloque 'llm:' en config.yaml)."},
        })
        await websocket.close(code=1011)
        return

    try:
        conn_raw = await websocket.receive_text()
        conn_params = json.loads(conn_raw) if conn_raw else {}
    except (WebSocketDisconnect, RuntimeError, json.JSONDecodeError):
        return

    serial = conn_params.get("serial") or None
    use_relay = bool(conn_params.get("relay"))

    device = None
    frida_host = None
    if use_relay:
        if not serial:
            await websocket.send_json({
                "kind": "error",
                "data": {"text": "relay=true requiere 'serial' con el session_id de una "
                                  "sesión de relay conectada."},
            })
            await websocket.close(code=1011)
            return
        session = relay_manager.get(serial)
        if session is None or not session.attached:
            await websocket.send_json({
                "kind": "error",
                "data": {"text": f"no hay un navegador con el relay conectado para '{serial}' "
                                  "-- conectá el device por WebUSB y activá el túnel primero."},
            })
            await websocket.close(code=1011)
            return
        from nutcracker_core.plugins.aipwn.query_tools import DeviceIO
        loop = asyncio.get_running_loop()
        device = DeviceIO(relay_session=session, loop=loop)
        frida_host = f"127.0.0.1:{session.ports['frida']}"
    elif serial:
        from nutcracker_core.plugins.aipwn.query_tools import DeviceIO
        device = DeviceIO(serial=serial)
    # Sin serial ni relay: modo estático puro (device=None) -- las tools
    # dinámicas devuelven su propio error "no hay dispositivo conectado".

    try:
        from nutcracker_core.plugins.aipwn.query_agent import QueryAgent
        from nutcracker_core.plugins.aipwn.query_context import resolve_package_context
    except ImportError:
        await websocket.send_json({
            "kind": "error",
            "data": {"text": "plugin aipwn no instalado en este entorno."},
        })
        await websocket.close(code=1011)
        return

    decompiled_dir, runtime_dump_dir, analysis_result = await run_in_threadpool(
        resolve_package_context, package,
    )
    agent = QueryAgent(
        package=package,
        decompiled_dir=decompiled_dir,
        runtime_dump_dir=runtime_dump_dir,
        analysis_result=analysis_result,
        llm_config=_query_llm_config,
        db_path=_query_db_path,
        serial=serial if not use_relay else None,
        frida_host=frida_host,
        device=device,
    )

    try:
        while True:
            text = await websocket.receive_text()
            q: queue_mod.Queue = queue_mod.Queue()

            def _run_turn(agent=agent, text=text, q=q) -> None:
                try:
                    for event in agent.ask(text):
                        q.put(event)
                except Exception as exc:  # noqa: BLE001
                    from nutcracker_core.plugins.aipwn.query_agent import QueryEvent
                    q.put(QueryEvent("error", {"text": f"error interno del agente: {exc}"}))
                finally:
                    q.put(None)

            threading.Thread(target=_run_turn, daemon=True).start()

            while True:
                try:
                    item = await run_in_threadpool(q.get, True, _POLL_TIMEOUT_S)
                except queue_mod.Empty:
                    continue
                if item is None:
                    break
                await websocket.send_json({"kind": item.kind, "data": item.data})
    except (WebSocketDisconnect, RuntimeError):
        # Ver el comentario equivalente en ws_job -- un cierre en mal momento
        # puede llegar como RuntimeError en vez de WebSocketDisconnect.
        pass
