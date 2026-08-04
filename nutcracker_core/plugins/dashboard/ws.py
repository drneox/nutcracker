"""WebSockets del dashboard (Fase 3 del plan): logs en vivo de un job de la
cola (`/ws/jobs/{id}`) y chat operador→agente (`/ws/chat/{package}`)."""

from __future__ import annotations

import json
import queue as queue_mod

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from . import chat_mailbox
from .events import bus
from .relay import relay_manager

router = APIRouter()

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
