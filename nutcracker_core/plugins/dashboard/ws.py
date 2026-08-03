"""WebSockets del dashboard (Fase 3 del plan): logs en vivo de un job de la
cola (`/ws/jobs/{id}`) y chat operador→agente (`/ws/chat/{package}`)."""

from __future__ import annotations

import queue as queue_mod

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from . import chat_mailbox
from .events import bus

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
    canal ``job_id`` del EventBus (ver queue/engine.py::on_line y api.py)."""
    await websocket.accept()
    for event in bus.history(job_id):
        await websocket.send_json({"kind": event.kind, "data": event.data})

    q = bus.subscribe(job_id)
    try:
        while True:
            try:
                event = await run_in_threadpool(q.get, True, _POLL_TIMEOUT_S)
            except queue_mod.Empty:
                continue
            await websocket.send_json({"kind": event.kind, "data": event.data})
    except WebSocketDisconnect:
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
    except WebSocketDisconnect:
        pass
