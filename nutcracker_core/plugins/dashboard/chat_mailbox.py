"""Mailbox pull-based para el chat operador→agente (Fase 3, follow-up del plan).

Separado del EventBus (events.py) a propósito: un job ``aipwn`` corre como
**subproceso aislado** de la cola (ver orchestrator.py — no puede ser un
suscriptor WebSocket del proceso del dashboard), así que necesita un mecanismo
que pueda *consultar por HTTP* en vez de recibir push — ``FridaAgent`` hace
polling de ``GET /api/chat/{package}/pending`` una vez por iteración de su
loop ReAct (ver ``plugins/aipwn/frida_agent.py::_check_operator_chat``).

Cada mensaje enviado por ``/ws/chat/{package}`` se escribe aquí además de
hacer eco por WebSocket (ver ws.py) — dos consumidores independientes del
mismo mensaje del operador.
"""

from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
_pending: dict[str, list[str]] = defaultdict(list)


def add(package: str, text: str) -> None:
    with _lock:
        _pending[package].append(text)


def drain(package: str) -> list[str]:
    """Devuelve y vacía los mensajes pendientes de ``package``."""
    with _lock:
        messages = _pending.get(package, [])
        _pending[package] = []
        return messages
