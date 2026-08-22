"""Bus de eventos en memoria del dashboard (Fase 3 del plan).

Pub-sub simple con historial acotado por canal, para que un cliente que se
conecta tarde (WebSocket) reciba lo que se perdió antes de suscribirse. No
persiste nada — se reinicia con el proceso del dashboard, que es lo esperado:
el historial autoritativo de un run vive en SQLite (store/), esto es solo
para replay en vivo de logs de un job mientras el dashboard sigue corriendo.
"""

from __future__ import annotations

import queue
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

_DEFAULT_HISTORY_SIZE = 500


@dataclass
class Event:
    channel: str
    kind: str
    data: Any
    ts: float


class EventBus:
    """Pub-sub en memoria: cada canal (p.ej. ``"42"`` para el job #42, o un
    package id para el chat) tiene su propia lista de suscriptores y su propio
    historial acotado."""

    def __init__(self, history_size: int = _DEFAULT_HISTORY_SIZE) -> None:
        self._history_size = history_size
        self._lock = threading.Lock()
        self._subscribers: dict[str, list["queue.Queue[Event]"]] = defaultdict(list)
        self._history: dict[str, deque[Event]] = defaultdict(
            lambda: deque(maxlen=history_size)
        )

    def publish(self, channel: str, kind: str, data: Any) -> None:
        event = Event(channel=channel, kind=kind, data=data, ts=time.time())
        with self._lock:
            self._history[channel].append(event)
            subs = list(self._subscribers.get(channel, ()))
        for q in subs:
            q.put(event)

    def subscribe(self, channel: str) -> "queue.Queue[Event]":
        q: "queue.Queue[Event]" = queue.Queue()
        with self._lock:
            self._subscribers[channel].append(q)
        return q

    def unsubscribe(self, channel: str, q: "queue.Queue[Event]") -> None:
        with self._lock:
            subs = self._subscribers.get(channel)
            if subs and q in subs:
                subs.remove(q)

    def history(self, channel: str) -> list[Event]:
        with self._lock:
            return list(self._history.get(channel, ()))


# Instancia de proceso compartida — la usa `nutcracker dashboard` (server.py monta
# sobre esta) y cualquier sink que empuje eventos (QueueEngine.on_line, ws.py).
bus = EventBus()
