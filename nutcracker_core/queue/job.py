"""Representación en memoria de un job de la cola (ver engine.py)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Job:
    """Un job pendiente o en curso. El estado autoritativo vive en SQLite
    (tabla ``queue_jobs``, ver store/repository.py); esta instancia es solo el
    handle en memoria que usa QueueEngine para despacharlo."""

    target: str
    kind: str = "static"                 # static | dynamic | aipwn
    is_local_apk: bool = False
    serial: str | None = None
    priority: int = 0
    db_id: int | None = None             # id en queue_jobs, asignado al encolar
    created_at: float = field(default_factory=time.time)
    # Fuente del .apk para jobs "static" con target=package id: None (auto,
    # store por defecto) | "google-play" | "apk-pure" | "device" (adb pull del
    # ya instalado, ver downloader.DeviceInstalledDownloader). Solo en
    # memoria -- no persiste en SQLite (igual que is_local_apk, recalculado);
    # un job recuperado tras un reinicio del daemon (_load_queued_from_db)
    # cae a descarga normal en vez de perderse.
    source: str | None = None
