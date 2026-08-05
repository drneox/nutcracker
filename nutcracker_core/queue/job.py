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
    # Botón "+N iteraciones" del dashboard (job kind="aipwn"): continúa la
    # última sesión sin conclusión de este paquete en vez de arrancar una
    # conversación nueva -- ver agent_memory.load_resume_state() y
    # orchestrator.build_job_cmd(aipwn_resume=...). Solo en memoria, mismo
    # motivo que ``source``.
    aipwn_resume: bool = False
    aipwn_extra_iterations: int = 5
    # Relay "browser-as-bridge" (plan.md): cuando se setea, el subproceso del
    # job recibe NUTCRACKER_FRIDA_HOST=<este valor> en su env, para que aipwn
    # (aipwn.py:179) apunte frida al túnel local en vez de leer
    # strategies.frida_host del config. SÍ se persiste en SQLite (columna
    # queue_jobs.frida_host, migración 3 de store/db.py) -- a diferencia de
    # ``source``/``aipwn_resume``, perder esto en una recarga no degrada con
    # gracia (rompe el job en silencio con un síntoma engañoso, ver el fix en
    # vivo del 2026-08-05 documentado en plan.md).
    frida_host: str | None = None
    # Relay "browser-as-bridge": session_id de la sesión de relay a usar para
    # TODO lo que antes iba por adb (shell/install/pull/...) -- ver
    # engine.py::_run_job y toolbox/relay_adb_shim/adb. FIX de diseño
    # (verificado en vivo, 2026-08-04): el túnel TCP crudo para adb no es
    # viable (Android bloquea reenviar tcp: hacia el propio puerto de control
    # de adbd), así que a diferencia de frida_host, estas operaciones van por
    # RPC estructurado, no por un socket. `serial` NO se reescribe a una
    # dirección de loopback -- queda como el session_id elegido por el
    # operador, a propósito: así ``adb_transport.is_network_serial()`` no lo
    # confunde con un serial de red real y ``_ensure_transport`` no intenta
    # reconectarlo (ver el chequeo explícito ahí de todos modos, doble
    # resguardo). SÍ se persiste en SQLite -- mismo motivo que ``frida_host``
    # de arriba (perderlo NO degrada con gracia, a diferencia de ``source``).
    relay_session_id: str | None = None
