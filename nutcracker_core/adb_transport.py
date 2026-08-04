"""Salud del transporte adb-over-wifi (serial "host:puerto").

Contexto (encontrado en uso real, 2026-07-27): el dashboard usa WebUSB para el
video en vivo, que necesita reclamar en exclusiva la interfaz WinUSB del
teléfono. El daemon adb de Windows compite por *esa misma* interfaz: apenas
arranca enumera y abre toda interfaz ADB USB que vea, sin importar que todos
los comandos que le mandemos usen un serial de red. Por eso la estrategia del
proyecto es separar canales -- WebUSB se queda el cable, y nutcracker habla con
el teléfono por TCP/IP (``strategies.default_device_id`` = "<ip>:5555" tras un
``adb tcpip 5555``).

El punto débil de esa separación es que el canal TCP **no es durable**: la
conexión vive en el servidor adb local, así que se pierde ante un reinicio del
daemon (crash, ``adb kill-server``, sleep/wake), y también ante cortes de la
red del teléfono (dozing, hotspot). Cuando eso pasa, el serial de red
desaparece de ``adb devices`` y todo colapsa sobre el cable -- justo el
conflicto que la separación buscaba evitar. Se observó en vivo con 3 jobs
corriendo contra "172.20.10.6:5555" mientras ``adb -s 172.20.10.6:5555
get-state`` respondía "device not found" (el teléfono respondía a ping y tenía
el 5555 abierto: lo que se cayó fue el transporte, no el dispositivo).

Este módulo mantiene ese canal vivo: ``ensure_available()`` antes de cada job
que lo use, y ``TransportKeepAlive`` como chequeo periódico de fondo.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading

_log = logging.getLogger(__name__)

# Serial de red: "host:puerto" (ip, hostname o nombre de contenedor).
_NETWORK_SERIAL_RE = re.compile(r"^[\w.\-]+:\d+$")

# Fragmentos de stderr/stdout que indican una falla *transitoria* del daemon
# adb (no del device/paquete) -- vistos en uso real justo al conectar WebUSB
# (el navegador reclamando el USB desestabiliza momentáneamente adb.exe en
# Windows). Reintentar tras una pausa corta lo resuelve casi siempre --
# confirmado en uso real que el daemon se recupera solo en 1-2s.
_DAEMON_TRANSIENT_MARKERS = (
    "cannot connect to daemon",
    "failed to start daemon",
    "could not read ok from adb server",
    "daemon not running",
)

_CONNECT_TIMEOUT = 10
_STATE_TIMEOUT = 5
_RETRY_PAUSE = 1.5


def is_network_serial(serial: str | None) -> bool:
    """True si ``serial`` es un serial de red ("<host>:<puerto>") y no un
    serial USB (p.ej. "ZY22GPM27J")."""
    return bool(serial) and bool(_NETWORK_SERIAL_RE.match(serial))  # type: ignore[arg-type]


def is_daemon_transient_error(output: str) -> bool:
    low = output.lower()
    return any(marker in low for marker in _DAEMON_TRANSIENT_MARKERS)


def _adb(args: list[str], adb_bin: str, timeout: int) -> subprocess.CompletedProcess | None:
    """Corre adb devolviendo None si el binario no existe o el comando se
    colgó -- quien llama decide qué hacer (aquí nunca es fatal: el comando real
    del job fallará después con un error mucho más claro que un stacktrace de
    este helper)."""
    try:
        return subprocess.run(
            [adb_bin, *args], capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def kill_server(adb_bin: str = "adb") -> dict:
    """Mata el/los daemon(es) adb -- pensado para el botón "adb kill-server"
    del dashboard (libera el cable USB antes de conectar WebUSB, ver
    plugins/dashboard/webusb/).

    Corre el kill por DOS vías distintas, no solo una:
      - "wsl": ``adb_bin`` resuelto por el PATH normal (en este proyecto,
        típicamente un symlink al adb.exe de Windows vía interop de WSL).
      - "windows": explícitamente vía ``powershell.exe``, que resuelve el PATH
        *de Windows* -- puede apuntar a un adb.exe DISTINTO si el usuario tiene
        más de una instalación de platform-tools (p.ej. Android Studio además
        de la standalone que usa este proyecto). Un solo "adb kill-server"
        desde WSL no necesariamente mata ese otro proceso.

    No falla si no corre bajo WSL/Windows -- ``powershell.exe`` simplemente no
    existe en Linux nativo/macOS, y esa mitad queda en ``None`` en vez de
    error (no hay nada que matar ahí; no es una falla)."""
    result: dict = {"wsl": None, "windows": None}

    proc = _adb(["kill-server"], adb_bin, timeout=10)
    result["wsl"] = {
        "ok": proc is not None and proc.returncode == 0,
        "detail": ((proc.stdout or "") + (proc.stderr or "")).strip() if proc else "adb no encontrado",
    }

    powershell = shutil.which("powershell.exe")
    if powershell:
        try:
            win_proc = subprocess.run(
                [powershell, "-NoProfile", "-Command", "adb kill-server"],
                capture_output=True, text=True, timeout=15,
            )
            result["windows"] = {
                "ok": win_proc.returncode == 0,
                "detail": ((win_proc.stdout or "") + (win_proc.stderr or "")).strip(),
            }
        except (subprocess.TimeoutExpired, OSError) as exc:
            result["windows"] = {"ok": False, "detail": str(exc)}

    return result


def is_transport_alive(serial: str, adb_bin: str = "adb") -> bool:
    """True si el daemon adb tiene a ``serial`` registrado y utilizable.

    Usa ``get-state`` en vez de parsear ``adb devices`` porque distingue los
    tres casos que importan con un solo comando: transporte ausente (rc != 0,
    "device not found"), presente pero inutilizable ("offline", "unauthorized")
    y listo ("device")."""
    proc = _adb(["-s", serial, "get-state"], adb_bin, _STATE_TIMEOUT)
    if proc is None or proc.returncode != 0:
        return False
    return (proc.stdout or "").strip() == "device"


def ensure_connected(serial: str, adb_bin: str = "adb", attempts: int = 3) -> None:
    """``adb connect <serial>`` (idempotente) si ``serial`` es de red.

    No-op para seriales USB. Reintenta ante fallas transitorias del daemon en
    vez de rendirse en el primer intento."""
    if not is_network_serial(serial):
        return
    for attempt in range(attempts):
        proc = _adb(["connect", serial], adb_bin, _CONNECT_TIMEOUT)
        if proc is None:
            return
        output = (proc.stdout or "") + (proc.stderr or "")
        if not is_daemon_transient_error(output):
            return  # conectado, o un error real (no transitorio) -- no insistas
        if attempt < attempts - 1:
            _sleep(_RETRY_PAUSE)


def ensure_available(serial: str | None, adb_bin: str = "adb") -> bool:
    """Garantiza que ``serial`` esté usable antes de correr algo contra él.

    Retorna True si quedó listo (o si no hay nada que garantizar: serial vacío
    o USB, donde el propio comando del job reportará cualquier problema con un
    error más específico que el que podríamos dar acá).

    Chequea el estado *antes* de reconectar: ``adb connect`` arranca el daemon
    si no está corriendo, y un daemon nuevo re-reclama el cable USB -- si el
    transporte ya está vivo no hay razón para arriesgar ese efecto colateral
    contra el WebUSB del dashboard.
    """
    if not is_network_serial(serial):
        return True
    assert serial is not None
    if is_transport_alive(serial, adb_bin):
        return True
    _log.info("transporte adb caído para %s -- reconectando", serial)
    ensure_connected(serial, adb_bin)
    alive = is_transport_alive(serial, adb_bin)
    if alive:
        _log.info("transporte adb restablecido para %s", serial)
    else:
        _log.warning("no se pudo restablecer el transporte adb para %s", serial)
    return alive


def _sleep(seconds: float) -> None:
    """Indirección para que los tests puedan neutralizar las pausas sin
    parchear ``time.sleep`` global."""
    import time
    time.sleep(seconds)


class TransportKeepAlive:
    """Hilo de fondo que revisa periódicamente que los seriales de red sigan
    registrados en el daemon adb, y los reconecta si no.

    Complementa (no reemplaza) al chequeo por-job de ``QueueEngine``: sin esto,
    una caída del transporte durante un hueco sin jobs pasa inadvertida hasta
    el siguiente job, y mientras tanto cualquier ``adb`` suelto cae de vuelta al
    cable. Es un hilo daemon: no impide que el proceso termine.
    """

    def __init__(self, serials: list[str] | None = None, adb_bin: str = "adb",
                 interval_seconds: int = 60) -> None:
        self.adb_bin = adb_bin
        self.interval_seconds = max(10, interval_seconds)
        self._serials: set[str] = {s for s in (serials or []) if is_network_serial(s)}
        self._guard = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def track(self, serial: str | None) -> None:
        """Agrega un serial al conjunto vigilado (no-op si no es de red o si ya
        estaba). Permite que un job encolado con un serial distinto al default
        del config también quede cubierto."""
        if not is_network_serial(serial):
            return
        with self._guard:
            self._serials.add(serial)  # type: ignore[arg-type]

    @property
    def serials(self) -> set[str]:
        with self._guard:
            return set(self._serials)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="adb-transport-keepalive", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def check_once(self) -> None:
        for serial in self.serials:
            try:
                ensure_available(serial, self.adb_bin)
            except Exception:  # noqa: BLE001 - un serial roto no debe matar el hilo
                _log.exception("keepalive falló para %s", serial)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.check_once()
            self._stop.wait(self.interval_seconds)
