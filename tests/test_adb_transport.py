"""Tests de nutcracker_core/adb_transport.py — salud del canal adb-over-wifi.

Contexto del bug que motivó el módulo (visto en uso real, 2026-07-27): con el
video WebUSB del dashboard reclamando el cable USB, nutcracker depende del
serial de red ("<ip>:5555"). Ese transporte vive en el daemon adb y se cae
solo (reinicio del daemon, doze del teléfono), dejando jobs en vuelo con
"device '<ip>:5555' not found" pese a que el teléfono responde a ping.

Nada acá toca un adb real: se parchea subprocess.run del módulo.
"""

from __future__ import annotations

import subprocess

from nutcracker_core import adb_transport


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


def _patch_adb(monkeypatch, handler):
    """Instala un fake de subprocess.run que registra los comandos adb."""
    calls: list[list[str]] = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(list(cmd))
        return handler(list(cmd))

    monkeypatch.setattr("nutcracker_core.adb_transport.subprocess.run", fake_run)
    monkeypatch.setattr("nutcracker_core.adb_transport._sleep", lambda *_: None)
    return calls


# ── is_network_serial ────────────────────────────────────────────────────────

def test_is_network_serial_distinguishes_tcp_from_usb():
    assert adb_transport.is_network_serial("172.20.10.6:5555")
    assert adb_transport.is_network_serial("emulator-5554:5555")
    assert not adb_transport.is_network_serial("ZY22GPM27J")
    assert not adb_transport.is_network_serial("")
    assert not adb_transport.is_network_serial(None)


# ── is_transport_alive ───────────────────────────────────────────────────────

def test_is_transport_alive_true_only_for_state_device(monkeypatch):
    _patch_adb(monkeypatch, lambda cmd: _completed(stdout="device\n"))
    assert adb_transport.is_transport_alive("172.20.10.6:5555")


def test_is_transport_alive_false_when_transport_missing(monkeypatch):
    # Caso real observado: el daemon perdió el transporte de red.
    _patch_adb(monkeypatch, lambda cmd: _completed(
        returncode=1, stderr="error: device '172.20.10.6:5555' not found",
    ))
    assert not adb_transport.is_transport_alive("172.20.10.6:5555")


def test_is_transport_alive_false_when_offline(monkeypatch):
    # Registrado pero inutilizable — no alcanza con que aparezca en adb devices.
    _patch_adb(monkeypatch, lambda cmd: _completed(stdout="offline\n"))
    assert not adb_transport.is_transport_alive("172.20.10.6:5555")


# ── ensure_available ─────────────────────────────────────────────────────────

def test_ensure_available_noop_for_usb_serial(monkeypatch):
    calls = _patch_adb(monkeypatch, lambda cmd: _completed(stdout="device\n"))
    assert adb_transport.ensure_available("ZY22GPM27J")
    assert calls == []


def test_ensure_available_noop_for_empty_serial(monkeypatch):
    calls = _patch_adb(monkeypatch, lambda cmd: _completed())
    assert adb_transport.ensure_available(None)
    assert calls == []


def test_ensure_available_does_not_reconnect_when_already_alive(monkeypatch):
    """`adb connect` arranca el daemon si no está corriendo, y un daemon nuevo
    re-reclama el cable USB — que es justo lo que le rompe el video al WebUSB.
    Si el transporte ya está vivo, no debe tocarse."""
    calls = _patch_adb(monkeypatch, lambda cmd: _completed(stdout="device\n"))

    assert adb_transport.ensure_available("172.20.10.6:5555")

    assert calls == [["adb", "-s", "172.20.10.6:5555", "get-state"]]
    assert not any("connect" in c for c in calls)


def test_ensure_available_reconnects_when_transport_dropped(monkeypatch):
    state = {"connected": False}

    def handler(cmd):
        if "connect" in cmd:
            state["connected"] = True
            return _completed(stdout="connected to 172.20.10.6:5555")
        if "get-state" in cmd:
            if state["connected"]:
                return _completed(stdout="device\n")
            return _completed(returncode=1, stderr="device not found")
        return _completed()

    calls = _patch_adb(monkeypatch, handler)

    assert adb_transport.ensure_available("172.20.10.6:5555")

    assert ["adb", "connect", "172.20.10.6:5555"] in calls
    # get-state antes (detectar la caída) y después (confirmar que revivió).
    assert len([c for c in calls if "get-state" in c]) == 2


def test_ensure_available_returns_false_when_reconnect_fails(monkeypatch):
    def handler(cmd):
        if "connect" in cmd:
            return _completed(stderr="failed to connect to 172.20.10.6:5555")
        return _completed(returncode=1, stderr="device not found")

    _patch_adb(monkeypatch, handler)
    assert not adb_transport.ensure_available("172.20.10.6:5555")


def test_ensure_available_survives_missing_adb_binary(monkeypatch):
    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        raise FileNotFoundError()

    monkeypatch.setattr("nutcracker_core.adb_transport.subprocess.run", fake_run)
    # No debe propagar: el comando real del job dará un error más específico.
    assert not adb_transport.ensure_available("172.20.10.6:5555")


def test_ensure_connected_retries_on_daemon_transient_error(monkeypatch):
    """Conectar WebUSB desestabiliza momentáneamente adb.exe en Windows; un
    único intento tiraría abajo el job por algo que se resuelve en 1-2s."""
    attempts = {"n": 0}

    def handler(cmd):
        attempts["n"] += 1
        if attempts["n"] < 3:
            return _completed(stderr="adb.exe: cannot connect to daemon")
        return _completed(stdout="connected to 172.20.10.6:5555")

    calls = _patch_adb(monkeypatch, handler)
    adb_transport.ensure_connected("172.20.10.6:5555")
    assert len(calls) == 3


def test_ensure_connected_does_not_retry_on_real_error(monkeypatch):
    calls = _patch_adb(monkeypatch, lambda cmd: _completed(
        stderr="failed to connect to '172.20.10.6:5555': Connection refused",
    ))
    adb_transport.ensure_connected("172.20.10.6:5555")
    assert len(calls) == 1


# ── TransportKeepAlive ───────────────────────────────────────────────────────

def test_keepalive_only_tracks_network_serials():
    ka = adb_transport.TransportKeepAlive(serials=["172.20.10.6:5555", "ZY22GPM27J"])
    assert ka.serials == {"172.20.10.6:5555"}

    ka.track("ZY22GPM27J")
    ka.track(None)
    assert ka.serials == {"172.20.10.6:5555"}

    ka.track("10.0.0.5:5555")
    assert ka.serials == {"172.20.10.6:5555", "10.0.0.5:5555"}


def test_keepalive_check_once_revives_each_tracked_serial(monkeypatch):
    calls = _patch_adb(monkeypatch, lambda cmd: _completed(
        returncode=1, stderr="device not found",
    ))

    ka = adb_transport.TransportKeepAlive(serials=["172.20.10.6:5555", "10.0.0.5:5555"])
    ka.check_once()

    connected = {c[2] for c in calls if c[1] == "connect"}
    assert connected == {"172.20.10.6:5555", "10.0.0.5:5555"}


def test_keepalive_check_once_survives_a_broken_serial(monkeypatch):
    """Un serial que revienta no debe matar el hilo y dejar sin vigilancia a
    los demás."""
    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr("nutcracker_core.adb_transport.subprocess.run", fake_run)

    ka = adb_transport.TransportKeepAlive(serials=["172.20.10.6:5555"])
    ka.check_once()  # no debe propagar


def test_keepalive_start_stop_is_idempotent(monkeypatch):
    _patch_adb(monkeypatch, lambda cmd: _completed(stdout="device\n"))

    ka = adb_transport.TransportKeepAlive(serials=["172.20.10.6:5555"], interval_seconds=10)
    ka.start()
    ka.start()  # segunda llamada: no debe levantar un segundo hilo
    assert ka._thread is not None
    ka.stop()
    assert ka._thread is None
    ka.stop()  # doble stop: no debe fallar


def test_keepalive_interval_has_a_floor():
    """Un intervalo diminuto martillaría adb (y con él, el USB) sin ganancia."""
    assert adb_transport.TransportKeepAlive(interval_seconds=1).interval_seconds == 10
