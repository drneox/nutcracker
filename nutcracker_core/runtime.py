"""
Funciones compartidas de runtime para emulador y dispositivo físico.

Centraliza: launch_with_fart, launch_with_dexdump, wait_for_dumps,
pull_dumps, simulate_app_navigation, stop_frida, count_remote_dex.
"""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

# Tiempos de espera
DUMP_TIMEOUT = 300   # segundos esperando volcados DEX de FART
POLL_INTERVAL = 4    # segundos entre comprobaciones
FRIDA_TIMEOUT = 30   # segundos esperando inicialización de la app


# ── Helpers internos ──────────────────────────────────────────────────────────


def _is_emulator(serial: str) -> bool:
    """True si el serial corresponde a un emulador (no dispositivo físico)."""
    return (
        serial.startswith("emulator-")
        or serial.startswith("127.0.0.1:")
        or serial.startswith("localhost:")
    )


def _adb_cmd(adb: str, serial: str, *args: str) -> list[str]:
    """Construye comando adb con -s serial."""
    return [adb, "-s", serial, *args]


def _adb_shell(adb: str, serial: str, cmd: str, timeout: int = 10) -> str:
    """Ejecuta shell command en el dispositivo/emulador y devuelve stdout."""
    try:
        result = subprocess.run(
            _adb_cmd(adb, serial, "shell", cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


# ── Launch con FART ───────────────────────────────────────────────────────────


def launch_with_fart(
    serial: str,
    package: str,
    script_path: Path,
    tools: dict[str, str],
    progress_callback: Callable[[str], None] | None = None,
    frida_host: str | None = None,
) -> "tuple[subprocess.Popen, None] | tuple[None, str]":
    """
    Lanza la app con Frida + FART en background.

    Funciona tanto para emulador como para dispositivo físico.
    Si se indica frida_host (ej: "192.168.1.50:27042"), conecta vía -H en lugar
    de USB, saltándose los intentos -D/-U.

    Returns:
        (proc, None) si frida arrancó correctamente.
        (None, error_msg) si falló.
    """
    cb = progress_callback or (lambda _: None)
    frida_bin = tools.get("frida")
    if not frida_bin:
        msg = "frida CLI no encontrado — instala con: pip install frida-tools"
        cb(msg)
        return None, msg

    def _launch(args: list[str]) -> "tuple[subprocess.Popen, str | None]":
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # stdin=PIPE (no DEVNULL): frida entra en REPL y bloquea en read()
            # esperando input que nunca llega → permanece vivo mientras los
            # timers del script FART disparan. Con DEVNULL lee EOF y sale al instante.
            stdin=subprocess.PIPE,
            text=True,
        )
        time.sleep(3)
        if proc.poll() is not None:
            stderr_out = proc.stderr.read() if proc.stderr else ""
            stdout_out = proc.stdout.read() if proc.stdout else ""
            # Descartar el banner de frida para mostrar el error real
            combined = stderr_out + stdout_out
            lines = [l for l in combined.splitlines()
                     if not any(skip in l for skip in (
                         "/ _  |", "| (_| |", "> _  |", "/_/ |_|",
                         ". . . .", "frida.re", "Frida 1", "Commands:",
                         "help      ->", "object?   ->", "exit/quit",
                     ))]
            detail = "\n".join(lines).strip()[:600] or combined.strip()[:600]
            return proc, detail

        # Proceso vivo — vaciar stdout/stderr en background para que el buffer
        # (~64KB) no se llene y bloquee a frida cuando el script hace console.log().
        import threading

        def _drain(stream: "object") -> None:
            try:
                for _ in stream:  # type: ignore[attr-defined]
                    pass
            except Exception:
                pass

        if proc.stdout:
            threading.Thread(target=_drain, args=(proc.stdout,), daemon=True).start()
        if proc.stderr:
            threading.Thread(target=_drain, args=(proc.stderr,), daemon=True).start()

        return proc, None

    _DEAD_SYSTEM_KEYS = ("deadsystemexception", "deadsystemruntimeexception", "dead system")

    def _launch_with_retry(args: list[str], transport_flags: list[str] | None = None) -> "tuple[subprocess.Popen, str | None]":
        proc, err = _launch(args)
        return proc, err

    adb_bin = tools.get("adb", "adb")

    cb(f"Lanzando {package} con script FART...")

    # ── Conexión por host TCP (frida -H host:port) ────────────────────────────
    if frida_host:
        cb(f"Conectando vía host TCP a {frida_host}...")
        proc, err = _launch_with_retry(
            [frida_bin, "-H", frida_host, "-f", package, "-l", str(script_path)],
            transport_flags=[frida_bin, "-H", frida_host],
        )
        if err is None:
            return proc, None
        msg = f"frida terminó inesperadamente con -H {frida_host}: {err}"
        cb(msg)
        return None, msg

    if _is_emulator(serial):
        cb("Conectando al emulador vía -U...")
        proc, err = _launch_with_retry(
            [frida_bin, "-U", "-f", package, "-l", str(script_path)],
            transport_flags=[frida_bin, "-U"],
        )
        if err is None:
            return proc, None
        msg = f"frida terminó inesperadamente: {err}"
        cb(msg)
        return None, msg

    # Dispositivo físico: -D serial, con fallback a -U
    proc, err = _launch_with_retry(
        [frida_bin, "-D", serial, "-f", package, "-l", str(script_path)],
        transport_flags=[frida_bin, "-D", serial],
    )
    if err is None:
        return proc, None

    low = err.lower()
    if any(k in low for k in (
        "device not found", "unable to find device",
        "no usb device", "failed to enumerate devices",
        "not found",
    )):
        cb("Device no encontrado con -D; reintentando con -U...")
        proc_u, err_u = _launch_with_retry(
            [frida_bin, "-U", "-f", package, "-l", str(script_path)],
            transport_flags=[frida_bin, "-U"],
        )
        if err_u is None:
            return proc_u, None
        msg = f"frida terminó inesperadamente: {err_u}"
        cb(msg)
        return None, msg

    msg = f"frida terminó inesperadamente: {err}"
    cb(msg)
    return None, msg


# ── Launch con frida-dexdump ──────────────────────────────────────────────────


def launch_with_dexdump(
    serial: str,
    package: str,
    output_dir: Path,
    tools: dict[str, str],
    progress_callback: Callable[[str], None] | None = None,
    frida_host: str | None = None,
) -> "tuple[list[Path], str | None]":
    """
    Vuelca DEX de memoria con frida-dexdump. Funciona para emulador y device.

    Si se indica frida_host (ej: "192.168.1.50:27042"), conecta vía -H en lugar
    de -U/-D.

    Returns:
        (lista de .dex, None) si tuvo éxito.
        ([], mensaje_error) si falló.
    """
    cb = progress_callback or (lambda _: None)
    adb = tools.get("adb")
    dexdump_bin = tools.get("frida-dexdump")

    if not dexdump_bin:
        return [], "frida-dexdump no encontrado — instala con: pip install frida-dexdump"
    if not adb:
        return [], "adb no encontrado"

    output_dir.mkdir(parents=True, exist_ok=True)

    def _run_dexdump(args: list[str]) -> tuple[subprocess.CompletedProcess | None, str | None]:
        try:
            return subprocess.run(args, capture_output=True, text=True, timeout=120), None
        except subprocess.TimeoutExpired as exc:
            cmd = " ".join(args)
            detail = f"frida-dexdump timeout (>120s): {cmd}"
            if exc.stderr:
                stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else str(exc.stderr)
                detail = f"{detail} :: {stderr.strip()[:200]}"
            return None, detail

    # ── Remote host: use -H + -f (spawn mode) ────────────────────────────
    if frida_host:
        cb(f"Volcando DEX vía frida-dexdump -H {frida_host} -f {package}...")
        result, run_err = _run_dexdump([
            dexdump_bin, "-H", frida_host, "-f", package,
            "-o", str(output_dir),
        ])
        if run_err:
            return [], run_err
        dex_files = sorted(output_dir.glob("*.dex"))
        if not dex_files:
            detail = (result.stderr + result.stdout).strip()[:300]
            return [], f"frida-dexdump no volcó ningún DEX: {detail}"
        cb(f"{len(dex_files)} DEX volcados en {output_dir}")
        return dex_files, None

    # ── Local (USB/emulator): launch app, get PID, attach with -p ─────────
    target_label = "emulador" if _is_emulator(serial) else "dispositivo"
    cb(f"Arrancando {package} en el {target_label}...")
    subprocess.run(
        _adb_cmd(adb, serial, "shell", f"am force-stop {package}"),
        capture_output=True, timeout=10,
    )
    time.sleep(1)
    subprocess.run(
        _adb_cmd(adb, serial, "shell",
                  f"monkey -p {package} -c android.intent.category.LAUNCHER 1"),
        capture_output=True, timeout=15,
    )

    # Esperar PID — primera ronda (monkey, 15s)
    cb("Esperando que el proceso arranque...")
    deadline = time.monotonic() + 15
    pid: str | None = None
    while time.monotonic() < deadline:
        out = _adb_shell(adb, serial, f"pidof {package}", timeout=5)
        if out.isdigit() or (out and out.split()[0].isdigit()):
            pid = out.split()[0]
            break
        time.sleep(1)

    # Fallback 1: am start (más fiable que monkey en apps con anti-tampering)
    if not pid:
        cb("monkey no produjo proceso — intentando am start...")
        subprocess.run(
            _adb_cmd(adb, serial, "shell",
                     f"am start -a android.intent.action.MAIN "
                     f"-c android.intent.category.LAUNCHER {package}"),
            capture_output=True, timeout=15,
        )
        deadline2 = time.monotonic() + 20
        while time.monotonic() < deadline2:
            out = _adb_shell(adb, serial, f"pidof {package}", timeout=5)
            if out.isdigit() or (out and out.split()[0].isdigit()):
                pid = out.split()[0]
                break
            time.sleep(1)

    # Fallback 2: frida-dexdump en modo spawn (-f) — pausa la app antes de
    # que corra cualquier código (requiere frida-server activo)
    if not pid:
        cb("PID no encontrado — intentando spawn mode con frida-dexdump -f...")
        if _is_emulator(serial):
            spawn_result, spawn_err = _run_dexdump([
                dexdump_bin, "-D", serial, "-f", package, "-o", str(output_dir),
            ])
        else:
            spawn_result, spawn_err = _run_dexdump([
                dexdump_bin, "-U", "-f", package, "-o", str(output_dir),
            ])
        if not spawn_err:
            dex_files = sorted(output_dir.glob("*.dex"))
            if dex_files:
                cb(f"{len(dex_files)} DEX volcados en modo spawn")
                return dex_files, None
        return [], f"El proceso {package} no arrancó en el {target_label}"

    cb(f"Proceso PID={pid} — esperando inicialización ({FRIDA_TIMEOUT}s)...")
    time.sleep(FRIDA_TIMEOUT)

    cb(f"Volcando DEX de memoria con frida-dexdump (PID={pid})...")

    if _is_emulator(serial):
        result, run_err = _run_dexdump([dexdump_bin, "-U", "-p", pid, "-o", str(output_dir)])
    else:
        result, run_err = _run_dexdump([dexdump_bin, "-D", serial, "-p", pid, "-o", str(output_dir)])

    if run_err:
        return [], run_err

    dex_files = sorted(output_dir.glob("*.dex"))
    if not dex_files:
        detail_probe = (result.stderr + result.stdout).lower()
        if any(k in detail_probe for k in (
            "device not found", "unable to find device",
            "no usb device", "failed to enumerate devices",
            "not found",
        )):
            cb("frida-dexdump no encontró device; reintentando con -U...")
            result, run_err = _run_dexdump([dexdump_bin, "-U", "-p", pid, "-o", str(output_dir)])
            if run_err:
                return [], run_err
            dex_files = sorted(output_dir.glob("*.dex"))

    if not dex_files:
        detail = (result.stderr + result.stdout).strip()[:300]
        return [], f"frida-dexdump no volcó ningún DEX: {detail}"

    cb(f"{len(dex_files)} DEX volcados en {output_dir}")
    return dex_files, None


# ── Polling de volcados ───────────────────────────────────────────────────────


def count_remote_dex(
    serial: str,
    tools: dict[str, str],
    package: str,
) -> int:
    """Cuenta DEX volcados en el directorio de datos de la app."""
    adb = tools["adb"]
    remote_dir = f"/data/user/0/{package}/files/frida_dump/"
    out = _adb_shell(
        adb, serial,
        f"ls '{remote_dir}'*.dex 2>/dev/null | wc -l",
        timeout=10,
    )
    try:
        return int(out)
    except ValueError:
        return 0


def wait_for_dumps(
    serial: str,
    tools: dict[str, str],
    package: str,
    timeout: int = DUMP_TIMEOUT,
    min_dex: int = 1,
    progress_callback: Callable[[str], None] | None = None,
) -> bool:
    """
    Polling hasta detectar DEX volcados y que se estabilicen.

    Funciona para emulador y dispositivo físico.
    Espera dos polls consecutivos con el mismo conteo para confirmar estabilización.

    Returns:
        True si se detectaron al menos min_dex archivos estabilizados.
    """
    cb = progress_callback or (lambda _: None)
    remote_dir = f"/data/user/0/{package}/files/frida_dump/"
    deadline = time.monotonic() + timeout
    last_count = -1

    while time.monotonic() < deadline:
        count = count_remote_dex(serial, tools, package)
        remaining = int(deadline - time.monotonic())

        if count >= min_dex:
            if count == last_count:
                cb(f"{count} DEX volcados en {remote_dir} (estabilizado)")
                return True
            cb(f"{count} DEX detectados — esperando estabilización...")
        else:
            cb(f"Esperando volcados en {remote_dir} ({remaining}s)...")

        last_count = count
        time.sleep(POLL_INTERVAL)

    return False


def pull_dumps(
    serial: str,
    tools: dict[str, str],
    package: str,
    local_dir: Path,
    progress_callback: Callable[[str], None] | None = None,
) -> list[Path]:
    """
    Descarga los DEX volcados desde el dispositivo/emulador via adb pull.

    Returns:
        Lista de rutas .dex locales.
    """
    cb = progress_callback or (lambda _: None)
    adb = tools["adb"]
    remote_dir = f"/data/user/0/{package}/files/frida_dump/"
    local_dir.mkdir(parents=True, exist_ok=True)

    cb(f"Descargando volcados desde {serial}:{remote_dir}...")
    subprocess.run(
        _adb_cmd(adb, serial, "pull", remote_dir, str(local_dir)),
        capture_output=True,
        text=True,
        timeout=120,
    )

    dex_files = sorted(local_dir.rglob("*.dex"))
    cb(f"Descargados: {len(dex_files)} archivos .dex")
    return dex_files


# ── Simulación de UI ──────────────────────────────────────────────────────────


def simulate_app_navigation(
    serial: str,
    tools: dict[str, str],
    stop_event: "threading.Event",
    startup_delay: float = 8.0,
    progress_callback: Callable[[str], None] | None = None,
) -> None:
    """
    Simula interacción de usuario para forzar carga de clases.

    Funciona para emulador y dispositivo físico.
    Ejecuta en un thread separado; se detiene cuando stop_event está set.
    """
    cb = progress_callback or (lambda _: None)
    adb = tools.get("adb")
    if not adb:
        return

    W, H = 540, 960

    tap_points = [
        (W, H), (W, H // 2), (W, H + H // 4),
        (W // 2, H), (W + W // 4, H), (W, H - 200),
    ]
    swipes = [
        (W, H + 300, W, H - 300, 400),
        (W, H - 300, W, H + 300, 400),
        (W + 200, H, W - 200, H, 300),
    ]

    cb(f"UI: esperando {startup_delay:.0f}s para el arranque de la app...")
    stop_event.wait(timeout=startup_delay)
    if stop_event.is_set():
        return

    cb("UI: iniciando automatización de pantalla")
    cycle = 0
    while not stop_event.is_set():
        try:
            x, y = tap_points[cycle % len(tap_points)]
            subprocess.run(
                _adb_cmd(adb, serial, "shell", f"input tap {x} {y}"),
                capture_output=True, timeout=5,
            )
            stop_event.wait(timeout=1.5)
            if stop_event.is_set():
                break

            if cycle % 3 == 0:
                x1, y1, x2, y2, dur = swipes[(cycle // 3) % len(swipes)]
                subprocess.run(
                    _adb_cmd(adb, serial, "shell", f"input swipe {x1} {y1} {x2} {y2} {dur}"),
                    capture_output=True, timeout=5,
                )
                stop_event.wait(timeout=1.5)

            if cycle % 6 == 0:
                subprocess.run(
                    _adb_cmd(adb, serial, "shell", "input keyevent 66"),
                    capture_output=True, timeout=5,
                )
                stop_event.wait(timeout=1.0)

            if cycle % 10 == 0 and cycle > 0:
                subprocess.run(
                    _adb_cmd(adb, serial, "shell", "input keyevent 4"),
                    capture_output=True, timeout=5,
                )
                stop_event.wait(timeout=2.0)

            cycle += 1
            stop_event.wait(timeout=2.0)

        except Exception:  # noqa: BLE001
            stop_event.wait(timeout=3.0)

    cb("UI: automatización detenida")


# ── Cierre de proceso Frida ───────────────────────────────────────────────────


def stop_frida(proc: "subprocess.Popen | None") -> None:
    """Termina el proceso frida si sigue corriendo."""
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
