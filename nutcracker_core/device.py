"""
Gestión del emulador Android para desofuscación FART automatizada.

Flujo completo:
  1. Localizar Android SDK (emulator, adb) en rutas conocidas de macOS/Linux/Windows
  2. Listar AVDs disponibles y detectar su ABI (arm64, x86_64…)
  3. Iniciar AVD si no hay un emulador ya corriendo
  4. Esperar a que el sistema arranque (sys.boot_completed=1)
  5. Descargar frida-server de GitHub (versión == frida instalado en venv)
  6. Subir frida-server al emulador y arrancarlo como daemon
  7. Instalar la APK a analizar
  8. Lanzar la app con el script FART via frida CLI
  9. Esperar a que FART vuelque los DEX en /data/user/0/<package>/files/frida_dump/
 10. Hacer adb pull de los volcados
"""

from __future__ import annotations

import lzma
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable

# ── Rutas conocidas del SDK de Android en macOS/Linux ─────────────────────────

_SDK_SEARCH_PATHS: list[Path] = [
    Path.home() / "Library" / "Android" / "sdk",      # Android Studio macOS
    Path.home() / "Android" / "Sdk",                  # Android Studio Linux
    Path("/opt/android-sdk"),
    Path("/usr/local/android-sdk"),
]

# Mapa ABI Dalvik  →  sufijo frida-server de GitHub
_ABI_TO_FRIDA_ARCH: dict[str, str] = {
    "arm64-v8a":   "arm64",
    "x86_64":      "x86_64",
    "armeabi-v7a": "arm",
    "x86":         "x86",
}

# Directorio caché para frida-server descargado
_CACHE_DIR = Path.home() / ".cache" / "nutcracker"

# Tiempos de espera
BOOT_TIMEOUT    = 180   # segundos esperando a que el emulador arranque
FRIDA_TIMEOUT   = 30    # segundos esperando a que frida-server arranque
DUMP_TIMEOUT    = 300   # segundos esperando volcados DEX de FART
POLL_INTERVAL   = 4     # segundos entre comprobaciones


# ── Localizar herramientas Android SDK ────────────────────────────────────────


def find_sdk_root() -> Path | None:
    """Devuelve el directorio raíz del Android SDK o None si no se encuentra."""
    # 1. Variable de entorno explícita
    env_sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if env_sdk:
        p = Path(env_sdk)
        if (p / "emulator" / "emulator").exists():
            return p

    # 2. Rutas conocidas
    for candidate in _SDK_SEARCH_PATHS:
        if (candidate / "emulator" / "emulator").exists():
            return candidate

    return None


def find_sdk_tools(sdk_root: Path | None = None) -> dict[str, str]:
    """
    Busca las herramientas del SDK y devuelve un dict con sus rutas.

    Returns:
        {"emulator": "/path/to/emulator", "adb": "/path/to/adb", "frida": "/path/..."}
        Las claves ausentes indican que esa herramienta no se encontró.
    """
    tools: dict[str, str] = {}

    sdk = sdk_root or find_sdk_root()

    if sdk:
        em_path = sdk / "emulator" / "emulator"
        if em_path.exists():
            tools["emulator"] = str(em_path)

        adb_path = sdk / "platform-tools" / "adb"
        if adb_path.exists():
            tools["adb"] = str(adb_path)

    # Fallback a PATH
    if "emulator" not in tools:
        found = shutil.which("emulator")
        if found:
            tools["emulator"] = found

    if "adb" not in tools:
        found = shutil.which("adb")
        if found:
            tools["adb"] = found

    # frida CLI (mismo directorio que el python del venv, o PATH)
    frida_bin = Path(sys.executable).parent / "frida"
    if frida_bin.exists():
        tools["frida"] = str(frida_bin)
    elif (found := shutil.which("frida")):
        tools["frida"] = found

    # frida-dexdump CLI (mismo directorio que frida o PATH)
    dexdump_bin = Path(sys.executable).parent / "frida-dexdump"
    if dexdump_bin.exists():
        tools["frida-dexdump"] = str(dexdump_bin)
    elif (found := shutil.which("frida-dexdump")):
        tools["frida-dexdump"] = found

    # apksigner (build-tools del SDK, versión más reciente)
    if sdk:
        bt_dir = sdk / "build-tools"
        if bt_dir.exists():
            for ver_dir in sorted(bt_dir.iterdir(), reverse=True):
                candidate = ver_dir / "apksigner"
                if candidate.exists():
                    tools["apksigner"] = str(candidate)
                    break
    if "apksigner" not in tools:
        found = shutil.which("apksigner")
        if found:
            tools["apksigner"] = found

    return tools


# ── Gestión de AVDs ───────────────────────────────────────────────────────────


def list_avds(tools: dict[str, str]) -> list[str]:
    """Lista los AVDs disponibles instalados en el sistema."""
    emulator = tools.get("emulator")
    if not emulator:
        return []
    result = subprocess.run(
        [emulator, "-list-avds"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def get_avd_abi(avd_name: str) -> str:
    """
    Lee el archivo config.ini del AVD y devuelve el ABI.

    Fallback heurístico si no encuentra el archivo.
    """
    config = (
        Path.home() / ".android" / "avd" / f"{avd_name}.avd" / "config.ini"
    )
    if config.exists():
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("abi.type="):
                return line.split("=", 1)[1].strip()

    # Heurístico por nombre
    name_lo = avd_name.lower()
    if "arm64" in name_lo:
        return "arm64-v8a"
    if "x86_64" in name_lo:
        return "x86_64"
    if "x86" in name_lo:
        return "x86"
    return "x86_64"  # fallback conservador


def frida_arch_for_avd(avd_name: str) -> str:
    """Devuelve el sufijo de arquitectura que usa GitHub para frida-server."""
    abi = get_avd_abi(avd_name)
    return _ABI_TO_FRIDA_ARCH.get(abi, "x86_64")


def frida_arch_for_device(serial: str, tools: dict[str, str]) -> str:
    """Detecta la arquitectura de un dispositivo físico vía adb y devuelve el sufijo frida."""
    adb = tools.get("adb", "adb")
    result = subprocess.run(
        [adb, "-s", serial, "shell", "getprop", "ro.product.cpu.abi"],
        capture_output=True, text=True, timeout=10,
    )
    abi = result.stdout.strip()
    return _ABI_TO_FRIDA_ARCH.get(abi, "arm64")


# ── Estado del emulador ───────────────────────────────────────────────────────


def get_running_emulator(tools: dict[str, str]) -> str | None:
    """
    Devuelve el serial del primer emulador ya corriendo, o None.

    Ejemplo de serial: "emulator-5554"
    """
    adb = tools.get("adb")
    if not adb:
        return None
    result = subprocess.run(
        [adb, "devices"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("emulator-") and "\tdevice" in line:
            return line.split("\t")[0]
    return None


def _adb_shell(
    adb: str,
    serial: str,
    command: str,
    timeout: int = 15,
) -> str:
    """Ejecuta un comando en el shell del dispositivo y devuelve stdout."""
    result = subprocess.run(
        [adb, "-s", serial, "shell", command],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout.strip()


# ── Arrancar emulador ─────────────────────────────────────────────────────────


def start_emulator(
    avd_name: str,
    tools: dict[str, str],
    progress_callback: Callable[[str], None] | None = None,
    show_window: bool = False,
) -> str | None:
    """
    Arranca el AVD indicado y espera a que esté completamente listo.

    Returns:
        Serial del emulador (ej. "emulator-5554") o None si falla.
    """
    cb = progress_callback or (lambda _: None)
    emulator = tools.get("emulator")
    adb = tools.get("adb")
    if not emulator or not adb:
        cb("emulator o adb no encontrado en Android SDK")
        return None

    # ¿Ya hay un emulador corriendo?
    serial = get_running_emulator(tools)
    if serial:
        cb(f"Emulador ya en ejecución: {serial}")
        return serial

    cb(f"Iniciando AVD: {avd_name} ...")

    # Lanzar emulador en background (no bloqueante)
    emu_cmd = [emulator, "-avd", avd_name, "-no-snapshot-save", "-no-audio"]
    if not show_window:
        emu_cmd.append("-no-window")
    subprocess.Popen(
        emu_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Esperar a que aparezca en adb devices
    deadline = time.monotonic() + BOOT_TIMEOUT
    serial = None
    while time.monotonic() < deadline:
        serial = get_running_emulator(tools)
        if serial:
            break
        cb(f"Esperando que el emulador aparezca en adb devices...")
        time.sleep(POLL_INTERVAL)

    if not serial:
        cb("Timeout: el emulador no apareció en adb devices")
        return None

    # Esperar a que Android arranque completamente
    cb(f"Emulador {serial} detectado — esperando arranque de Android...")
    while time.monotonic() < deadline:
        boot = _adb_shell(adb, serial, "getprop sys.boot_completed", timeout=10)
        if boot == "1":
            cb(f"Android arrancado: {serial}")
            # Pequeña pausa extra para que se estabilicen los servicios
            time.sleep(3)
            return serial
        remaining = int(deadline - time.monotonic())
        cb(f"Esperando boot completo ({remaining}s)...")
        time.sleep(POLL_INTERVAL)

    cb("Timeout: Android no arrancó en el tiempo esperado")
    return None


# ── Descargar frida-server ────────────────────────────────────────────────────


def get_frida_version() -> str | None:
    """Devuelve la versión de frida instalada en el entorno Python actual."""
    try:
        import importlib.metadata
        return importlib.metadata.version("frida")
    except Exception:
        pass
    # Fallback: ejecutar frida CLI
    frida_bin = Path(sys.executable).parent / "frida"
    if frida_bin.exists():
        result = subprocess.run(
            [str(frida_bin), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or None
    return None


def download_frida_server(
    version: str,
    arch: str,
    cache_dir: Path = _CACHE_DIR,
    progress_callback: Callable[[str], None] | None = None,
) -> Path:
    """
    Descarga frida-server de GitHub Releases y lo descomprime.

    Usa caché en ~/.cache/nutcracker/ para no re-descargar en cada ejecución.

    Args:
        version: Versión de frida, ej. "17.9.1"
        arch:    Arquitectura frida, ej. "arm64", "x86_64"
        cache_dir: Directorio de caché local
        progress_callback: Función opcional de progreso

    Returns:
        Path al binario frida-server listo para subir.

    Raises:
        RuntimeError si la descarga falla.
    """
    cb = progress_callback or (lambda _: None)
    cache_dir.mkdir(parents=True, exist_ok=True)

    binary_name = f"frida-server-{version}-android-{arch}"
    cached = cache_dir / binary_name

    if cached.exists():
        cb(f"frida-server {version}-{arch} en caché: {cached.name}")
        return cached

    url = (
        f"https://github.com/frida/frida/releases/download/"
        f"{version}/frida-server-{version}-android-{arch}.xz"
    )
    cb(f"Descargando frida-server {version} ({arch}) desde GitHub...")

    try:
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
            xz_data = resp.read()
    except Exception as exc:
        raise RuntimeError(
            f"No se pudo descargar frida-server: {exc}\n"
            f"URL: {url}"
        ) from exc

    cb("Descomprimiendo frida-server...")
    binary_data = lzma.decompress(xz_data)
    cached.write_bytes(binary_data)
    cached.chmod(0o755)

    cb(f"frida-server guardado en caché: {cached.name}")
    return cached


# ── Configurar frida-server en el emulador ────────────────────────────────────


def setup_frida_server(
    serial: str,
    tools: dict[str, str],
    server_binary: Path,
    progress_callback: Callable[[str], None] | None = None,
    listen_all: bool = False,
    force_restart: bool = False,
) -> bool:
    """
    Sube frida-server al device/emulador y lo arranca como daemon.

    En emuladores eleva adbd con 'adb root'.
    En devices físicos usa 'su -c' (requiere root).

    Returns:
        True si frida-server está corriendo correctamente.
    """
    cb = progress_callback or (lambda _: None)
    adb = tools["adb"]
    remote_path = "/data/local/tmp/frida-server"

    # ¿Ya está corriendo?
    ps_out = _adb_shell(adb, serial, "ps -A | grep frida-server", timeout=10)
    if "frida-server" in ps_out:
        if not force_restart:
            cb("frida-server ya está corriendo")
            return True
        cb("Reiniciando frida-server (force_restart)...")
        _adb_shell(adb, serial, "killall frida-server 2>/dev/null; sleep 1", timeout=8)

    # Push del binario
    cb("Subiendo frida-server al device...")
    result = subprocess.run(
        [adb, "-s", serial, "push", str(server_binary), remote_path],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        cb(f"Error subiendo frida-server: {result.stderr[:200]}")
        return False

    _adb_shell(adb, serial, f"chmod 755 {remote_path}", timeout=10)

    # Intentar 'adb root' primero — funciona en emuladores y devices userdebug/rooteados con adbd root
    cb("Elevando permisos con adb root...")
    root_result = subprocess.run(
        [adb, "-s", serial, "root"],
        capture_output=True, text=True, timeout=10,
    )
    root_ok = root_result.returncode == 0 and "cannot" not in root_result.stdout.lower()

    # Deshabilitar SELinux enforcing — necesario para que el helper de Frida pueda arrancar
    selinux_out = _adb_shell(adb, serial, "getenforce", timeout=5).strip()
    if selinux_out.lower() == "enforcing":
        cb("SELinux enforcing detectado — poniendo en permissive...")
        if root_ok:
            _adb_shell(adb, serial, "setenforce 0", timeout=5)
        else:
            # Intentar con su — en dispositivos físicos Magisk/SuperSU puede
            # mostrar un popup pidiendo autorización, por eso el timeout largo
            cb("  (si aparece un popup de root en el dispositivo, acéptalo)")
            try:
                subprocess.run(
                    [adb, "-s", serial, "shell", "su 0 setenforce 0"],
                    capture_output=True, timeout=30,
                )
            except subprocess.TimeoutExpired:
                cb("⚠  Timeout esperando autorización de root para setenforce")
        selinux_after = _adb_shell(adb, serial, "getenforce", timeout=5).strip()
        if selinux_after.lower() == "enforcing":
            cb(
                "⚠  No se pudo cambiar SELinux a permissive. "
                "Frida puede fallar con: assertion failed (res == OK).\n"
                f"  Comando manual: adb -s {serial} shell su 0 setenforce 0"
            )
        else:
            cb("SELinux permissive OK")

    _bin_cmd = f"{remote_path} -l 0.0.0.0" if listen_all else remote_path
    # Limpiar LD_PRELOAD para evitar conflictos con el mecanismo de inyección de Frida.
    # Magisk/Zygisk y algunos módulos LSPosed lo setean en el shell, y los procesos hijos
    # lo heredan — lo que provoca fallos al attacharse o spawnar la app.
    _launch_cmd = f"unset LD_PRELOAD; {_bin_cmd}"
    if root_ok:
        time.sleep(1.5)  # adbd necesita un momento para reiniciarse como root
        subprocess.Popen(
            [adb, "-s", serial, "shell", f"{_launch_cmd} &"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        # Fallback: su (Magisk y otros managers de root)
        cb("adb root no disponible — intentando con su...")
        launched = False
        for su_cmd in [f"su 0 sh -c '{_launch_cmd} &'", f"su -c '{_launch_cmd} &'"]:
            r = subprocess.run(
                [adb, "-s", serial, "shell", su_cmd],
                capture_output=True, text=True, timeout=15,
            )
            combined = (r.stdout + r.stderr).lower()
            if "not found" in combined or "permission denied" in combined:
                continue
            launched = True
            break
        if not launched:
            cb(
                "No se pudo arrancar frida-server.\n"
                "Prueba: adb root, o root con Magisk y 'su 0' habilitado.\n"
                f"Comando manual: adb -s {serial} shell \"su 0 sh -c 'unset LD_PRELOAD; {remote_path} &'\""
            )
            return False

    # Esperar a que arranque
    deadline = time.monotonic() + FRIDA_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(2)
        ps_out = _adb_shell(adb, serial, "ps -A | grep frida-server", timeout=10)
        if "frida-server" in ps_out:
            cb("frida-server arrancado correctamente")
            return True
        cb("Esperando a que frida-server arranque...")

    cb("Timeout: frida-server no arrancó")
    return False


# ── APK tools (delegan a nutcracker_core.apk_tools) ──────────────────────────
# Re-exportadas para mantener compatibilidad con imports existentes.

from nutcracker_core.apk_tools import (  # noqa: E402
    find_apksigner as _find_apksigner,
    ensure_debug_keystore as _ensure_debug_keystore,
    find_split_apks as _find_split_apks,
    strip_required_splits_from_manifest as _strip_required_splits_from_manifest,
    patch_split_apk as _patch_split_apk,
    install_apk,
)
from nutcracker_core.runtime import (  # noqa: E402
    launch_with_fart,
    launch_with_dexdump,
    simulate_app_navigation,
    count_remote_dex,
    wait_for_dumps,
    pull_dumps,
    stop_frida,
)
