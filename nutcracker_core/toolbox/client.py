"""Capa de acceso uniforme a herramientas de análisis estático, sandboxeadas
en Docker (inspirado en la arquitectura de auto_pentest: toolbox estático en
contenedor + herramientas dinámicas -- adb/frida -- en el host, hablando con
el dispositivo físico real).

Por qué Docker solo para lo estático: jadx/apktool/radare2/etc. decompilan
contenido de terceros (APKs de apps reales, potencialmente maliciosas) -- el
contenedor aísla cualquier intento de explotar un bug del propio decompilador
del resto del host. Lo dinámico (adb, frida) necesita hablar directo con un
dispositivo físico conectado al host; meterlo en un contenedor solo agregaría
una capa de red/USB que resolver sin ganar aislamiento real (el aislamiento ahí
lo da tener un dispositivo de pruebas dedicado, no el proceso que lo controla).

Diseño **opt-in**: ``toolbox.enabled: false` (default) preserva 100% el
comportamiento actual -- cada módulo (decompiler.py, native_scanner.py, ...)
sigue invocando binarios locales vía ``shutil.which()`` tal como siempre. Con
``toolbox.enabled: true``, esos mismos módulos enrutan la misma llamada a
través de ``run()`` hacia el contenedor, sin cambiar su propia lógica.

Montaje de volumen: se monta el directorio de trabajo actual (``Path.cwd()``)
en el contenedor en la MISMA ruta absoluta (``-v {cwd}:{cwd} -w {cwd}``) --
suficiente porque todo el código de nutcracker opera sobre rutas relativas al
proyecto (``./downloads``, ``./decompiled``, ...), nunca fuera de él. Evita
necesitar lógica de traducción de rutas host↔contenedor.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from nutcracker_core.config import get as cfg_get

# Herramientas estáticas que ofrece la imagen (ver docker/Dockerfile.static).
# Documentativo -- run() no valida contra esta lista, así no hay que tocar
# este módulo cada vez que se agrega una herramienta al Dockerfile.
STATIC_TOOLS = (
    "aapt", "aapt2", "apktool", "baksmali", "smali", "jadx",
    "r2", "readelf", "nm", "objdump", "strings", "blint", "gitleaks", "apkid",
    "apksigner", "apkleaks",
)

DEFAULT_IMAGE = "nutcracker-toolbox-static:latest"
_DOCKERFILE = Path(__file__).parent / "docker" / "Dockerfile.static"


class ToolboxError(Exception):
    pass


def is_enabled(config: dict | None) -> bool:
    return bool(cfg_get(config or {}, "toolbox", "enabled", default=False))


def image_name(config: dict | None) -> str:
    return str(cfg_get(config or {}, "toolbox", "image", default=DEFAULT_IMAGE))


def _docker_bin() -> str:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        raise ToolboxError(
            "toolbox.enabled=true en config.yaml, pero 'docker' no está instalado "
            "o no está en el PATH."
        )
    return docker_bin


def image_exists(config: dict | None = None) -> bool:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False
    proc = subprocess.run(
        [docker_bin, "image", "inspect", image_name(config)],
        capture_output=True, text=True, timeout=30,
    )
    return proc.returncode == 0


def ensure_image(config: dict | None = None, build_timeout: int = 1800) -> None:
    """Construye la imagen del toolbox si todavía no existe localmente.

    No busca ni descarga desde un registry -- la imagen se define y se
    construye 100% local a partir de ``docker/Dockerfile.static``, sin
    depender de que el usuario tenga acceso a un registry propio."""
    if image_exists(config):
        return
    docker_bin = _docker_bin()
    proc = subprocess.run(
        [docker_bin, "build", "-f", str(_DOCKERFILE), "-t", image_name(config),
         str(_DOCKERFILE.parent)],
        capture_output=True, text=True, timeout=build_timeout,
    )
    if proc.returncode != 0:
        raise ToolboxError(
            f"Falló el build de la imagen del toolbox ({image_name(config)}).\n"
            f"stderr: {proc.stderr[-2000:]}"
        )


def run(
    tool: str,
    args: list[str],
    config: dict | None = None,
    timeout: int = 600,
    build_if_missing: bool = True,
) -> subprocess.CompletedProcess:
    """Corre ``tool args...`` dentro del contenedor del toolbox estático.

    Los ``args`` que sean rutas deben venir ya resueltas a absolutas por el
    llamador (ver decompiler.py) -- este módulo no adivina cuáles argumentos
    son rutas, solo monta ``Path.cwd()`` en la misma ruta dentro del
    contenedor para que esas rutas absolutas resuelvan igual en ambos lados.

    FIX (verificado en vivo, 2026-07-28): la imagen no define un usuario no-root,
    así que sin ``--user`` todo lo que el contenedor escribe en el volumen queda
    con dueño root -- confirmado con jadx real: el host ni siquiera podía
    borrar/sobreescribir su propio output después (`apktool --force` en un
    rerun habría fallado). Se corre como el UID:GID del host para que el
    resultado quede utilizable por el resto del pipeline, que corre como el
    usuario normal.
    """
    docker_bin = _docker_bin()
    if build_if_missing:
        ensure_image(config)

    cwd = str(Path.cwd().resolve())
    cmd = [
        docker_bin, "run", "--rm",
        "-v", f"{cwd}:{cwd}",
        "-w", cwd,
        "--user", f"{os.getuid()}:{os.getgid()}",
        image_name(config),
        tool, *args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def scratch_dir() -> Path:
    """Directorio temporal DENTRO del proyecto (bajo ``Path.cwd()``), para
    archivos intermedios (reportes de apkleaks/gitleaks, etc.) que herramientas
    corridas vía el toolbox necesitan leer/escribir.

    Necesario porque ``run()`` solo monta ``Path.cwd()`` en el contenedor --
    el ``/tmp`` del sistema (donde ``tempfile`` escribe por defecto) no es
    visible ahí. Se usa siempre (con o sin toolbox habilitado) para no tener
    dos rutas de código distintas según el modo."""
    d = Path.cwd() / ".nutcracker_tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d
