"""
Decompilación de APKs usando jadx o apktool.

Preferencia: jadx (produce código Java/Kotlin legible).
Fallback: apktool (produce ensamblador smali + recursos XML).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class DecompilerError(Exception):
    pass


def _find_tool(name: str) -> str | None:
    return shutil.which(name)


def get_available_tool() -> tuple[str, str] | tuple[None, None]:
    """
    Devuelve (nombre_tool, ruta) del primer decompilador disponible.
    Prioridad: jadx > apktool.
    """
    for name in ("jadx", "apktool"):
        path = _find_tool(name)
        if path:
            return name, path
    return None, None


def install_instructions() -> str:
    return (
        "No se encontró ningún decompilador. Instala uno:\n\n"
        "  [bold]jadx[/bold] (recomendado, produce Java/Kotlin):\n"
        "    brew install jadx\n\n"
        "  [bold]apktool[/bold] (produce smali + recursos):\n"
        "    brew install apktool"
    )


def decompile(apk_path: Path, output_dir: Path) -> Path:
    """
    Decompila la APK en output_dir.

    Returns:
        El directorio con los fuentes descompilados.

    Raises:
        DecompilerError si no hay herramienta disponible o falla la decompilación.
    """
    tool, tool_path = get_available_tool()

    if tool is None:
        raise DecompilerError(
            "No se encontró jadx ni apktool en el sistema.\n"
            "Instala jadx con: brew install jadx"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    if tool == "jadx":
        return _decompile_jadx(tool_path, apk_path, output_dir)
    else:
        return _decompile_apktool(tool_path, apk_path, output_dir)


def _decompile_jadx(jadx_path: str, apk_path: Path, output_dir: Path) -> Path:
    dest = output_dir / apk_path.stem
    dest.mkdir(parents=True, exist_ok=True)

    cmd = [
        jadx_path,
        "--deobf",                  # desofuscar nombres si es posible
        "--show-bad-code",          # incluir código que no pudo descompilarse bien
        "--no-imports",             # evitar ambigüedades de imports
        "-d", str(dest),
        str(apk_path),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)

    # jadx devuelve código != 0 cuando hay errores parciales, pero igual genera output
    if not any(dest.rglob("*.java")) and result.returncode != 0:
        raise DecompilerError(
            f"jadx falló sin generar código fuente.\n"
            f"stderr: {result.stderr[:500]}"
        )

    return dest


def _decompile_apktool(apktool_path: str, apk_path: Path, output_dir: Path) -> Path:
    dest = output_dir / apk_path.stem

    cmd = [
        apktool_path,
        "d",
        "--force",
        "-o", str(dest),
        str(apk_path),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if result.returncode != 0:
        raise DecompilerError(
            f"apktool falló.\nstderr: {result.stderr[:500]}"
        )

    return dest
