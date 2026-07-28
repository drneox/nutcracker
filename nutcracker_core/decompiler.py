"""
Decompilación de APKs usando jadx o apktool.

Preferencia: jadx (produce código Java/Kotlin legible).
Fallback: apktool (produce ensamblador smali + recursos XML).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from nutcracker_core import toolbox

# Sentinel devuelto como "ruta" por get_available_tool()/_find_tool() cuando
# la herramienta se resuelve vía el toolbox de Docker en vez de un binario
# local -- _decompile_jadx/_decompile_apktool lo usan para elegir entre
# subprocess.run() local y toolbox.run().
TOOLBOX = "toolbox"


class DecompilerError(Exception):
    pass


def _find_tool(name: str, config: dict | None = None) -> str | None:
    if toolbox.is_enabled(config) and name in toolbox.STATIC_TOOLS:
        return TOOLBOX
    return shutil.which(name)


def get_available_tool(config: dict | None = None) -> tuple[str, str] | tuple[None, None]:
    """
    Devuelve (nombre_tool, ruta) del primer decompilador disponible.
    Prioridad: jadx > apktool.

    Con ``toolbox.enabled: true`` en config.yaml, jadx siempre "está
    disponible" (la imagen lo garantiza) sin necesitar el binario en el host
    -- ver nutcracker_core/toolbox/client.py.
    """
    for name in ("jadx", "apktool"):
        path = _find_tool(name, config)
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


def decompile(
    apk_path: Path, output_dir: Path, dest_name: str | None = None,
    config: dict | None = None,
) -> Path:
    """
    Decompila la APK en output_dir.

    ``dest_name`` nombra el subdirectorio de salida (``output_dir / dest_name``).
    Por defecto usa ``apk_path.stem`` -- pero para Android App Bundles, apkeep
    guarda el APK base literalmente como "base.apk" para *cualquier* paquete,
    así que ese default hace colisionar en el mismo directorio a apps
    distintas. Encontrado en vivo (2026-07-28): jobs estáticos concurrentes de
    distintos paquetes (todos descargados como "base.apk") decompilando a la
    vez hacia "decompiled/base/" -- apktool --force de uno pisaba a mitad de
    camino el output que el otro job estaba escaneando, dejando
    "files_scanned: 0" pese a que la app no tenía nada que ver con eso.
    Orchestrator ya pasa ``dest_name=package`` para evitarlo.

    ``config`` habilita el toolbox de Docker si ``toolbox.enabled: true``
    (ver nutcracker_core/toolbox/) -- opt-in, sin ``config`` (o con el flag en
    false) se comporta exactamente igual que antes, contra binarios locales.

    Returns:
        El directorio con los fuentes descompilados.

    Raises:
        DecompilerError si no hay herramienta disponible o falla la decompilación.
    """
    tool, tool_path = get_available_tool(config)
    dest_name = dest_name or apk_path.stem

    if tool is None:
        raise DecompilerError(
            "No se encontró jadx ni apktool en el sistema.\n"
            "Instala jadx con: brew install jadx"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    if tool == "jadx":
        try:
            return _decompile_jadx(tool_path, apk_path, output_dir, dest_name, config)
        except DecompilerError as jadx_exc:
            apktool_path = _find_tool("apktool", config)
            if apktool_path:
                return _decompile_apktool(apktool_path, apk_path, output_dir, dest_name, config)
            raise DecompilerError(
                f"{jadx_exc}\n\n"
                "No hay fallback disponible con apktool."
            ) from jadx_exc
    else:
        return _decompile_apktool(tool_path, apk_path, output_dir, dest_name, config)


def _run_tool(tool_path: str, tool_name: str, args: list[str], config: dict | None,
              timeout: int) -> subprocess.CompletedProcess:
    """Corre ``tool_name`` local (``tool_path`` de ``shutil.which``) o vía el
    toolbox de Docker (cuando ``tool_path is TOOLBOX``), según corresponda.
    Los ``args`` ya vienen con rutas absolutas -- ``toolbox.run()`` monta
    ``Path.cwd()`` en el contenedor en la misma ruta que en el host, así que
    una ruta absoluta resuelve igual en ambos lados."""
    if tool_path is TOOLBOX:
        return toolbox.run(tool_name, args, config=config, timeout=timeout)
    return subprocess.run([tool_path, *args], capture_output=True, text=True, timeout=timeout)


def _decompile_jadx(jadx_path: str, apk_path: Path, output_dir: Path, dest_name: str,
                     config: dict | None = None) -> Path:
    dest = output_dir / dest_name
    dest.mkdir(parents=True, exist_ok=True)

    args = [
        "--deobf",                  # desofuscar nombres si es posible
        "--show-bad-code",          # incluir código que no pudo descompilarse bien
        "--no-imports",             # evitar ambigüedades de imports
        "-d", str(dest.resolve()),
        str(apk_path.resolve()),
    ]

    try:
        result = _run_tool(jadx_path, "jadx", args, config, timeout=900)
    except subprocess.TimeoutExpired as exc:
        raise DecompilerError(
            "jadx excedió el tiempo límite de 900s durante la decompilación. "
            "Intentando fallback con apktool si está disponible."
        ) from exc
    except toolbox.ToolboxError as exc:
        raise DecompilerError(str(exc)) from exc

    # jadx devuelve código != 0 cuando hay errores parciales, pero igual genera output
    if not any(dest.rglob("*.java")) and result.returncode != 0:
        raise DecompilerError(
            f"jadx falló sin generar código fuente.\n"
            f"stderr: {result.stderr[:500]}"
        )

    return dest


def _decompile_apktool(apktool_path: str, apk_path: Path, output_dir: Path, dest_name: str,
                        config: dict | None = None) -> Path:
    dest = output_dir / dest_name

    args = ["d", "--force", "-o", str(dest.resolve()), str(apk_path.resolve())]

    try:
        result = _run_tool(apktool_path, "apktool", args, config, timeout=600)
    except toolbox.ToolboxError as exc:
        raise DecompilerError(str(exc)) from exc

    if result.returncode != 0:
        raise DecompilerError(
            f"apktool falló.\nstderr: {result.stderr[:500]}"
        )

    return dest


def extract_manifest(apk_path: Path, output_dir: Path, name_hint: str | None = None,
                      config: dict | None = None) -> Path | None:
    """
    Extrae y decodifica únicamente el AndroidManifest.xml del APK.

    Útil cuando el código fue obtenido por runtime dump (Frida) y no hay
    manifest disponible, pero sí existe el APK original.

    ``name_hint`` identifica el directorio temporal (por defecto
    ``apk_path.stem``) -- mismo motivo que en ``decompile()``: "base.apk" no es
    único entre paquetes distintos (App Bundles), así que sin un hint más
    específico dos extracciones concurrentes de apps distintas podrían pisarse.

    Intenta primero con apktool (--no-src), luego con jadx (--no-res).
    Devuelve la ruta al AndroidManifest.xml decodificado, o None si falla.
    """
    name_hint = name_hint or apk_path.stem

    # ── Intento 1: apktool --no-src (solo recursos + manifest) ───────────────
    apktool_path = _find_tool("apktool", config)
    if apktool_path:
        tmp = output_dir / f"_manifest_apktool_{name_hint}"
        try:
            _run_tool(
                apktool_path, "apktool",
                ["d", "--force", "--no-src", "-o", str(tmp.resolve()), str(apk_path.resolve())],
                config, timeout=120,
            )
            manifest = tmp / "AndroidManifest.xml"
            if manifest.exists():
                return manifest
        except (subprocess.TimeoutExpired, OSError, toolbox.ToolboxError):
            pass

    # ── Intento 2: jadx --no-res (sin recursos, pero extrae manifest decodificado) ─
    jadx_path = _find_tool("jadx", config)
    if jadx_path:
        tmp = output_dir / f"_manifest_jadx_{name_hint}"
        try:
            _run_tool(
                jadx_path, "jadx",
                ["--no-res", "--no-src", "-d", str(tmp.resolve()), str(apk_path.resolve())],
                config, timeout=120,
            )
            # jadx coloca el manifest en resources/AndroidManifest.xml
            for candidate in [
                tmp / "resources" / "AndroidManifest.xml",
                tmp / "AndroidManifest.xml",
            ]:
                if candidate.exists():
                    return candidate
        except (subprocess.TimeoutExpired, OSError, toolbox.ToolboxError):
            pass

    # ── Intento 3: unzip directo (manifest binario — no decodificado, no válido) ─
    # No intentar: el AXML binario no es parseable por ManifestAnalyzer sin decodificar.

    return None
