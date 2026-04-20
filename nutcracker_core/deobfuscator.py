"""
Desobfuscador automático para APKs protegidas con DexGuard/Arxan.

Flujo:
  1. Se genera el script FART con frida_bypass.generate_fart_script()
  2. El usuario lo ejecuta en el dispositivo con Frida
  3. runtime.py poll-ea /data/user/0/<package>/files/frida_dump/ mediante adb
  4. Hace adb pull cuando detecta los DEX volcados
  5. Decompila cada DEX con jadx para obtener el código limpio
  6. (Opcional) Aplica el decrypt_map.txt para parchear strings ofuscadas
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

# Re-exports desde runtime.py para mantener compatibilidad con imports existentes.
from nutcracker_core.runtime import (  # noqa: F401
    wait_for_dumps,
    pull_dumps,
)


# ── Helpers de adb ────────────────────────────────────────────────────────────


def check_adb() -> tuple[bool, str]:
    """
    Verifica que adb esté disponible y haya un dispositivo autorizado conectado.

    Returns:
        (ok, mensaje) — ok=True si hay dispositivo listo.
    """
    if not shutil.which("adb"):
        return False, "adb no encontrado en PATH. Instala Android SDK Platform-Tools."

    result = subprocess.run(
        ["adb", "devices"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not line.startswith("List of")
    ]
    if not lines:
        return False, "No hay dispositivos conectados (adb devices está vacío)."

    for line in lines:
        if "\tdevice" in line:
            device_id = line.split("\t")[0]
            return True, f"Dispositivo conectado: {device_id}"

    if any("unauthorized" in line for line in lines):
        return False, "Dispositivo encontrado pero no autorizado. Acepta el diálogo en el móvil."

    if any("offline" in line for line in lines):
        return False, "Dispositivo offline. Desconecta y vuelve a conectar."

    return False, f"Estado desconocido del dispositivo: {lines[0]}"


# ── Decompilación de DEX volcados ─────────────────────────────────────────────


def decompile_dumps(
    dex_files: list[Path],
    output_dir: Path,
    progress_callback=None,
) -> Path:
    """
    Decompila cada DEX volcado con jadx y fusiona el código fuente.

    Args:
        dex_files: Lista de archivos .dex descargados.
        output_dir: Directorio donde generar el código limpio.
        progress_callback: Función opcional callback(msg: str).

    Returns:
        output_dir con el código fuente desofuscado.

    Raises:
        RuntimeError si jadx no está disponible o falla en todos los DEX.
    """
    jadx = shutil.which("jadx")
    if not jadx:
        raise RuntimeError(
            "jadx no encontrado. Instala con: brew install jadx"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    any_success = False

    for i, dex in enumerate(dex_files, 1):
        if progress_callback:
            progress_callback(
                f"Decompilando {dex.name} ({i}/{len(dex_files)})..."
            )

        cmd = [
            jadx,
            "--deobf",           # desofuscar nombres ProGuard
            "--show-bad-code",   # incluir código con errores parciales
            "--no-imports",      # evitar colisiones de imports
            "-d", str(output_dir),
            str(dex),
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            # jadx puede devolver código != 0 en caso de errores parciales
            java_files = list(output_dir.rglob("*.java"))
            if java_files:
                any_success = True
        except subprocess.TimeoutExpired:
            if progress_callback:
                progress_callback(f"Timeout decompilando {dex.name}, continuando...")
        except Exception as exc:  # noqa: BLE001
            if progress_callback:
                progress_callback(f"Error en {dex.name}: {exc}")

    if not any_success:
        raise RuntimeError(
            f"jadx no generó ningún archivo .java en {output_dir}. "
            "Comprueba que los DEX volcados sean válidos."
        )

    return output_dir


# ── Aplicar mapa de descifrado de strings ─────────────────────────────────────


def apply_decrypt_map(source_dir: Path, decrypt_map: Path) -> int:
    """
    Aplica el mapa de descifrado de strings generado por el script FART.

    Busca en el código Java/smali los patrones "ClassName.method(arg)"
    y los reemplaza por el string literal descifrado.

    Args:
        source_dir: Directorio con el código fuente decompilado.
        decrypt_map: Ruta a decrypt_map.txt generado por el script FART.

    Returns:
        Número de sustituciones realizadas.
    """
    if not decrypt_map.exists():
        return 0

    # Parsear el mapa:  com.a.b.method(123)="valor descifrado"
    substitutions: list[tuple[str, str]] = []
    for raw_line in decrypt_map.read_text(encoding="utf-8", errors="replace").splitlines():
        raw_line = raw_line.strip()
        if '="' not in raw_line:
            continue
        call_part, _, value_part = raw_line.partition('="')
        decrypted = value_part.rstrip('"')

        # Construir un patrón de búsqueda legible en decompiled Java:
        # com.a.B.a(123) → "decrypted"
        # jadx suele generar: B.a(123) (solo clase simple + método)
        if "." in call_part:
            parts = call_part.split(".")
            # simple: ClassName.method(args)
            short_call = ".".join(parts[-2:])  # e.g. "B.a(123)"
            substitutions.append((short_call, decrypted))

    if not substitutions:
        return 0

    total_replacements = 0
    for java_file in source_dir.rglob("*.java"):
        try:
            original = java_file.read_text(encoding="utf-8", errors="replace")
            patched = original
            for call, value in substitutions:
                if call in patched:
                    # Reemplazar la llamada por el string literal
                    patched = patched.replace(call, f'"{value}"')
                    total_replacements += 1
            if patched != original:
                java_file.write_text(patched, encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

    return total_replacements
