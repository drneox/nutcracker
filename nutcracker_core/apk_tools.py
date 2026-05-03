"""
Herramientas de manipulación de APK: signing, patching de splits,
parcheado de AndroidManifest.xml y gestión de instalación en emulador/device.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Callable

from .i18n import t

# Directorio caché para debug keystore
_CACHE_DIR = Path.home() / ".cache" / "nutcracker"


# ── Localizar herramientas de firma ───────────────────────────────────────────


def find_apksigner(sdk: Path | None = None) -> str | None:
    """Localiza apksigner en las build-tools del Android SDK."""
    if sdk is None:
        from nutcracker_core.device import find_sdk_root  # lazy import (evita circular)
        sdk = find_sdk_root()
    if sdk:
        bt_dir = sdk / "build-tools"
        if bt_dir.exists():
            for ver_dir in sorted(bt_dir.iterdir(), reverse=True):
                candidate = ver_dir / "apksigner"
                if candidate.exists():
                    return str(candidate)
    return shutil.which("apksigner")


def ensure_debug_keystore() -> Path | None:
    """
    Retorna la ruta al debug keystore, generándolo si no existe.

    Se almacena en el directorio de caché de nutcracker.
    Devuelve None si keytool no está disponible.
    """
    keystore = _CACHE_DIR / "debug.keystore"
    if keystore.exists():
        return keystore
    if not shutil.which("keytool"):
        return None
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "keytool", "-genkey", "-v",
            "-keystore", str(keystore),
            "-alias", "androiddebugkey",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-storepass", "android", "-keypass", "android",
            "-dname", "CN=Android Debug,O=Android,C=US",
        ],
        capture_output=True, text=True, timeout=30,
    )
    return keystore if result.returncode == 0 else None


# ── Splits APK ────────────────────────────────────────────────────────────────


def find_split_apks(apk_path: Path) -> list[Path]:
    """
    Busca los APK splits complementarios del mismo paquete.

    apkeep descarga bundles en un directorio con el nombre del paquete
    (ej. downloads/com.example.app/ → base.apk, split_config.arm64_v8a.apk, …)
    o bien como archivos hermanos con el mismo prefijo.

    Returns:
        Lista de todos los APKs del conjunto (incluido el propio apk_path).
    """
    collected: list[Path] = [apk_path]

    # Caso 0: base.apk dentro de carpeta de bundle
    if apk_path.name == "base.apk" and apk_path.parent.is_dir():
        for f in sorted(apk_path.parent.glob("*.apk")):
            if f not in collected:
                collected.append(f)
        if len(collected) > 1:
            return collected

    # Caso 1: directorio hermano con el nombre del paquete (apkeep)
    stem_dir = apk_path.parent / apk_path.stem
    if stem_dir.is_dir():
        for f in sorted(stem_dir.rglob("*.apk")):
            if f not in collected:
                collected.append(f)
        if len(collected) > 1:
            return collected

    # Caso 2: archivos hermanos con el mismo nombre base
    prefix = apk_path.stem
    for f in sorted(apk_path.parent.glob("*.apk")):
        if f == apk_path:
            continue
        stem = f.stem
        if stem.endswith("_patched") or stem.endswith("_unsigned") or stem.endswith("_resign"):
            continue

        is_same_prefix = f.name.startswith(prefix)
        is_split_like = (
            f.name.startswith("split_config.")
            or f.name.startswith("config.")
            or stem.startswith("split_")
            or stem.startswith("base.config.")
            or ".config." in f.name
        )

        if is_same_prefix or is_split_like:
            collected.append(f)

    # Deduplicar preservando orden
    if len(collected) > 1:
        seen: set[Path] = set()
        deduped: list[Path] = []
        for p in collected:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        collected = deduped

    return collected


# ── Parcheado del AndroidManifest.xml ─────────────────────────────────────────


def strip_required_splits_from_manifest(manifest_bytes: bytes) -> bytes:
    """
    Parcheado binario del AndroidManifest.xml: vacía el valor del atributo
    'requiredSplitTypes' en el string pool binario (formato AXML de Android).

    Estrategia: localiza el string que contiene los tipos requeridos
    (p. ej. "base__abi,base__density") y pone su longitud a 0 directamente
    en el string pool.

    Returns:
        Bytes del manifest parcheado. Si no se encuentra el atributo, devuelve
        el original sin cambios.
    """
    import struct as _struct

    data = bytearray(manifest_bytes)

    def ru32(off: int) -> int:
        return _struct.unpack_from("<I", data, off)[0]

    def ru16(off: int) -> int:
        return _struct.unpack_from("<H", data, off)[0]

    def ri32(off: int) -> int:
        return _struct.unpack_from("<i", data, off)[0]

    # ── Parsear string pool ───────────────────────────────────────────────────
    sp_base        = 8
    sp_header_size = ru16(sp_base + 2)
    n_strings      = ru32(sp_base + 8)
    flags          = ru32(sp_base + 16)
    strings_start  = ru32(sp_base + 20)
    is_utf8        = bool(flags & (1 << 8))
    offsets_base   = sp_base + sp_header_size

    def _str_abs_off(idx: int) -> int:
        off = ru32(offsets_base + idx * 4)
        return sp_base + strings_start + off

    def get_string(idx: int) -> str:
        abs_off = _str_abs_off(idx)
        if is_utf8:
            c = data[abs_off]
            if c & 0x80:
                c = ((c & 0x7F) << 8) | data[abs_off + 1]; abs_off += 1
            abs_off += 1
            b = data[abs_off]
            if b & 0x80:
                b = ((b & 0x7F) << 8) | data[abs_off + 1]; abs_off += 1
            abs_off += 1
            return data[abs_off:abs_off + b].decode("utf-8", errors="replace")
        else:
            char_len = ru16(abs_off)
            abs_off += 2
            return data[abs_off:abs_off + char_len * 2].decode("utf-16-le", errors="replace")

    def _zero_string_len(idx: int) -> None:
        abs_off = _str_abs_off(idx)
        if is_utf8:
            c = data[abs_off]
            if c & 0x80:
                data[abs_off]     = 0x00
                data[abs_off + 1] = 0x00
                abs_off += 2
            else:
                data[abs_off] = 0x00
                abs_off += 1
            b = data[abs_off]
            if b & 0x80:
                data[abs_off]     = 0x00
                data[abs_off + 1] = 0x00
                abs_off += 2
            else:
                data[abs_off] = 0x00
                abs_off += 1
            data[abs_off] = 0x00
        else:
            data[abs_off]     = 0x00
            data[abs_off + 1] = 0x00
            data[abs_off + 2] = 0x00
            data[abs_off + 3] = 0x00

    # ── Encontrar índice del string "requiredSplitTypes" ─────────────────────
    req_split_name_idx = None
    for i in range(n_strings):
        if get_string(i) == "requiredSplitTypes":
            req_split_name_idx = i
            break

    if req_split_name_idx is None:
        return bytes(data)

    # ── Buscar el elemento <manifest> y el atributo requiredSplitTypes ───────
    RES_XML_START_EL = 0x0102
    sp_size = ru32(sp_base + 4)
    pos = sp_base + sp_size

    while pos + 8 <= len(data):
        chunk_type  = ru16(pos)
        chunk_size  = ru32(pos + 4)
        if chunk_size == 0:
            break

        if chunk_type == RES_XML_START_EL:
            name_idx   = ri32(pos + 20)
            attr_off   = ru16(pos + 24)
            attr_size  = ru16(pos + 26)
            attr_count = ru16(pos + 28)

            if get_string(name_idx) == "manifest":
                attr_base = pos + 16 + attr_off
                for i in range(attr_count):
                    a = attr_base + i * attr_size
                    a_name    = ri32(a + 4)
                    a_raw_idx = ri32(a + 8)

                    if a_name == req_split_name_idx and a_raw_idx >= 0:
                        _zero_string_len(a_raw_idx)
                        val_data = ri32(a + 16)
                        if val_data == a_raw_idx:
                            _zero_string_len(val_data)
                        break
                break

        pos += chunk_size

    return bytes(data)


# ── Parcheado de split APK ────────────────────────────────────────────────────


def patch_split_apk(
    apk_path: Path,
    tools: dict[str, str],
    progress_callback: Callable[[str], None] | None = None,
) -> Path | None:
    """
    Genera una copia del APK con el atributo 'requiredSplitTypes' anulado
    y la re-firma con clave debug para permitir instalación en el emulador.

    Returns:
        Path al APK parcheado y firmado, o None si no se pudo parchear.
    """
    import zipfile as _zipfile

    cb = progress_callback or (lambda _: None)

    from nutcracker_core.device import find_sdk_root  # lazy import (evita circular)
    sdk = find_sdk_root()
    apksigner = find_apksigner(sdk)
    if not apksigner:
        cb(t("apk_no_apksigner"))
        return None

    keystore = ensure_debug_keystore()
    if not keystore:
        cb(t("apk_no_keytool"))
        return None

    cb(t("apk_patching_splits"))

    unsigned = apk_path.parent / f"{apk_path.stem}_unsigned.apk"
    aligned  = apk_path.parent / f"{apk_path.stem}_aligned.apk"
    patched  = apk_path.parent / f"{apk_path.stem}_patched.apk"

    REMOVE: set[str] = set()

    try:
        with _zipfile.ZipFile(apk_path, "r") as zin, \
             _zipfile.ZipFile(str(unsigned), "w") as zout:
            for item in zin.infolist():
                if item.filename in REMOVE:
                    cb(t("apk_removed_item", filename=item.filename))
                    continue
                if item.filename.startswith("META-INF/"):
                    continue

                raw = zin.read(item.filename)

                if item.filename == "AndroidManifest.xml":
                    patched_raw = strip_required_splits_from_manifest(raw)
                    if patched_raw != raw:
                        cb(t("apk_patched_manifest"))
                    raw = patched_raw

                zout.writestr(item, raw, compress_type=item.compress_type)
    except Exception as exc:
        cb(t("apk_repack_error", exc=exc))
        unsigned.unlink(missing_ok=True)
        return None

    zipalign = str(Path(apksigner).parent / "zipalign")
    if Path(zipalign).exists():
        cb(t("apk_aligning"))
        za_result = subprocess.run(
            [zipalign, "-f", "4", str(unsigned), str(aligned)],
            capture_output=True, text=True, timeout=60,
        )
        unsigned.unlink(missing_ok=True)
        if za_result.returncode != 0:
            cb(t("apk_zipalign_warning", err=za_result.stderr[:200]))
            aligned.rename(unsigned)
    else:
        aligned = unsigned

    cb(t("apk_signing"))
    sign_result = subprocess.run(
        [
            apksigner, "sign",
            "--ks", str(keystore),
            "--ks-pass", "pass:android",
            "--key-pass", "pass:android",
            "--ks-key-alias", "androiddebugkey",
            "--out", str(patched),
            str(aligned),
        ],
        capture_output=True, text=True, timeout=60,
    )
    aligned.unlink(missing_ok=True)

    if sign_result.returncode != 0:
        cb(t("apk_sign_error", err=sign_result.stderr[:300]))
        patched.unlink(missing_ok=True)
        return None

    cb(t("apk_patched_ready", name=patched.name))
    return patched


# ── Instalación de APK ────────────────────────────────────────────────────────


def install_apk(
    serial: str,
    tools: dict[str, str],
    apk_path: Path,
    package_name: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> bool:
    """
    Instala la APK (o el conjunto de splits) en el emulador/device.

    Estrategia:
      1. adb install -r -t -d  (reinstalar, allow test, allow downgrade)
      2. Si falla con INSTALL_FAILED_UPDATE_INCOMPATIBLE  → desinstalar y reintentar
      3. Si falla con INSTALL_FAILED_MISSING_SPLIT        → buscar splits y usar
                                                             adb install-multiple
      4. Si falla con INSTALL_FAILED_NO_MATCHING_ABIS     → AVD con ABI incompatible

    Returns:
        True si la instalación fue exitosa.
    """
    cb = progress_callback or (lambda _: None)
    adb = tools["adb"]

    def _run_install(apks: list[Path]) -> tuple[bool, str]:
        if len(apks) == 1:
            cmd = [adb, "-s", serial, "install", "-r", "-t", "-d", str(apks[0])]
        else:
            cmd = [adb, "-s", serial, "install-multiple", "-r", "-t", "-d",
                   *[str(f) for f in apks]]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        combined = result.stdout + result.stderr
        if "Success" in combined:
            return True, ""
        for line in combined.splitlines():
            if "Failure" in line or "INSTALL_FAILED" in line or "failed" in line.lower():
                return False, line.strip()
        if result.returncode == 0:
            return True, ""
        return False, combined[:300].strip()

    cb(t("apk_installing", serial=serial))
    ok, err = _run_install([apk_path])

    if ok:
        cb(t("apk_installed_ok"))
        return True

    cb(t("apk_install_initial_fail", err=err))

    # ── Splits requeridos ─────────────────────────────────────────────────────
    if "MISSING_SPLIT" in err:
        splits = find_split_apks(apk_path)
        if len(splits) > 1:
            cb(t("apk_bundle_detected", count=len(splits)))
            ok, err = _run_install(splits)
            if ok:
                cb(t("apk_installed_splits_ok", count=len(splits)))
                return True
            cb(t("apk_install_splits_fail", err=err))

        cb(t("apk_no_splits_patching"))
        patched = patch_split_apk(apk_path, tools, cb)
        if patched:
            ok, err = _run_install([patched])
            if ok:
                cb(t("apk_patched_installed_ok"))
                return True
            cb(t("apk_install_patched_fail", err=err))

        cb(t("apk_install_missing_split"))
        return False

    # ── Firma incompatible: desinstalar primero ───────────────────────────────
    if "UPDATE_INCOMPATIBLE" in err or "SIGNATURES_DO_NOT_MATCH" in err:
        pkg_to_uninstall = package_name or apk_path.stem
        cb(t("apk_incompatible_sig"))
        subprocess.run(
            [adb, "-s", serial, "uninstall", pkg_to_uninstall],
            capture_output=True, text=True, timeout=30,
        )
        ok, err = _run_install([apk_path])
        if ok:
            cb(t("apk_installed_after_uninstall"))
            return True

    # ── Mismatch de ABI ───────────────────────────────────────────────────────
    if "NO_MATCHING_ABIS" in err:
        cb(t("apk_no_matching_abis"))
        return False

    cb(t("apk_install_error", err=err))
    return False
