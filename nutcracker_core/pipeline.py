"""Pipeline de extracción runtime de DEX: emulador Android y dispositivo físico."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from nutcracker_core.config import get as cfg_get
from nutcracker_core.deobfuscator import check_adb
from nutcracker_core.apk_tools import install_apk as emulator_install_apk
from nutcracker_core.device import (
    download_frida_server,
    find_sdk_tools,
    frida_arch_for_avd,
    frida_arch_for_device,
    get_frida_version,
    setup_frida_server,
    start_emulator,
)
from nutcracker_core.frida_bypass import fart_run_instructions, generate_fart_script
from nutcracker_core.runtime import (
    launch_with_dexdump,
    launch_with_fart,
    pull_dumps,
    simulate_app_navigation,
    stop_frida,
    wait_for_dumps,
)

console = Console()


# ── Resultado de extracción ───────────────────────────────────────────────────


@dataclass
class ExtractionResult:
    """Datos producidos por una extracción runtime de DEX."""

    dex_files: list[Path]
    method_used: str
    local_dump_dir: Path
    clean_dir: Path


# ── Config helpers (parametrizados con cfg dict) ──────────────────────────────


def _auto(cfg: dict, key: str) -> bool | None:
    auto_block = cfg.get("auto", {})
    if not isinstance(auto_block, dict):
        return None
    val = auto_block.get(key)
    return bool(val) if val is not None else None


def _unattended(cfg: dict) -> bool:
    return bool(cfg_get(cfg, "auto", "unattended", default=False))


def _ask_or_auto(cfg: dict, prompt: str, key: str, default: bool = False) -> bool:
    cfg_val = _auto(cfg, key)
    if cfg_val is not None:
        tag = "si" if cfg_val else "no"
        console.print(f"[dim]  (config auto.{key}={tag} — saltando pregunta)[/dim]")
        return cfg_val
    if _unattended(cfg):
        tag = "si" if default else "no"
        console.print(f"[dim]  (auto.unattended=true — {prompt} => {tag})[/dim]")
        return default
    return click.confirm(prompt, default=default)


# ── Utilidades ADB ────────────────────────────────────────────────────────────


def connected_adb_devices() -> list[str]:
    """Devuelve IDs de dispositivos adb en estado device."""
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:  # noqa: BLE001
        return []

    devices: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("List of"):
            continue
        if "\tdevice" in line:
            devices.append(line.split("\t", 1)[0])
    return devices


def is_emulator_serial(serial: str) -> bool:
    s = serial.strip().lower()
    return s.startswith("emulator-") or s.startswith("127.0.0.1:") or s.startswith("localhost:")


# ── Pipeline helpers ──────────────────────────────────────────────────────────


def _pick_avd(cfg: dict, avds: list[str]) -> str:
    """Muestra un menú y devuelve el AVD elegido."""
    preferred = str(cfg_get(cfg, "strategies", "default_emulator_avd", default="")).strip()

    if preferred:
        if preferred in avds:
            console.print(f"[dim]  Usando AVD por config: {preferred}[/dim]")
            return preferred
        console.print(
            f"[yellow]⚠[/yellow]  default_emulator_avd='{preferred}' no existe. "
            "Usando el primero disponible."
        )

    if len(avds) == 1:
        return avds[0]
    if _unattended(cfg):
        console.print(f"[dim]  (auto.unattended=true → usando '{avds[0]}')[/dim]")
        return avds[0]
    console.print("\n  AVDs disponibles:")
    for i, avd in enumerate(avds, 1):
        console.print(f"    [cyan]{i}[/cyan]) {avd}")
    idx = click.prompt(
        "  Elige un AVD",
        default=1,
        type=click.IntRange(1, len(avds)),
    )
    return avds[idx - 1]


def deobf_method_order(cfg: dict, protected: bool = True) -> list[str]:
    """
    Devuelve el orden de métodos de extracción runtime.

    Config:
      pipelines.<protected|unprotected>.runtime_methods
    Fallback:
      deobfuscation.methods_order
    """
    scope = "protected" if protected else "unprotected"
    raw = cfg_get(cfg, "pipelines", scope, "runtime_methods")
    if not raw and not protected:
        raw = cfg_get(cfg, "pipelines", "protected", "runtime_methods")
    if not raw:
        raw = cfg_get(cfg, "deobfuscation", "methods_order")

    aliases = {
        "frida_server": "frida_server",
        "frida-server": "frida_server",
        "server": "frida_server",
        "gadget": "gadget",
        "gadget_inject": "gadget",
        "frida_gadget": "gadget",
        "fart": "fart",
    }

    if isinstance(raw, list) and raw:
        ordered: list[str] = []
        for item in raw:
            key = aliases.get(str(item).strip().lower())
            if key and key not in ordered:
                ordered.append(key)
        if ordered:
            return ordered

    return ["frida_server", "gadget", "fart"]


# ── Spinner helper ────────────────────────────────────────────────────────────


def _with_spinner(label: str, fn):
    """Ejecuta fn(callback) dentro de un spinner. Devuelve el resultado."""
    out = [None]
    last_msgs: list[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(label, total=None)

        def _update(msg: str) -> None:
            last_msgs.append(msg)
            progress.update(task, description=msg)

        out[0] = fn(_update)

    _with_spinner._last_msgs = last_msgs  # type: ignore[attr-defined]
    return out[0]


# ── Pipeline: Emulador ────────────────────────────────────────────────────────


def do_fart_emulator(
    cfg: dict,
    package: str,
    apk_path: Path,
    sdk_tools: dict,
    avds: list[str],
) -> ExtractionResult | None:
    """Flujo FART totalmente automatizado usando el emulador Android."""

    avd_name = _pick_avd(cfg, avds)
    arch = frida_arch_for_avd(avd_name)
    local_dump_dir = Path("./decompiled") / f"dexguard_dump_{package}"
    clean_dir = local_dump_dir / "source"

    frida_proc = None

    try:
        method_order = deobf_method_order(cfg, protected=True)
        console.print(f"[dim]  Pipeline de extracción: {' -> '.join(method_order)}[/dim]")

        # ── A. Descargar frida-server ─────────────────────────────────────
        _cfg_ver = str(cfg_get(cfg, "strategies", "frida_server_version") or "").strip()
        frida_ver = _cfg_ver or get_frida_version()
        if not frida_ver:
            console.print("[red]✘[/red] No se pudo detectar la versión de frida instalada.")
            return None

        # Sincronizar frida + frida-dexdump Python si la versión difiere
        _installed_frida = get_frida_version()
        if _installed_frida and _installed_frida != frida_ver:
            console.print(
                f"  [dim]frida instalado: {_installed_frida} → "
                f"sincronizando con frida-server {frida_ver}...[/dim]"
            )
            _pip_result = subprocess.run(
                [
                    sys.executable, "-m", "pip", "install", "--quiet",
                    f"frida=={frida_ver}",
                ],
                capture_output=True, text=True, timeout=120,
            )
            if _pip_result.returncode == 0:
                console.print(f"  [green]✔[/green] frida actualizado a {frida_ver}")
            else:
                console.print(
                    f"  [yellow]⚠[/yellow]  No se pudo instalar frida=={frida_ver}: "
                    f"{_pip_result.stderr.strip()[:200]}"
                )

        console.print(f"  frida {frida_ver} — arquitectura AVD: {arch}")

        try:
            server_bin = _with_spinner(
                f"Descargando frida-server {frida_ver} ({arch})...",
                lambda cb: download_frida_server(frida_ver, arch, progress_callback=cb),
            )
        except RuntimeError as exc:
            console.print(f"[red]✘[/red] Error descargando frida-server: {exc}")
            console.print(
                "  [yellow]Verifica:[/yellow]"
                "\n    • Conexión a Internet"
                f"\n    • Que la arquitectura {arch} sea compatible"
                "\n    • Permisos de escritura en cache"
            )
            return None
        console.print(f"[green]✔[/green] frida-server listo: {server_bin.name}")

        # ── B. Arrancar emulador ───────────────────────────────────────────
        console.print(f"[dim]  Iniciando AVD: {avd_name}[/dim]")
        serial = _with_spinner(
            f"Iniciando emulador {avd_name}...",
            lambda cb: start_emulator(
                avd_name,
                sdk_tools,
                progress_callback=cb,
                show_window=bool(cfg_get(cfg, "strategies", "show_emulator", default=True)),
            ),
        )
        if not serial:
            console.print("[red]✘[/red] El emulador no arrancó después de esperar 3 minutos.")
            console.print(
                "  [yellow]Verifica:[/yellow]"
                "\n    • El AVD existe: [cyan]emulator -list-avds[/cyan]"
                "\n    • Permisos del SDK en [cyan]~/Library/Android/sdk[/cyan]"
                "\n    • Si el hardware lo soporta: KVM en Linux, Hypervisor en macOS"
                f"\n    • Intenta limpiar: [cyan]rm -rf ~/.android/avd/{avd_name}/cache[/cyan]"
            )
            return None
        console.print(f"[green]✔[/green] Emulador listo: {serial}")

        has_dexdump = bool(sdk_tools.get("frida-dexdump"))
        dex_files: list[Path] = []
        method_used: str | None = None
        attempted_methods: list[str] = []
        frida_ready = False
        app_installed = False
        _frida_host = cfg_get(cfg, "strategies", "frida_host") or None

        def _ensure_frida_server() -> bool:
            nonlocal frida_ready
            if frida_ready:
                return True
            ok = _with_spinner(
                "Configurando frida-server en el emulador...",
                lambda cb: setup_frida_server(
                    serial, sdk_tools, server_bin,
                    progress_callback=cb,
                    listen_all=bool(_frida_host),
                ),
            )
            if not ok:
                last_msgs = getattr(_with_spinner, "_last_msgs", [])
                detail = last_msgs[-1] if last_msgs else "sin detalles"
                console.print(f"[red]✘[/red] frida-server no arrancó: {detail}")
                console.print(
                    "  [yellow]Verifica:[/yellow]"
                    f"\n    • Conectividad adb: [cyan]adb -s {serial} shell id[/cyan]"
                    f"\n    • Permisos en el emulador: [cyan]adb -s {serial} shell getprop ro.secure[/cyan]"
                    f"\n    • Reinicia el emulador: [cyan]adb -s {serial} reboot[/cyan]"
                )
                return False
            console.print("[green]✔[/green] frida-server corriendo")
            frida_ready = True
            return True

        def _ensure_installed(target_apk: Path, pkg: str) -> bool:
            nonlocal app_installed
            if app_installed and target_apk == apk_path:
                return True

            ok = _with_spinner(
                f"Instalando APK {package}...",
                lambda cb: emulator_install_apk(
                    serial,
                    sdk_tools,
                    target_apk,
                    package_name=pkg,
                    progress_callback=cb,
                ),
            )
            if not ok:
                last = getattr(_with_spinner, "_last_msgs", [])
                detail = next(
                    (m for m in reversed(last) if any(
                        kw in m for kw in ("INSTALL_FAILED", "Error", "ERROR", "failed", "ABI")
                    )),
                    last[-1] if last else "sin detalles",
                )
                console.print(f"[red]✘[/red] No se pudo instalar la APK:")
                console.print(f"  Error: {detail}")
                if "INSTALL_FAILED_INVALID_APK" in str(detail):
                    console.print("  → La APK puede estar corrupta o es incompatible")
                elif "ABI" in str(detail):
                    console.print(f"  → Problema de ABI. AVD: {arch}. Verifica que sea compatible.")
                return False
            console.print(f"[green]✔[/green] APK {package} instalada")
            if target_apk == apk_path:
                app_installed = True
            return True

        for method in method_order:
            if dex_files:
                break
            attempted_methods.append(method)

            if method == "gadget":
                console.print("[yellow]⚠[/yellow]  Intentando con Frida Gadget...")
                gadget_dex = try_gadget_inject(
                    apk_path, serial, sdk_tools, package, local_dump_dir,
                    _with_spinner,
                )
                if gadget_dex:
                    dex_files = gadget_dex
                    method_used = "frida-gadget+frida-dexdump"
                else:
                    # Gadget puede haber reinstalado un APK parcheado en el emulador.
                    # Forzar reinstalación del APK original en el siguiente método.
                    app_installed = False
                continue

            if method == "frida_server":
                if not _ensure_frida_server():
                    continue
                if not _ensure_installed(apk_path, package):
                    continue

                if has_dexdump:
                    dex_files, dexdump_err = _with_spinner(
                        f"Volcando DEX de memoria con frida-dexdump ({package})...",
                        lambda cb: launch_with_dexdump(
                            serial, package, local_dump_dir, sdk_tools,
                            progress_callback=cb,
                            frida_host=_frida_host,
                        ),
                    )
                    if dex_files:
                        console.print(
                            f"[green]✔[/green] {len(dex_files)} DEX volcados con frida-dexdump "
                            f"→ {local_dump_dir}"
                        )
                        method_used = "frida-server+frida-dexdump"
                    else:
                        console.print(
                            f"[yellow]⚠[/yellow]  frida-dexdump: {dexdump_err}"
                        )
                continue

            if method == "fart":
                console.print("[dim]  Intentando FART (classloader hook)...[/dim]")
                if not _ensure_frida_server():
                    continue
                if not _ensure_installed(apk_path, package):
                    continue

                frida_proc = None
                import tempfile as _tempfile
                _tmp_scripts = Path(_tempfile.mkdtemp(prefix="apkmon_fart_"))
                try:
                    _fart_script = generate_fart_script(package, _tmp_scripts)
                except Exception as _exc:
                    console.print(f"[red]✘[/red] No se pudo generar script FART: {_exc}")
                    continue
                _frida_host = cfg_get(cfg, "strategies", "frida_host") or None
                frida_proc, frida_err = launch_with_fart(
                    serial, package, _fart_script, sdk_tools,
                    frida_host=_frida_host,
                )
                if not frida_proc:
                    console.print(f"[red]✘[/red] No se pudo lanzar frida: {frida_err}")
                    continue
                console.print(
                    "[green]✔[/green] App lanzada con FART — simulando interacción de usuario..."
                )

                import threading
                _ui_stop = threading.Event()
                _ui_thread = threading.Thread(
                    target=simulate_app_navigation,
                    args=(serial, sdk_tools, _ui_stop),
                    kwargs={"progress_callback": lambda m: None},
                    daemon=True,
                )
                _ui_thread.start()

                found = _with_spinner(
                    f"Esperando volcados DEX de {package} (FART)...",
                    lambda cb: wait_for_dumps(
                        serial, sdk_tools, package,
                        timeout=300,
                        progress_callback=cb,
                    ),
                )
                _ui_stop.set()
                _ui_thread.join(timeout=5)

                if not found:
                    console.print(
                        "[yellow]⚠[/yellow]  FART sin volcados detectados (timeout)."
                    )
                    continue

                dex_files = _with_spinner(
                    "Descargando DEX volcados...",
                    lambda cb: pull_dumps(
                        serial, sdk_tools, package, local_dump_dir, progress_callback=cb
                    ),
                )
                if dex_files:
                    console.print(f"[green]✔[/green] {len(dex_files)} DEX descargados → {local_dump_dir}")
                    method_used = "FART (classloader hook)"
                else:
                    console.print("[yellow]⚠[/yellow]  FART no descargó archivos .dex")
                continue

        if not dex_files:
            tried = " -> ".join(attempted_methods) if attempted_methods else "(sin métodos)"
            console.print("[red]✘[/red] No se logró extraer DEX con el pipeline configurado.")
            console.print(f"[dim]  Métodos intentados: {tried}[/dim]")
            return None

    finally:
        stop_frida(frida_proc)

    return ExtractionResult(
        dex_files=dex_files,
        method_used=method_used or "emulator-pipeline",
        local_dump_dir=local_dump_dir,
        clean_dir=clean_dir,
    )


# ── Pipeline: Gadget Inject ───────────────────────────────────────────────────


def try_gadget_inject(
    apk_path: Path,
    serial: str,
    sdk_tools: dict,
    package: str,
    dump_dir: Path,
    with_spinner,
) -> list[Path] | None:
    """
    Intenta extraer DEX inyectando Frida Gadget en el APK.

    Flujo:
      1. Desempaqueta el APK con apktool.
      2. Descarga libfrida-gadget.so para la arquitectura del AVD.
      3. Copia el gadget en lib/<abi>/ y añade System.loadLibrary al smali.
      4. Reempaqueta + refirma.
      5. Reinstala y conecta con frida para volcar DEX.

    Devuelve lista de DEX volcados o None si algo falla.
    """
    import shutil as _shutil
    import tempfile as _tempfile
    import zipfile as _zipfile

    from nutcracker_core.apk_tools import (
        find_apksigner as _find_apksigner,
        ensure_debug_keystore as _ensure_debug_keystore,
    )
    from nutcracker_core.device import find_sdk_root

    # ── Verificar apktool ────────────────────────────────────────────────────
    if not _shutil.which("apktool"):
        console.print(
            "[yellow]⚠[/yellow]  apktool no encontrado — no se puede inyectar Frida Gadget.\n"
            "  Instala con: brew install apktool"
        )
        return None

    sdk = find_sdk_root()
    apksigner = _find_apksigner(sdk)
    if not apksigner:
        console.print(
            "[yellow]⚠[/yellow]  apksigner no encontrado en Android SDK — omitiendo gadget."
        )
        return None

    keystore = _ensure_debug_keystore()
    if not keystore:
        console.print("[yellow]⚠[/yellow]  keytool no disponible — omitiendo gadget.")
        return None

    work_dir = Path(_tempfile.mkdtemp(prefix="apkmon_gadget_"))

    try:
        # ── 1. Detectar ABI del emulador ────────────────────────────────────
        import subprocess as _sp
        abi_result = _sp.run(
            [sdk_tools["adb"], "-s", serial, "shell", "getprop", "ro.product.cpu.abi"],
            capture_output=True, text=True, timeout=10,
        )
        abi = abi_result.stdout.strip() or "arm64-v8a"
        console.print(f"  ABI del emulador: {abi}")

        _ABI_GADGET = {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "x86_64": "x86_64",
            "x86": "x86",
        }
        frida_arch = _ABI_GADGET.get(abi, "arm64")

        # ── 2. Descargar Frida Gadget .so ───────────────────────────────────
        import frida  # type: ignore[import]
        frida_ver = frida.__version__
        gadget_url = (
            f"https://github.com/frida/frida/releases/download/{frida_ver}/"
            f"frida-gadget-{frida_ver}-android-{frida_arch}.so.xz"
        )
        gadget_xz = work_dir / "frida-gadget.so.xz"
        gadget_so = work_dir / "libfrida-gadget.so"

        console.print(f"  Descargando Frida Gadget {frida_ver} ({frida_arch})...")
        import urllib.request as _req
        try:
            _req.urlretrieve(gadget_url, gadget_xz)  # noqa: S310
        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow]  No se pudo descargar el gadget: {exc}")
            return None

        import lzma as _lzma
        with _lzma.open(gadget_xz, "rb") as xz_f, open(gadget_so, "wb") as out_f:
            out_f.write(xz_f.read())

        # ── 3. Desempaquetar APK con apktool ────────────────────────────────
        decompiled_dir = work_dir / "decompiled"
        console.print("  Desempaquetando APK con apktool...")
        r = _sp.run(
            ["apktool", "d", str(apk_path), "-o", str(decompiled_dir), "-f", "--no-res"],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            console.print(f"[yellow]⚠[/yellow]  apktool falló: {r.stderr[:200]}")
            return None

        # ── 4. Copiar gadget en lib/<abi>/ ───────────────────────────────────
        lib_dir = decompiled_dir / "lib" / abi
        lib_dir.mkdir(parents=True, exist_ok=True)
        _shutil.copy2(gadget_so, lib_dir / "libfrida-gadget.so")

        # ── 5. Parchear el smali del Application / MainActivity ──────────────
        smali_dirs = list(decompiled_dir.glob("smali*"))
        load_line = (
            "\n    const-string v0, \"frida-gadget\"\n"
            "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        )
        patched = False
        for smali_root in smali_dirs:
            for smali_file in smali_root.rglob("*.smali"):
                content = smali_file.read_text(encoding="utf-8", errors="replace")
                if (
                    "Landroid/app/Application;" in content
                    or "extends Application" in content
                ) and ".method public constructor <init>()V" in content:
                    content = content.replace(
                        ".method public constructor <init>()V",
                        ".method public constructor <init>()V" + load_line,
                        1,
                    )
                    smali_file.write_text(content, encoding="utf-8")
                    patched = True
                    console.print(f"  Gadget inyectado en: {smali_file.name}")
                    break
            if patched:
                break

        if not patched:
            console.print(
                "[yellow]⚠[/yellow]  No se encontró clase Application en smali — "
                "gadget no inyectado."
            )
            return None

        # ── 6. Reempaquetar con apktool ──────────────────────────────────────
        patched_unsigned_raw = work_dir / f"{package}_gadget_unsigned_raw.apk"
        patched_unsigned = work_dir / f"{package}_gadget_unsigned.apk"
        console.print("  Reempaquetando APK...")
        r = _sp.run(
            ["apktool", "b", str(decompiled_dir), "-o", str(patched_unsigned_raw)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            console.print(f"[yellow]⚠[/yellow]  apktool build falló: {r.stderr[:200]}")
            return None

        # ── 6b. Reempaquetar .so como STORED (sin compresión) ────────────────
        console.print("  Re-empaquetando libs nativas como STORED...")
        with _zipfile.ZipFile(patched_unsigned_raw, "r") as zin, \
             _zipfile.ZipFile(str(patched_unsigned), "w") as zout:
            for item in zin.infolist():
                raw = zin.read(item.filename)
                if item.filename.endswith(".so"):
                    zout.writestr(item, raw, compress_type=_zipfile.ZIP_STORED)
                else:
                    zout.writestr(item, raw, compress_type=item.compress_type)
        patched_unsigned_raw.unlink(missing_ok=True)

        # ── 6c. zipalign ─────────────────────────────────────────────────────
        zipalign_bin = str(Path(apksigner).parent / "zipalign")
        patched_aligned = work_dir / f"{package}_gadget_aligned.apk"
        if Path(zipalign_bin).exists():
            console.print("  Alineando APK (zipalign 4096)...")
            za = _sp.run(
                [zipalign_bin, "-f", "-p", "4", str(patched_unsigned), str(patched_aligned)],
                capture_output=True, text=True, timeout=60,
            )
            if za.returncode == 0:
                patched_unsigned.unlink(missing_ok=True)
                patched_unsigned = patched_aligned
            else:
                console.print(f"[yellow]⚠[/yellow]  zipalign falló (continuando sin alinear): {za.stderr[:100]}")
                patched_aligned.unlink(missing_ok=True)
        else:
            console.print("[yellow]⚠[/yellow]  zipalign no encontrado en build-tools — libs pueden no estar alineadas")

        # ── 7. Firmar ─────────────────────────────────────────────────────────
        patched_apk = work_dir / f"{package}_gadget.apk"
        console.print("  Firmando APK con gadget...")
        r = _sp.run(
            [
                apksigner, "sign",
                "--ks", str(keystore),
                "--ks-pass", "pass:android",
                "--key-pass", "pass:android",
                "--ks-key-alias", "androiddebugkey",
                "--out", str(patched_apk),
                str(patched_unsigned),
            ],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            console.print(f"[yellow]⚠[/yellow]  Firma falló: {r.stderr[:200]}")
            return None

        # ── 8. Reinstalar e intentar dexdump sobre el gadget ─────────────────
        from nutcracker_core.apk_tools import install_apk as _install_apk, find_split_apks as _find_split_apks
        console.print("  Reinstalando APK con gadget...")

        # Si el APK original es parte de un bundle, copiar los splits
        # al work_dir y reemplazar base.apk por el parcheado para que
        # install_apk los envíe todos juntos con adb install-multiple.
        orig_splits = _find_split_apks(apk_path)
        if len(orig_splits) > 1:
            for s in orig_splits:
                if s.resolve() != apk_path.resolve():
                    _shutil.copy2(s, work_dir / s.name)
            # patched_apk ya está en work_dir; install_apk usará find_split_apks
            # que ahora encontrará todos los splits en el mismo directorio.

        _install_msgs: list[str] = []
        ok = _install_apk(
            serial,
            sdk_tools,
            patched_apk,
            package_name=package,
            progress_callback=_install_msgs.append,
        )
        if not ok:
            detail = _install_msgs[-1] if _install_msgs else "sin detalles"
            console.print(
                f"[yellow]⚠[/yellow]  No se pudo reinstalar el APK con gadget.\n"
                f"  Causa: {detail}\n"
                f"  Posibles soluciones:\n"
                f"    · INSTALL_FAILED_UPDATE_INCOMPATIBLE → "
                f"desinstala la app original del emulador manualmente\n"
                f"    · INSTALL_FAILED_DEXOPT → apktool no soporta el formato "
                f"del APK (DexGuard modifica resources.arsc)\n"
                f"    · INSTALL_FAILED_MISSING_SPLIT → la app es un bundle; "
                f"el gadget solo se inyectó en base.apk"
            )
            return None

        console.print("  Intentando volcar DEX vía gadget...")
        dex_files, err = with_spinner(
            f"Volcando DEX con gadget ({package})...",
            lambda cb: launch_with_dexdump(serial, package, dump_dir, sdk_tools, progress_callback=cb, frida_host=cfg_get(cfg, "strategies", "frida_host") or None if cfg else None),
        )
        if dex_files:
            console.print(f"[green]✔[/green] {len(dex_files)} DEX extraídos con Frida Gadget")
            return dex_files

        console.print(f"[yellow]⚠[/yellow]  Gadget: dexdump aún falló: {err}")
        return None

    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]⚠[/yellow]  Error en inyección de gadget: {exc}")
        return None
    finally:
        _shutil.rmtree(work_dir, ignore_errors=True)


# ── Pipeline: Dispositivo físico ──────────────────────────────────────────────


def do_fart_manual(
    cfg: dict,
    package: str,
    script_path: Path,
    apk_path: Path,
    method_order: list[str] | None = None,
) -> ExtractionResult | None:
    """Flujo runtime en dispositivo físico respetando runtime_methods."""

    console.print(fart_run_instructions(package, script_path))

    adb_ok, adb_msg = check_adb()
    if not adb_ok:
        console.print(f"[yellow]⚠[/yellow]  {adb_msg}")
        console.print(
            f"  Conecta el dispositivo y ejecuta el script Frida manualmente:\n"
            f"  [cyan]frida -U -f {package} -l {script_path}[/cyan]\n"
            f"  Luego: [cyan]adb pull /data/user/0/{package}/files/frida_dump/ ./dumps/[/cyan]"
        )
        return None
    console.print(f"[green]✔[/green] {adb_msg}")

    preferred_device = str(cfg_get(cfg, "strategies", "default_device_id", default="")).strip()
    devices = [d for d in connected_adb_devices() if not is_emulator_serial(d)]
    selected_device = ""
    if preferred_device and preferred_device in devices:
        selected_device = preferred_device
    elif preferred_device and preferred_device not in devices:
        console.print(
            f"[yellow]⚠[/yellow]  default_device_id='{preferred_device}' no está conectado. "
            "Usando el primer dispositivo físico encontrado."
        )
    if not selected_device and devices:
        selected_device = devices[0]

    if not selected_device:
        console.print(
            "[red]✘[/red] No hay dispositivos físicos conectados para runtime_target=device."
        )
        return None

    if selected_device:
        os.environ["ANDROID_SERIAL"] = selected_device
        console.print(f"[dim]  Dispositivo objetivo: {selected_device}[/dim]")

    frida_proc = None
    local_dump_dir = Path("./decompiled") / f"dexguard_dump_{package}"
    clean_dir = local_dump_dir / "source"

    sdk_tools = find_sdk_tools()
    has_dexdump = bool(sdk_tools.get("frida-dexdump"))
    methods = method_order or ["fart"]
    console.print(f"[dim]  Pipeline de extracción (device): {' -> '.join(methods)}[/dim]")

    # ── Instalar APK en el device ─────────────────────────────────────────────
    if selected_device and apk_path and apk_path.exists():
        console.print(f"[dim]  Instalando APK en device {selected_device}...[/dim]")
        apk_installed = _with_spinner(
            f"Instalando {package} en device...",
            lambda cb: emulator_install_apk(
                selected_device, sdk_tools, apk_path, package, progress_callback=cb
            ),
        )
        if apk_installed:
            console.print(f"[green]✔[/green] APK instalada en device")
        else:
            console.print(
                f"[yellow]⚠[/yellow]  No se pudo instalar la APK en el device. "
                "Asegúrate de que el device tiene instalación desde fuentes desconocidas habilitada."
            )

    dex_files: list[Path] = []
    method_used: str | None = None
    attempted_methods: list[str] = []
    try:
        for method in methods:
            if dex_files:
                break
            attempted_methods.append(method)
            console.print(f"[dim]  Intentando método runtime (device): {method}[/dim]")

            if method == "gadget":
                console.print("[yellow]⚠[/yellow]  Método gadget no soportado en modo device. Saltando...")
                continue

            if method == "frida_server":
                if not selected_device:
                    console.print("[yellow]⚠[/yellow]  Sin serial de dispositivo para frida-dexdump.")
                    continue
                if not has_dexdump:
                    console.print("[yellow]⚠[/yellow]  frida-dexdump no instalado. Saltando frida_server.")
                    continue

                # ── Auto-instalar frida-server en el device ────────────────
                # Versión de frida-server: config > auto-detectada del entorno Python
                _cfg_ver = str(cfg_get(cfg, "strategies", "frida_server_version") or "").strip()
                frida_ver = _cfg_ver or get_frida_version()
                if frida_ver:
                    # Sincronizar frida + frida-dexdump Python si la versión difiere
                    _installed_frida = get_frida_version()
                    if _installed_frida and _installed_frida != frida_ver:
                        console.print(
                            f"  [dim]frida instalado: {_installed_frida} → "
                            f"sincronizando con frida-server {frida_ver}...[/dim]"
                        )
                        _pip_result = subprocess.run(
                            [
                                sys.executable, "-m", "pip", "install", "--quiet",
                                f"frida=={frida_ver}",
                            ],
                            capture_output=True, text=True, timeout=120,
                        )
                        if _pip_result.returncode == 0:
                            console.print(f"  [green]✔[/green] frida actualizado a {frida_ver}")
                        else:
                            console.print(
                                f"  [yellow]⚠[/yellow]  No se pudo instalar frida=={frida_ver}: "
                                f"{_pip_result.stderr.strip()[:200]}"
                            )

                    _dev_arch = frida_arch_for_device(selected_device, sdk_tools)
                    console.print(f"  frida-server {frida_ver} — arquitectura device: {_dev_arch}")
                    _frida_host_dev = cfg_get(cfg, "strategies", "frida_host") or None
                    try:
                        _server_bin = _with_spinner(
                            f"Descargando frida-server {frida_ver} ({_dev_arch})...",
                            lambda cb: download_frida_server(frida_ver, _dev_arch, progress_callback=cb),
                        )
                        _fs_ok = _with_spinner(
                            f"Instalando frida-server {frida_ver} en el device...",
                            lambda cb: setup_frida_server(
                                selected_device, sdk_tools, _server_bin,
                                progress_callback=cb,
                                listen_all=bool(_frida_host_dev),
                            ),
                        )
                        if _fs_ok:
                            console.print(f"[green]✔[/green] frida-server {frida_ver} corriendo en el device")
                        else:
                            console.print(
                                "[yellow]⚠[/yellow]  No se pudo arrancar frida-server automáticamente.\n"
                                "  Asegúrate de que el device tiene acceso root (adb root) y\n"
                                f"  sube frida-server manualmente: adb push frida-server /data/local/tmp/\n"
                                f"  O configura strategies.frida_server_version en config.yaml (ej: '17.4.0')"
                            )
                    except RuntimeError as _exc:
                        console.print(f"[yellow]⚠[/yellow]  Error descargando frida-server: {_exc}")
                else:
                    console.print("[yellow]⚠[/yellow]  No se detectó versión de frida — omitiendo auto-instalación de frida-server")

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Extrayendo DEX con frida-dexdump (device)...", total=None)
                    _frida_host_dex = cfg_get(cfg, "strategies", "frida_host") or None
                    dex_files, dexdump_err = launch_with_dexdump(
                        selected_device,
                        package,
                        local_dump_dir,
                        sdk_tools,
                        progress_callback=lambda m: progress.update(task, description=m),
                        frida_host=_frida_host_dex,
                    )

                if dex_files:
                    method_used = "frida-server+frida-dexdump"
                    console.print(f"[green]✔[/green] {len(dex_files)} DEX volcados con frida-dexdump")
                else:
                    console.print(f"[yellow]⚠[/yellow]  frida-dexdump no produjo DEX: {dexdump_err}")
                continue

            if method == "fart":
                if _ask_or_auto(
                    cfg,
                    "\n  ¿Lanzar automáticamente Frida/FART en dispositivo físico?",
                    "auto_launch_fart_device",
                    default=True,
                ):
                    if not selected_device:
                        console.print(
                            "[yellow]⚠[/yellow]  No se detectó serial del dispositivo para auto-lanzar Frida. "
                            "Usando flujo manual."
                        )
                    else:
                        _frida_host = cfg_get(cfg, "strategies", "frida_host") or None
                        frida_proc, frida_err = launch_with_fart(
                            selected_device,
                            package,
                            script_path,
                            sdk_tools,
                            frida_host=_frida_host,
                        )
                        if frida_proc:
                            console.print("[green]✔[/green] Frida/FART lanzado automáticamente en dispositivo físico")
                        else:
                            console.print(f"[yellow]⚠[/yellow]  No se pudo auto-lanzar Frida: {frida_err}")
                            console.print("[dim]  Continúa con el flujo manual mostrado arriba.[/dim]")

                import threading as _threading
                _ui_stop = _threading.Event()
                _ui_thread = _threading.Thread(
                    target=simulate_app_navigation,
                    args=(selected_device, sdk_tools, _ui_stop),
                    kwargs={"progress_callback": lambda m: None},
                    daemon=True,
                )
                _ui_thread.start()

                if not _ask_or_auto(cfg, "\n  ¿Esperar automáticamente los volcados DEX?", "wait_fart_dumps", default=True):
                    _ui_stop.set()
                    _ui_thread.join(timeout=5)
                    continue

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Esperando volcados DEX...", total=None)
                    found = wait_for_dumps(
                        selected_device, sdk_tools, package,
                        timeout=300,
                        progress_callback=lambda m: progress.update(task, description=m),
                    )

                _ui_stop.set()
                _ui_thread.join(timeout=5)

                if not found:
                    console.print("[yellow]⚠[/yellow]  FART timeout en device. Probando siguiente método...")
                    continue

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Descargando DEX volcados...", total=None)
                    dex_files = pull_dumps(
                        selected_device, sdk_tools, package,
                        local_dump_dir,
                        progress_callback=lambda m: progress.update(task, description=m),
                    )

                if dex_files:
                    method_used = "FART (classloader hook)"
                    console.print(f"[green]✔[/green] {len(dex_files)} DEX descargados → {local_dump_dir}")
                else:
                    console.print("[yellow]⚠[/yellow]  FART no descargó DEX en device.")
                continue

        if not dex_files:
            tried = " -> ".join(attempted_methods) if attempted_methods else "(sin métodos)"
            console.print("[red]✘[/red] No se logró extraer DEX con el pipeline configurado en device.")
            console.print(f"[dim]  Métodos intentados: {tried}[/dim]")
            return None

    finally:
        stop_frida(frida_proc)

    return ExtractionResult(
        dex_files=dex_files,
        method_used=method_used or "device-pipeline",
        local_dump_dir=local_dump_dir,
        clean_dir=clean_dir,
    )
