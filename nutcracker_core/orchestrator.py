"""Orquestación compartida del pipeline de análisis de nutcracker.

Extraído de nutcracker.py (Fase 0.2 del plan): fuente única de la verdad del
pipeline (descarga → análisis → bypass/decompilación → scan → OSINT → PDF/JSON),
para que CLI, daemon y dashboard la reusen sin duplicar lógica.

Mantiene el mismo patrón de estado mutuo a nivel de módulo que tenía
nutcracker.py (``_CFG``, ``_MANIFEST_ANALYSIS``, ``_OSINT_RESULT``,
``_LAUNCH_APP``, ``_LAUNCH_SERIAL``): los comandos CLI (nutcracker_core/cli/)
los asignan antes de invocar estas funciones.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from nutcracker_core.analyzer import APKAnalyzer
from nutcracker_core.config import get as cfg_get
from nutcracker_core.decompiler import (
    decompile, get_available_tool, install_instructions, DecompilerError, _find_tool,
)
from nutcracker_core.deobfuscator import (
    apply_decrypt_map,
    check_adb,
    decompile_dumps,
)
from nutcracker_core.device import (
    download_frida_server,
    find_sdk_tools,
    frida_arch_for_device,
    get_frida_version,
    list_avds,
    setup_frida_server,
)
from nutcracker_core.frida_bypass import (
    fart_run_instructions,
    frida_run_instructions,
    generate_bypass_script,
    generate_fart_script,
)
from nutcracker_core import i18n
from nutcracker_core.i18n import t
from nutcracker_core.plugins import fire_post_hooks
from nutcracker_core.manifest_analyzer import analyze_decompiled_dir, Misconfiguration
from nutcracker_core.pdf_reporter import generate_pdf_report
from nutcracker_core.reporter import print_report, save_json_report, save_analysis_json, print_vuln_report, print_masvs_summary
from nutcracker_core.pipeline import (
    ExtractionResult,
    connected_adb_devices,
    deobf_method_order,
    do_fart_emulator,
    do_fart_manual,
    is_emulator_serial,
)
from nutcracker_core.vuln_scanner import scan_directory, auto_scan, scan_with_apkleaks, scan_with_gitleaks, ScanResult
from nutcracker_core.osint import run_osint, OsintResult

console = Console()


# ── Configuración global (se carga una vez en el comando principal) ────────────
_CFG: dict = {}
_MANIFEST_ANALYSIS = None  # ManifestAnalysisResult del último scan
_OSINT_RESULT = None       # OsintResult del último scan
_LAUNCH_APP: bool = False  # --launch: lanzar app con bypass script tras el análisis
_LAUNCH_SERIAL: str | None = None  # --serial para --launch
# --dynamic-checks: corre los checks dinámicos de Fase 2 (ADB puro, sin Frida,
# sin REPL interactivo) tras el análisis estático — ver _run_dynamic_checks_for().
# Introducido junto al fix de --launch (2026-07-24, prueba con dispositivo físico
# real): --launch reemplaza el proceso Python con un REPL de frida interactivo,
# pensado para un humano en terminal — un job automatizado de la cola (Fase 1)
# que lo invocaba se quedaría esperando input que nunca llega. Los jobs
# dinámicos de la cola usan este flag en vez de --launch.
_RUN_DYNAMIC_CHECKS: bool = False
_DYNAMIC_CHECKS_SERIAL: str | None = None


def apply_static_only_override(config: dict) -> None:
    """Fuerza decompilación jadx y evita el flujo runtime/dispositivo para esta
    ejecución, sin tocar config.yaml en disco (usado por `--static-only` en
    `analyze`/`scan`). Pensado para jobs encolados o del scheduler (Fase 1 del
    plan): una revisión masiva/periódica no debe competir por el teléfono físico,
    que es un recurso compartido y escaso."""
    pipelines = config.setdefault("pipelines", {})
    protected = pipelines.setdefault("protected", {})
    protected["decompilation"] = "jadx"
    protected.setdefault("fallback_jadx", True)


def build_job_cmd(
    target: str,
    *,
    is_local_apk: bool,
    config_path: str = "config.yaml",
    static_only: bool = True,
    dynamic_checks: bool = False,
    serial: str | None = None,
    aipwn: bool = False,
    source: str | None = None,
    aipwn_resume: bool = False,
    aipwn_extra_iterations: int = 5,
) -> list[str]:
    """Construye el argv para ejecutar un job de análisis como subproceso aislado.

    Usado por nutcracker_core/queue/engine.py (Fase 1 del plan). Cada job corre en
    su propio proceso Python en vez de llamar a `_run_analysis` en el mismo
    proceso: este módulo mantiene estado mutuo a nivel de módulo (`_CFG`,
    `_MANIFEST_ANALYSIS`, `_OSINT_RESULT`, ...) que no es seguro entre análisis
    concurrentes de APKs distintas. El aislamiento por proceso evita ese riesgo
    sin reescribir el orquestador, y de paso da paralelismo real (sin GIL).

    Los jobs dinámicos usan ``--dynamic-checks`` (checks/dynamic/ de Fase 2, ADB
    puro) en vez de ``--launch``: ``--launch`` reemplaza el proceso con un REPL
    de frida interactivo pensado para un humano en terminal — un job automatizado
    de la cola que lo usara se quedaría esperando input que nunca llega
    (encontrado en prueba con dispositivo físico real, 2026-07-24; ver plan.md).

    ``aipwn=True`` (Fase 3, wiring del dashboard con el agente de bypass) corre
    ``nutcracker aipwn <target>`` en vez de analyze/scan — ``target`` es un
    package id, no una ruta/URL de APK (aipwn requiere que ya exista un
    análisis previo del package, igual que en uso manual por CLI). El comando
    ``aipwn`` no acepta ``--config`` (siempre lee ``config.yaml`` por defecto),
    así que ``config_path``/``static_only``/``dynamic_checks`` se ignoran en
    este modo.

    ``source="device"`` (job de tipo scan, ``target`` es un package id): en vez
    de descargar de Google Play/APKPure, ``scan`` extrae el .apk ya instalado
    en el dispositivo ``serial`` vía ``adb pull`` — ver
    ``downloader.DeviceInstalledDownloader``. Útil para apps de prueba propias
    no publicadas en ninguna store (mismo caso que motivó el fix de
    "re-analizar" — pero resuelto desde el origen para apps nunca antes
    analizadas localmente, no solo las que ya tienen un run previo).

    ``source="device-or-store"``: igual que ``"device"``, pero con fallback
    automático a la store si el pull falla (dispositivo no conectado, app no
    instalada) -- ver ``downloader.download_apk_from_config``. Usado por el
    batchero del dashboard para listas de package IDs donde no se sabe de
    antemano cuáles ya están instalados en el device de pruebas.
    """
    entry = str(Path(__file__).resolve().parent.parent / "nutcracker.py")
    cmd = [sys.executable, entry]
    if aipwn:
        # FIX (reportado en vivo, 2026-07-27): sin --report, run_aipwn() genera
        # el ExploitReport en memoria (PoCs confirmados/no confirmados, con
        # evidencia y screenshots) pero plugins/aipwn/__init__.py solo lo
        # vuelca a disco (exploit_report_<pkg>.json/.pdf) si este flag está
        # presente -- un job de cola/dashboard corría el exploit agent entero
        # y tiraba el resultado: el único rastro que sobrevivía era el .txt de
        # log crudo en logs/, nada reutilizable ni visible desde el dashboard.
        cmd += ["aipwn", target, "--report"]
        if serial:
            cmd += ["--serial", serial]
        if aipwn_resume:
            cmd += ["--resume", "--extra-iterations", str(aipwn_extra_iterations)]
        return cmd
    if is_local_apk:
        cmd += ["analyze", target, "--config", config_path]
        if dynamic_checks:
            cmd.append("--dynamic-checks")
            if serial:
                cmd += ["--serial", serial]
    else:
        cmd += ["scan", target, "--config", config_path, "--keep-apk"]
        if source:
            cmd += ["--source", source]
            if source in ("device", "device-or-store") and serial:
                cmd += ["--serial", serial]
    if static_only:
        cmd.append("--static-only")
    return cmd


def _run_dynamic_checks_for(result, serial: str | None) -> None:
    """Corre los checks dinámicos de Fase 2 (ADB puro, sin Frida) contra
    ``result.package`` en el dispositivo ``serial`` e imprime los hallazgos.

    A diferencia de --launch, nunca cede el proceso a un REPL interactivo:
    apto para automatización headless (jobs de la cola, Fase 1).
    """
    from .checks import dynamic_checks, load_registry
    from .checks.dynamic.context import DynamicCheckContext

    load_registry()
    checks = dynamic_checks()
    if not checks:
        return

    console.print(f"\n[bold cyan]Checks dinámicos[/bold cyan] ({len(checks)}) — serial={serial or '(auto)'}")
    ctx = DynamicCheckContext(package=result.package, serial=serial)
    for check in checks:
        try:
            findings = check.run(ctx)
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]✘[/red] {check.meta.id}: error ejecutando el check — {exc}")
            continue
        for finding in findings:
            icon = "[yellow]⚠[/yellow]" if finding.detected else "[dim]–[/dim]"
            console.print(f"  {icon} {finding.check_id}  {finding.detail}")


def _init_i18n(config: dict) -> None:
    """Initialize the i18n module from the loaded config."""
    language = str(cfg_get(config, "language", default="en")).strip().lower()
    if language not in i18n.SUPPORTED_LANGUAGES:
        console.print(f"[yellow]⚠[/yellow]  {t('unsupported_language', lang=language)}")
    i18n.init(language)


def _format_elapsed(seconds: float) -> str:
    """Formatea una duración en formato legible para consola."""
    total_seconds = max(0, int(round(seconds)))
    minutes, secs = divmod(total_seconds, 60)
    hours, mins = divmod(minutes, 60)

    parts: list[str] = []
    if hours:
        parts.append(f"{hours}h")
    if mins or hours:
        parts.append(f"{mins}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _print_elapsed(label: str, seconds: float) -> None:
    """Imprime el tiempo total consumido por una ejecución."""
    console.print(f"[bold cyan]⏱ {label}:[/bold cyan] {_format_elapsed(seconds)}")


def _find_latest_bypass_script(package: str, scripts_dir: Path = Path("frida_scripts")) -> Path | None:
    """Devuelve el script de bypass más reciente para el paquete, o None."""
    if not scripts_dir.exists():
        return None
    candidates = sorted(
        scripts_dir.glob(f"bypass_{package}_*.js"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _launch_frida_bypass(
    package: str,
    script_path: Path,
    serial: str | None = None,
    frida_host: str | None = None,
) -> None:
    """Reinicia frida-server y lanza la app con el bypass script (reemplaza el proceso)."""
    import shutil as _shutil
    import time as _time

    adb = _shutil.which("adb")
    if not adb:
        console.print(f"[red]Error:[/red] {t('cli_dep_adb_missing')}")
        return

    frida_bin = str(Path(sys.executable).parent / "frida")
    if not Path(frida_bin).exists():
        frida_bin = _shutil.which("frida") or ""
    if not frida_bin:
        console.print(f"[red]Error:[/red] {t('cli_dep_frida_missing')}")
        return

    adb_args = [adb] + (["-s", serial] if serial else [])

    console.print(f"[dim]  {t('cli_restarting_frida')}[/dim]")
    # FIX (prueba con dispositivo físico real, 2026-07-24): antes reiniciaba
    # frida-server con un simple "nohup .../frida-server &" — sin -l 0.0.0.0
    # (nunca escuchaba en red, solo en 127.0.0.1: --launch con frida_host
    # configurado no podía conectar aunque el ruteo de red funcionara), sin
    # respetar strategies.frida_server_version (riesgo de mismatch de versión
    # con la librería Python), y sin el "unset LD_PRELOAD" que setup_frida_server
    # sí hace — necesario en devices con Magisk Zygisk/LSPosed (hma_oss_zygisk,
    # zygisksu, etc., que setean LD_PRELOAD y rompen el attach/spawn de Frida).
    # Reusa el mismo mecanismo robusto que ya usa el flujo FART (pipeline.py).
    if serial:
        try:
            tools = find_sdk_tools()
            tools.setdefault("adb", adb)
            cfg_ver = str(cfg_get(_CFG, "strategies", "frida_server_version") or "").strip()
            frida_ver = cfg_ver or get_frida_version()
            if frida_ver:
                arch = frida_arch_for_device(serial, tools)
                server_bin = download_frida_server(frida_ver, arch)
                setup_frida_server(
                    serial, tools, server_bin,
                    listen_all=bool(frida_host),
                    force_restart=True,
                )
            else:
                console.print(f"[yellow]⚠[/yellow]  {t('pipe_frida_not_found')}")
        except Exception as exc:  # noqa: BLE001
            console.print(
                f"[yellow]⚠[/yellow]  No se pudo reiniciar frida-server automáticamente "
                f"({exc}); intentando con el binario que ya esté en el device."
            )
    else:
        # Sin --serial explícito (un único device/emulador conectado): no hay
        # forma fiable de resolverle arquitectura/tools a setup_frida_server,
        # así que se conserva el restart simple de antes como fallback — sin
        # -l 0.0.0.0 (frida_host sin --serial es un caso raro) pero al menos
        # asegura que frida-server esté corriendo para -U.
        subprocess.run(adb_args + ["shell", "killall frida-server 2>/dev/null; true"], capture_output=True)
        subprocess.run(adb_args + ["root"], capture_output=True)
        _time.sleep(2)
        subprocess.run(
            adb_args + ["shell", "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"],
            capture_output=True,
        )
        _time.sleep(2)
    subprocess.run(adb_args + ["shell", f"am force-stop {package}"], capture_output=True)
    _time.sleep(1)

    if frida_host:
        frida_cmd = [frida_bin, "-H", frida_host, "-f", package, "-l", str(script_path)]
    elif serial:
        frida_cmd = [frida_bin, "-D", serial, "-f", package, "-l", str(script_path)]
    else:
        frida_cmd = [frida_bin, "-U", "-f", package, "-l", str(script_path)]

    console.print(f"[green]▶[/green]  [bold cyan]{' '.join(frida_cmd)}[/bold cyan]")
    # FIX (encontrado en prueba con dispositivo físico real, 2026-07-24): antes
    # usaba os.execvp(), que REEMPLAZA el proceso Python actual por el de frida.
    # Esto hacía que todo el código posterior a _post_analysis_flow() en
    # _run_analysis() (save_analysis_json, PDF, reporte MASVS, post-hooks de
    # persistencia SQLite) nunca se ejecutara — el análisis estático, ya
    # completo en ese punto, se perdía sin dejar rastro en disco ni en la BD,
    # sin importar si frida lograba conectar o no. subprocess.run() preserva
    # el mismo comportamiento interactivo (hereda stdin/stdout/stderr, así que
    # un humano en terminal sigue viendo el REPL de frida en vivo) pero, a
    # diferencia de execvp, retorna cuando frida termina — permitiendo que el
    # resto del pipeline complete su trabajo de guardado.
    subprocess.run(frida_cmd)


def _auto(key: str) -> "bool | None":
    """Lee un flag del bloque `auto:` en config.yaml. None si no está configurado."""
    auto_block = _CFG.get("auto", {})
    if not isinstance(auto_block, dict):
        return None
    val = auto_block.get(key)
    return bool(val) if val is not None else None


def _unattended() -> bool:
    """Modo no interactivo global."""
    return bool(cfg_get(_CFG, "auto", "unattended", default=False))


def _ask_or_auto(prompt: str, key: str, default: bool = False) -> bool:
    """Usa el flag de config si está explícitamente configurado; si no, pregunta."""
    cfg_val = _auto(key)
    if cfg_val is not None:
        tag = "yes" if cfg_val else "no"
        console.print(f"[dim]  {t('pipe_auto_skip', key=key, tag=tag)}[/dim]")
        return cfg_val
    if _unattended():
        tag = "yes" if default else "no"
        console.print(f"[dim]  {t('pipe_unattended_skip', prompt=prompt, tag=tag)}[/dim]")
        return default
    return click.confirm(prompt, default=default)


def _feature_enabled(name: str, default: bool = True) -> bool:
    """Lee flags de features:<name> con fallback al default."""
    v = cfg_get(_CFG, "features", name, default=default)
    return bool(v)


def _pipeline_decompilation_mode(protected: bool) -> str:
    """Modo de decompilación desde pipelines.<protected|unprotected>."""
    if protected:
        mode = str(cfg_get(_CFG, "pipelines", "protected", "decompilation", default="")).strip().lower()
        return mode if mode in ("runtime", "jadx") else "runtime"
    # unprotected: booleano decompilation_jadx
    jadx_enabled = cfg_get(_CFG, "pipelines", "unprotected", "decompilation_jadx", default=True)
    return "jadx" if jadx_enabled else "none"


def _validate_all_dependencies(protected: bool = True) -> bool:
    """
    Valida temprano todas las dependencias según config (jadx, frida, adb, apktool, etc).

    Retorna True si todo está ok. Si falta algo, imprime error y retorna False.
    """
    import shutil as _shutil

    errors = []
    warnings = []

    # ── Decompilación ─────────────────────────────────────────────────────────
    decompilation_enabled = _feature_enabled("decompilation", default=True)
    if decompilation_enabled:
        decompilation_mode = _pipeline_decompilation_mode(protected)
        if decompilation_mode == "jadx":
            # FIX (mismo bug reportado en vivo que _do_decompile, 2026-08-05):
            # shutil.which("jadx") a secas ignora el toolbox de Docker por
            # completo -- con toolbox.enabled=true en config.yaml, jadx "está
            # disponible" vía el contenedor aunque no exista el binario local
            # (ver decompiler._find_tool/toolbox.STATIC_TOOLS).
            if not _find_tool("jadx", _CFG):
                errors.append(t("cli_dep_jadx_missing"))

    # ── Desofuscación runtime ─────────────────────────────────────────────────
    runtime_target = str(
        cfg_get(_CFG, "strategies", "runtime_target", default="auto")
    ).strip().lower()

    decompilation_mode = _pipeline_decompilation_mode(protected)
    should_validate_runtime = decompilation_mode == "runtime"

    if should_validate_runtime:
        scope = "protected" if protected else "unprotected"
        runtime_methods = cfg_get(_CFG, "pipelines", scope, "runtime_methods",
                                  default=["frida_server", "gadget", "fart"]) or []

        # Emulador
        if runtime_target in ("auto", "emulator"):
            sdk_tools = find_sdk_tools()
            has_emulator = bool(sdk_tools.get("emulator")) and bool(list_avds(sdk_tools))

            if runtime_target == "emulator" and not has_emulator:
                errors.append(t("cli_dep_no_avd"))

            if not get_frida_version():
                errors.append(t("cli_dep_frida_missing"))

        # Dispositivo físico
        if runtime_target in ("auto", "device"):
            if not _shutil.which("adb"):
                errors.append(t("cli_dep_adb_missing"))

            if not get_frida_version():
                errors.append(t("cli_dep_frida_missing"))

        # Herramientas opcionales para runtime
        if "frida_server" in runtime_methods or "gadget" in runtime_methods:
            if not _shutil.which("frida-dexdump"):
                warnings.append(t("cli_dep_dexdump_warn"))

        # Si gadget está habilitado, necesita apktool + apksigner
        if "gadget" in runtime_methods:
            if not _shutil.which("apktool"):
                errors.append(t("cli_dep_apktool_missing"))
            # apksigner está en Android SDK build-tools
            sdk_tools = find_sdk_tools()
            apksigner = sdk_tools.get("apksigner")
            if not apksigner:
                warnings.append(t("cli_dep_apksigner_warn"))

    # ── Escaneo de vulnerabilidades ───────────────────────────────────────────
    scanner_engine = cfg_get(_CFG, "sast", "engine", default="auto") or "auto"
    if str(scanner_engine).lower() == "semgrep":
        if not _shutil.which("semgrep"):
            warnings.append(t("cli_dep_semgrep_warn"))

    # ── Mostrar errores y advertencias ────────────────────────────────────────
    if errors:
        console.print(f"\n[red][bold]{t('cli_dep_errors_header')}[/bold][/red]")
        for err in errors:
            console.print(f"  [red]✘[/red] {err}")
        console.print(f"\n  [dim]{t('cli_requirements_url')}[/dim]\n")
        return False

    if warnings:
        console.print(f"[yellow][bold]{t('cli_dep_warnings_header')}[/bold][/yellow]")
        for warn in warnings:
            console.print(f"  [yellow]⚠[/yellow]  {warn}")
        console.print()

    return True


# ── Lógica compartida ─────────────────────────────────────────────────────────

def _run_analysis(apk_path: Path, report_path: str | None, keep_apk: bool, gen_pdf: bool = True) -> None:
    started_at = time.perf_counter()
    result = None
    elapsed_seconds = 0.0
    try:
        anti_root_engine = str(
            cfg_get(_CFG, "strategies", "anti_root_engine", default="native")
        ).strip().lower()
        if anti_root_engine == "builtin":
            anti_root_engine = "native"
        if anti_root_engine not in ("native", "apkid"):
            anti_root_engine = "native"
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            task = progress.add_task(t("cli_analyzing_apk"), total=None)

            def on_progress(msg: str) -> None:
                progress.update(task, description=msg)

            analyzer = APKAnalyzer(progress_callback=on_progress, engine=anti_root_engine, config=_CFG)
            result = analyzer.analyze(apk_path)
            # Si anti_root_analysis=false en config, ignorar la detección de protección
            if not bool(cfg_get(_CFG, "strategies", "anti_root_analysis", default=True)):
                result.protected = False
                console.print("[dim]  strategies.anti_root_analysis=false → omitiendo flujo Frida/emulador[/dim]")

    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{t('cli_error_unexpected')}[/red] {exc}")
        sys.exit(1)

    if result:
        print_report(result)
        # Flujo post-análisis: bypass, vuln scan, etc. (puede poblar decompilation_info)
        vuln_scan = _post_analysis_flow(result, apk_path)

        elapsed_seconds = time.perf_counter() - started_at
        result.elapsed_seconds = elapsed_seconds

        # Guardar JSON una vez que todos los datos están completos
        save_analysis_json(result, scan_result=vuln_scan, manifest=_MANIFEST_ANALYSIS)

        # ── Resumen MASVS v2 ─────────────────────────────────────────────
        try:
            from nutcracker_core.masvs import build_masvs_report
            _masvs = build_masvs_report(result, vuln_scan, _MANIFEST_ANALYSIS)
            print_masvs_summary(_masvs)
        except Exception:
            pass

        # ── Veredicto final en terminal ───────────────────────────────────
        _print_verdict(result, vuln_scan)

        # Generar PDF solo si está habilitado en config (save_pdf)
        if gen_pdf:
            _generate_pdf(result, vuln_scan,
                          vuln_scan_enabled=_feature_enabled("sast_scan", default=True))

        # FIX (reportado en vivo por el usuario, 2026-07-27): el dashboard
        # asumía que "re-analizar" siempre podía volver a *descargar* la app
        # por su package id (scan), pero una app analizada desde un .apk local
        # (analyze <path>, o un job local vía la cola) puede no estar
        # publicada en ninguna store -- el intento de re-descarga fallaba con
        # "APK no encontrada en 'downloads' tras la descarga" para apps que
        # nunca vinieron de ahí en primer lugar. store/hooks.py no puede
        # recibir apk_path directo (la firma de after_analysis es compartida
        # con otros post-hooks sin **kwargs, ver comentario abajo) -- se pasa
        # por env var, mismo patrón que NUTCRACKER_QUEUE_JOB_ID. Solo se fija
        # si el archivo va a seguir existiendo tras esta función (keep_apk) --
        # si se va a borrar, no hay nada reutilizable que ofrecer.
        if keep_apk and apk_path and apk_path.exists():
            os.environ["NUTCRACKER_APK_SOURCE"] = str(apk_path.resolve())
        else:
            os.environ.pop("NUTCRACKER_APK_SOURCE", None)

        # ── Post-hooks de plugins ──────────────────────────────────────────
        # Firma estable (package, result, vuln_scan, config): otros plugins (p.ej. aireview)
        # ya registran hooks con esta firma exacta y no aceptan **kwargs adicionales.
        fire_post_hooks(
            "after_analysis",
            package=result.package,
            result=result,
            vuln_scan=vuln_scan,
            config=_CFG,
        )

        # ── Checks dinámicos (--dynamic-checks) ─────────────────────────────
        # Corre después de guardar todo lo estático a propósito: si algo falla
        # acá (dispositivo desconectado, ADB sin permisos, etc.) el análisis
        # estático ya quedó persistido — nunca se pierde por un paso opcional
        # posterior (ver fix de --launch/execvp más arriba en este archivo).
        if _RUN_DYNAMIC_CHECKS:
            try:
                _run_dynamic_checks_for(result, _DYNAMIC_CHECKS_SERIAL)
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]{t('cli_error_unexpected')}[/red] {exc}")

    if not keep_apk and apk_path and apk_path.exists():
        apk_path.unlink()
        console.print(f"[dim]{t('cli_apk_deleted', path=apk_path)}[/dim]")

    _print_elapsed(t("cli_elapsed"), elapsed_seconds)


def _print_bypass_banner(dex_count: int) -> None:
    """Panel naranja de alerta: protección eludida tras volcar los DEX."""
    from rich.panel import Panel
    from rich.text import Text
    from rich.align import Align

    banner_text = Text(justify="center")
    banner_text.append("\n  ✔  " + t("cli_protection_broken_banner") + "  \n\n", style="bold yellow")
    banner_text.append(
        t("cli_protection_broken_frida", dex_count=dex_count),
        style="dim white",
    )
    banner_text.append("\n")
    console.print()
    console.print(Panel(Align.center(banner_text), border_style="yellow", padding=(0, 4)))
    console.print()


def _print_verdict(result, vuln_scan) -> None:
    """Imprime un banner de veredicto final en la terminal."""
    from rich.panel import Panel
    from rich.text import Text
    from rich.align import Align

    has_vulns = vuln_scan is not None and bool(vuln_scan.findings)
    protected = result.protected

    # Bypass real: extracción runtime de DEX vía Frida/FART/Gadget.
    decomp = getattr(result, "decompilation_info", None)
    method = ""
    dex_count = 0
    if isinstance(decomp, dict):
        method = str(decomp.get("method", ""))
        try:
            dex_count = int(decomp.get("dex_count", 0) or 0)
        except (TypeError, ValueError):
            dex_count = 0

    runtime_bypass = any(k in method.lower() for k in ("frida", "fart", "gadget"))
    was_bypassed = protected and runtime_bypass and dex_count > 0
    # ROADMAP "Differentiate runtime bypass vs DEX extraction": aipwn puede
    # confirmar un bypass (report_success) sin haber volcado DEX — verdicto
    # dinámico independiente de was_bypassed (que exige dex_count > 0).
    aipwn_bypass_only = protected and bool(getattr(result, "aipwn_bypass_confirmed", False)) and not was_bypassed

    if not protected:
        color  = "red"
        icon   = "✘"
        title  = t("cli_no_protection_banner")
        detail = t("cli_no_protection_detail")
    elif was_bypassed:
        color  = "yellow"
        icon   = "⚡"
        title  = t("cli_protection_broken_banner")
        detail = t("cli_bypassed_detail", method=method, dex_count=dex_count)
    elif aipwn_bypass_only:
        color  = "yellow"
        icon   = "⚡"
        title  = t("cli_bypass_confirmed_banner")
        detail = t("cli_bypass_confirmed_detail")
    else:
        color  = "green"
        icon   = "✔"
        title  = t("cli_protected_banner")
        if has_vulns:
            n = len(vuln_scan.findings)
            detail = t("cli_protected_vulns_detail", count=n)
        else:
            detail = t("cli_protected_detail")

    verdict_text = Text(justify="center")
    verdict_text.append(f"\n  {icon}  {title}  {icon}\n\n", style=f"bold {color}")
    verdict_text.append(f"  {detail}  ", style="dim white")
    verdict_text.append("\n")

    console.print()
    console.print(Panel(Align.center(verdict_text), border_style=color, padding=(0, 4)))
    console.print()


def _post_analysis_flow(result, apk_path: Path):
    """Flujo interactivo tras el análisis. Retorna el ScanResult si se escanearon vulns."""
    console.print()

    # ── Detectar si hay ofuscación DexGuard ───────────────────────────────────
    dexguard_result = next(
        (r for r in result.results if r.name == "DexGuardDetector" and r.detected),
        None,
    )

    _label = "[green]ℹ[/green]" if result.protected else "[yellow]ℹ[/yellow]"
    _estado = t("cli_app_has_protection") if result.protected else t("cli_app_no_protection")
    console.print(f"{_label}  {t('cli_app_protection_line', status=_estado, protection=t('cli_anti_root_label'))}")

    # ── Selección automática del mejor método ─────────────────────────────────
    decomp_mode = _pipeline_decompilation_mode(result.protected)
    runtime_target = str(
        cfg_get(_CFG, "strategies", "runtime_target", default="auto")
    ).strip().lower()
    # DexGuard detectado → frida-dexdump (bytecode post-descifrado en memoria)
    # Sin DexGuard       → JADX por defecto, salvo pipeline runtime explícito
    # Si decompilation=jadx en config, nunca usar runtime aunque haya DexGuard
    should_try_runtime = decomp_mode == "runtime"

    if should_try_runtime:
        if dexguard_result:
            if runtime_target == "device":
                console.print(
                    f"[yellow]⚠[/yellow]  {t('cli_dexguard_device_warn')}"
                )
            else:
                console.print(
                    f"[yellow]⚠[/yellow]  {t('cli_dexguard_emulator_warn')}"
                )
        else:
            console.print(
                f"[cyan]ℹ[/cyan]  {t('cli_runtime_pipeline_info')}"
            )
        # Con protección anti-root: ofrecer combinar bypass en el mismo script
        if result.protected:
            if _LAUNCH_APP or _ask_or_auto(t("cli_include_bypass_prompt"), "bypass_script", default=True):
                scripts_dir = Path("./frida_scripts")
                try:
                    bp_path = generate_bypass_script(result, scripts_dir)
                    console.print(
                        f"[green]✔[/green] {t('cli_bypass_script_generated')} [bold]{bp_path}[/bold]"
                    )
                    if _LAUNCH_APP:
                        _fh = str(cfg_get(_CFG, "strategies", "frida_host", default="")).strip() or None
                        _launch_frida_bypass(result.package, bp_path, _LAUNCH_SERIAL, frida_host=_fh)
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[red]{t('cli_error_bypass')}[/red] {exc}")

        runtime_prompt = (
            t("cli_fart_prompt_device")
            if runtime_target == "device"
            else t("cli_fart_prompt_emulator")
        )
        if _ask_or_auto(runtime_prompt, "fart", default=True):
            return _do_dexguard_deobf(result, apk_path)

    # Sin DexGuard (o usuario rechazó frida) → jadx directo
    # Si hay protección anti-root sin DexGuard, ofrecer script de bypass por separado
    if result.protected and not dexguard_result:
        if _LAUNCH_APP or _ask_or_auto(t("cli_gen_bypass_prompt"), "bypass_script", default=False):
            scripts_dir = Path("./frida_scripts")
            try:
                script_path = generate_bypass_script(result, scripts_dir)
                console.print(f"[green]✔[/green] {t('cli_frida_script_generated')} [bold]{script_path}[/bold]")
                if _LAUNCH_APP:
                    _fh = str(cfg_get(_CFG, "strategies", "frida_host", default="")).strip() or None
                    _launch_frida_bypass(result.package, script_path, _LAUNCH_SERIAL, frida_host=_fh)
                else:
                    console.print(frida_run_instructions(result.package, script_path))
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]{t('cli_error_bypass')}[/red] {exc}")

    if not _should_fallback_jadx(result.protected):
        return None

    if not _ask_or_auto(t("cli_decompile_jadx_prompt"), "decompile", default=True):
        return None
    return _do_decompile(apk_path, result.package)


def _should_fallback_jadx(protected: bool) -> bool:
    """Determina si se debe intentar decompilación jadx como fallback."""
    if not _feature_enabled("decompilation", default=True):
        console.print(f"[dim]{t('cli_skipping_decompilation')}[/dim]")
        return False
    if protected:
        fallback = cfg_get(_CFG, "pipelines", "protected", "fallback_jadx", default=True)
        if not fallback:
            console.print(
                f"[dim]{t('cli_fallback_jadx_disabled')}[/dim]"
            )
            return False
    return True


def _do_dexguard_deobf(result, apk_path: Path) -> "ScanResult | None":
    """
    Flujo completo de desofuscación para apps DexGuard/Arxan.

    Estrategia primaria: frida-dexdump (sin script en disco).
    Fallback: FART - el script se genera en temp solo si es necesario.

    Ofrece dos modos:
      A) Emulador automático - arranca AVD, instala APK, extrae DEX, descarga DEX
      B) Dispositivo físico  - genera el script FART y el usuario lo ejecuta manualmente
    """
    # ── Validar todas las dependencias (jadx, frida, adb, apktool, etc) ──────
    if not _validate_all_dependencies(protected=result.protected):
        console.print(
            f"[yellow]⚠[/yellow]  {t('cli_skip_runtime_fallback_jadx')}"
        )
        if not _should_fallback_jadx(result.protected):
            return None
        if not _ask_or_auto(t("cli_decompile_jadx_prompt"), "decompile", default=True):
            return None
        return _do_decompile(apk_path, result.package)

    # ── Elegir modo ──────────────────────────────────────────────────────────
    sdk_tools = find_sdk_tools()
    avds = list_avds(sdk_tools)
    has_emulator = bool(sdk_tools.get("emulator")) and bool(avds)
    use_emulator = False

    runtime_target = str(
        cfg_get(_CFG, "strategies", "runtime_target", default="auto")
    ).strip().lower()
    if runtime_target not in {"auto", "emulator", "device"}:
        runtime_target = "auto"

    if runtime_target == "emulator":
        if has_emulator:
            use_emulator = True
            console.print("[dim]  strategies.runtime_target=emulator[/dim]")
        else:
            console.print(
                f"[yellow]⚠[/yellow]  {t('cli_no_avd_using_device')}"
            )
            use_emulator = False
    elif runtime_target == "device":
        use_emulator = False
        console.print("[dim]  strategies.runtime_target=device[/dim]")
        connected = connected_adb_devices()
        physical = [d for d in connected if not is_emulator_serial(d)]
        if not physical:
            console.print(
                f"[yellow]⚠[/yellow]  {t('cli_no_physical_device')}"
            )
    elif has_emulator:
        # runtime_target=auto conserva comportamiento histórico
        if _unattended():
            use_emulator = True
            console.print(t("cli_fart_mode_unattended"))
        else:
            console.print(t("cli_fart_mode_choice", avd_count=len(avds)))
            choice = click.prompt(
                t("cli_fart_choose_prompt"),
                default="A",
                type=click.Choice(["A", "a", "B", "b"], case_sensitive=False),
                show_choices=False,
            ).upper()
            use_emulator = choice == "A"
    else:
        console.print(
            f"[yellow]⚠[/yellow]  {t('cli_no_emulator_using_device')}"
        )

    method_order = deobf_method_order(_CFG, protected=True)

    if use_emulator:
        ext = do_fart_emulator(_CFG, result.package, apk_path, sdk_tools, avds)
    else:
        # Modo manual: el usuario necesita el script en disco para ejecutarlo
        scripts_dir = Path("./frida_scripts")
        try:
            script_path = generate_fart_script(result.package, scripts_dir)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]{t('cli_fart_script_error')}[/red] {exc}")
            return None
        ext = do_fart_manual(_CFG, result.package, script_path, apk_path, method_order)

    if ext is None:
        console.print(
            f"[yellow]⚠[/yellow]  {t('cli_runtime_extraction_failed')}"
        )
        if not _should_fallback_jadx(result.protected):
            return None
        if not _ask_or_auto(t("cli_decompile_jadx_prompt"), "decompile", default=True):
            return None
        return _do_decompile(apk_path, result.package)
    result.decompilation_info = {
        "method": ext.method_used,
        "dex_count": len(ext.dex_files),
        "source_dir": str(ext.clean_dir),
    }
    return _decompile_and_scan(
        ext.dex_files,
        ext.clean_dir,
        ext.local_dump_dir,
        result.package,
        dex_count=len(ext.dex_files),
        apk_path=apk_path,
    )


def _select_token_serial(config: dict) -> str:
    """Elige serial para setup-token respetando runtime_target y default_device_id."""
    preferred = str(cfg_get(config, "strategies", "default_device_id", default="")).strip()
    devices = connected_adb_devices()

    if preferred and preferred in devices:
        return preferred

    runtime_target = str(cfg_get(config, "strategies", "runtime_target", default="auto")).strip().lower()
    if runtime_target == "emulator":
        emus = [d for d in devices if is_emulator_serial(d)]
        if emus:
            return emus[0]
    elif runtime_target == "device":
        physical = [d for d in devices if not is_emulator_serial(d)]
        if physical:
            return physical[0]

    if preferred:
        return preferred
    return ""

def _decompile_and_scan(
    dex_files: list,
    clean_dir: Path,
    local_dump_dir: Path,
    package: str,
    dex_count: int = 0,
    apk_path: Path | None = None,
) -> "ScanResult | None":
    """Paso final compartido: jadx + decrypt_map + scan de vulns."""
    from nutcracker_core.deobfuscator import decompile_dumps, apply_decrypt_map

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(t("cli_decompiling_dex_jadx"), total=None)
            decompile_dumps(
                dex_files,
                clean_dir,
                progress_callback=lambda m: progress.update(task, description=m),
                config=_CFG,
            )
    except RuntimeError as exc:
        console.print(f"[red]{t('cli_error_decompiling_dex')}[/red] {exc}")
        return None

    java_count = len(list(clean_dir.rglob("*.java")))
    console.print(
        f"[green]✔[/green] {t('cli_clean_source', path=clean_dir, count=java_count)}"
    )

    if dex_count > 0:
        _print_bypass_banner(dex_count)

    decrypt_map = local_dump_dir / "decrypt_map.txt"
    if decrypt_map.exists():
        replaced = apply_decrypt_map(clean_dir, decrypt_map)
        if replaced > 0:
            console.print(
                f"[green]✔[/green] {t('cli_strings_replaced', count=replaced)}"
            )
    else:
        console.print(
            f"[dim]  {t('cli_decrypt_map_not_found')}[/dim]"
        )

    # Análisis de misconfigs del manifest
    manifest_analysis = None
    if _feature_enabled("manifest_scan", default=True):
        manifest_analysis = _do_manifest_scan(clean_dir, apk_path=apk_path)
    else:
        console.print(f"[dim]{t('cli_skipping_manifest_scan')}[/dim]")

    # Escaneo de vulnerabilidades y leaks (antes de OSINT para alimentarlo)
    scan_result = None
    vuln_enabled = _feature_enabled("sast_scan", default=True)
    leak_enabled = _feature_enabled("leak_scan", default=True)
    if not vuln_enabled and not leak_enabled:
        console.print(f"[dim]{t('cli_skipping_vuln_scan')}[/dim]")
    elif _ask_or_auto(
        t("cli_vuln_scan_deobf_prompt"),
        "sast_scan",
        default=True,
    ):
        scan_result = _do_vuln_scan(
            clean_dir,
            apk_path=apk_path,
            package_hint=package,
            include_vuln_scan=vuln_enabled,
            include_leak_scan=leak_enabled,
        )

    # OSINT sobre el código decompilado (alimentado por los hallazgos del scanner)
    leak_findings = scan_result.findings if scan_result else None
    _do_osint_scan(clean_dir, package, scan_findings=leak_findings)

    return scan_result


def _do_manifest_scan(decompiled_dir: Path, apk_path: Path | None = None) -> "ManifestAnalysisResult | None":
    """Analiza AndroidManifest.xml y archivos de config buscando misconfigs."""
    global _MANIFEST_ANALYSIS
    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(t("cli_analyzing_manifest"), total=None)
        analysis = analyze_decompiled_dir(
            decompiled_dir,
            progress_callback=lambda m: progress.update(task, description=m),
            apk_path=apk_path,
            config=_CFG,
        )

    _print_manifest_report(analysis)
    _MANIFEST_ANALYSIS = analysis
    return analysis


def _do_osint_scan(source_dir: Path, package: str, scan_findings: list | None = None) -> "OsintResult | None":
    """Ejecuta el pipeline OSINT si está habilitado en config."""
    global _OSINT_RESULT
    if not _feature_enabled("osint_scan", default=True):
        console.print(f"[dim]{t('cli_skipping_osint')}[/dim]")
        return None

    crt_sh = bool(cfg_get(_CFG, "osint", "crt_sh", default=True))
    github_search = bool(cfg_get(_CFG, "osint", "github_search", default=True))
    github_token = cfg_get(_CFG, "osint", "github_token", default="") or None
    grep_app_search = bool(cfg_get(_CFG, "osint", "grep_app_search", default=True))
    fofa_search = bool(cfg_get(_CFG, "osint", "fofa_search", default=False))
    fofa_key = cfg_get(_CFG, "osint", "fofa_key", default="") or None
    shodan_search = bool(cfg_get(_CFG, "osint", "shodan_search", default=False))
    shodan_key = cfg_get(_CFG, "osint", "shodan_key", default="") or None
    postman_search = bool(cfg_get(_CFG, "osint", "postman_search", default=True))
    execute_dorks_flag = bool(cfg_get(_CFG, "osint", "execute_dorks", default=False))
    dork_engines_cfg = cfg_get(_CFG, "osint", "dork_engines", default=["duckduckgo"])
    dork_engines = list(dork_engines_cfg) if isinstance(dork_engines_cfg, (list, tuple)) else ["duckduckgo"]
    dork_max_per_engine = int(cfg_get(_CFG, "osint", "dork_max_per_engine", default=5))
    dork_max_results_per_dork = int(cfg_get(_CFG, "osint", "dork_max_results_per_dork", default=5))
    wayback_search = bool(cfg_get(_CFG, "osint", "wayback_search", default=True))
    wayback_limit_per_domain = int(cfg_get(_CFG, "osint", "wayback_limit_per_domain", default=200))
    wayback_filter_interesting = bool(cfg_get(_CFG, "osint", "wayback_filter_interesting", default=True))

    console.print()
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("OSINT: extrayendo secretos...", total=None)
            app_label = getattr(_MANIFEST_ANALYSIS, "app_label", "") if _MANIFEST_ANALYSIS else ""
            osint_result = run_osint(
                source_dir,
                package,
                scan_findings=scan_findings,
                crt_sh=crt_sh,
                github_search=github_search,
                github_token=github_token,
                grep_app_search=grep_app_search,
                fofa_search=fofa_search,
                fofa_key=fofa_key,
                shodan_search=shodan_search,
                shodan_key=shodan_key,
                postman_search=postman_search,
                execute_dorks_flag=execute_dorks_flag,
                dork_engines=dork_engines,
                dork_max_per_engine=dork_max_per_engine,
                dork_max_results_per_dork=dork_max_results_per_dork,
                wayback_search=wayback_search,
                wayback_limit_per_domain=wayback_limit_per_domain,
                wayback_filter_interesting=wayback_filter_interesting,
                app_label=app_label,
                progress_callback=lambda m: progress.update(task, description=m),
            )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]⚠[/yellow] {t('cli_error_osint')} {exc}")
        return None

    _OSINT_RESULT = osint_result
    _print_osint_report(osint_result)

    # Guardar JSON de OSINT
    _save_osint_json(osint_result, package)

    return osint_result


def _print_osint_report(osint: OsintResult) -> None:
    """Imprime un resumen del análisis OSINT en la consola."""
    from rich.table import Table

    # ── Secretos ──────────────────────────────────────────────────────────
    if osint.secrets:
        console.print(f"\n[bold]{t('cli_osint_secrets_header', count=len(osint.secrets))}[/bold]")
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        table.add_column(t("cli_osint_field_col"), style="bold cyan")
        table.add_column(t("cli_osint_value_col"), style="dim", max_width=50, no_wrap=True)
        table.add_column(t("cli_osint_service_col"), style="yellow")
        table.add_column(t("cli_osint_file_col"), style="dim")
        for s in osint.secrets[:20]:
            val = s.value if len(s.value) <= 50 else s.value[:47] + "..."
            table.add_row(s.name, val, s.service or "-", s.file)
        console.print(table)
        if len(osint.secrets) > 20:
            console.print(f"  [dim]{t('cli_osint_more', count=len(osint.secrets) - 20)}[/dim]")

    # ── Dominios ──────────────────────────────────────────────────────────
    if osint.domains_scanned:
        console.print(f"\n[bold]{t('cli_osint_domains_header')}[/bold]  {', '.join(osint.domains_scanned)}")

    # ── Subdominios ───────────────────────────────────────────────────────
    if osint.subdomains:
        console.print(f"\n[bold]{t('cli_osint_subdomains_header', count=len(osint.subdomains))}[/bold]")
        # Clasificar
        dev_subs = [s for s in osint.subdomains if any(
            e in s.name for e in ("dev", "qa", "uat", "test", "staging", "pre.")
        )]
        if dev_subs:
            console.print(f"  [yellow]⚠ {t('cli_osint_dev_exposed', count=len(dev_subs))}[/yellow]")
            for s in dev_subs[:10]:
                console.print(f"    [yellow]▸[/yellow] {s.name}")
        # Mostrar los primeros
        for s in osint.subdomains[:15]:
            if s not in dev_subs:
                console.print(f"    {s.name}")
        if len(osint.subdomains) > 15:
            console.print(f"  [dim]{t('cli_osint_more', count=len(osint.subdomains) - 15)}[/dim]")

    # ── Leaks públicos ────────────────────────────────────────────────────
    if osint.public_leaks:
        console.print(f"\n[bold]{t('cli_osint_public_leaks_header', count=len(osint.public_leaks))}[/bold]")
        for leak in osint.public_leaks[:10]:
            console.print(f"  [{leak.source}] {leak.title}")
            if leak.url:
                console.print(f"    [dim]{leak.url}[/dim]")

    # ── Auth flows hardcodeados ───────────────────────────────────────────
    if osint.auth_flows:
        console.print(f"\n[yellow][bold]{t('cli_osint_auth_header', count=len(osint.auth_flows))}[/bold][/yellow]")
        for af in osint.auth_flows[:5]:
            console.print(f"  [yellow]⚠[/yellow] {af['type']} en {af['file']}:{af['line']}")


def _save_osint_json(osint: OsintResult, package: str) -> None:
    """Guarda el resultado OSINT en JSON dentro de reports/<package>/osint.json."""
    import json
    pkg_dir = Path("./reports") / package
    pkg_dir.mkdir(parents=True, exist_ok=True)
    out = pkg_dir / "osint.json"
    with out.open("w", encoding="utf-8") as fh:
        json.dump(osint.to_dict(), fh, ensure_ascii=False, indent=2)
    console.print(f"[dim]{t('cli_osint_saved')}[/dim] [bold]{out}[/bold]")


def _print_manifest_report(analysis) -> None:
    """Imprime un resumen de misconfigs del manifest en la consola."""
    from rich.table import Table

    misconfigs = analysis.misconfigurations
    if not misconfigs:
        console.print(f"[green]✔[/green] {t('cli_no_manifest_misconfigs')}")
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    severity_color = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "info": "dim",
    }

    misconfigs_sorted = sorted(misconfigs, key=lambda m: severity_order.get(m.severity, 9))

    counts = {}
    for m in misconfigs_sorted:
        counts[m.severity] = counts.get(m.severity, 0) + 1

    summary_parts = [
        f"[{severity_color.get(sev, '')}]{cnt} {sev.upper()}[/{severity_color.get(sev, '')}]"
        for sev, cnt in sorted(counts.items(), key=lambda kv: severity_order.get(kv[0], 9))
    ]
    console.print(
        f"\n[bold]{t('cli_manifest_misconfigs_header')}[/bold]  " + "  ".join(summary_parts)
    )

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column(t("cli_manifest_sev_col"), style="bold", width=9, no_wrap=True)
    table.add_column(t("cli_manifest_finding_col"))
    table.add_column(t("cli_manifest_evidence_col"), style="dim")
    table.add_column(t("cli_manifest_location_col"), style="dim")

    for m in misconfigs_sorted:
        color = severity_color.get(m.severity, "")
        sev_text = f"[{color}]{m.severity.upper()}[/{color}]"
        # Mostrar descripción truncada como evidencia
        evidence = m.description[:80] if m.description else "-"
        table.add_row(sev_text, m.title, evidence, m.location)

    console.print(table)

    # Mostrar recomendaciones de los críticos y altos
    shown = [m for m in misconfigs_sorted if m.severity in ("critical", "high")]
    if shown:
        console.print(f"\n[bold]{t('cli_manifest_recs_header')}[/bold]")
        for m in shown:
            color = severity_color.get(m.severity, "")
            console.print(f"  [{color}]▸[/{color}] [bold]{m.title}[/bold]")
            console.print(f"    {m.recommendation}\n")


def _do_decompile(apk_path: Path, package: str) -> Path | None:
    """Ejecuta la decompilación con feedback en consola. Devuelve el directorio o None."""
    # FIX (reportado en vivo, 2026-08-05): faltaba pasar config=_CFG acá --
    # get_available_tool() sin config nunca ve el toolbox de Docker como
    # disponible (toolbox.is_enabled(None) siempre da False), así que con
    # toolbox.enabled=true en config.yaml este chequeo igual cortaba con
    # "no hay decompilador" antes de llegar a la línea de abajo, que sí
    # pasaba config=_CFG correctamente a decompile().
    tool, _ = get_available_tool(config=_CFG)
    if tool is None:
        console.print(f"[red]✘[/red] {install_instructions()}")
        return None

    output_dir = Path("./decompiled")
    console.print(f"  {t('cli_decompiling_with', tool=tool, output_dir=output_dir, package=package)}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(t("cli_decompiling_pkg", package=package), total=None)
            # dest_name=package (no apk_path.stem): apkeep guarda el APK base de
            # un App Bundle literalmente como "base.apk" para cualquier paquete,
            # así que sin esto jobs estáticos concurrentes de apps distintas
            # decompilarían todas hacia el mismo "decompiled/base/" y se pisarían
            # entre sí (visto en vivo, 2026-07-28 -- ver decompiler.decompile()).
            dest = decompile(apk_path, output_dir, dest_name=package, config=_CFG)

        console.print(f"[green]✔[/green] {t('cli_source_code_at')} [bold]{dest}[/bold]")

        java_files = list(dest.rglob("*.java"))
        smali_files = list(dest.rglob("*.smali"))
        if java_files:
            console.print(f"   {t('cli_java_files', count=len(java_files))}")
        elif smali_files:
            console.print(f"   {t('cli_smali_files', count=len(smali_files))}")

        # Análisis de misconfigs del manifest
        if _feature_enabled("manifest_scan", default=True):
            _do_manifest_scan(dest, apk_path=apk_path)
        else:
            console.print(f"[dim]{t('cli_skipping_manifest_scan')}[/dim]")

        # Escaneo de vulnerabilidades y leaks (antes de OSINT para alimentarlo)
        scan_result = None
        vuln_enabled = _feature_enabled("sast_scan", default=True)
        leak_enabled = _feature_enabled("leak_scan", default=True)
        if not vuln_enabled and not leak_enabled:
            console.print(f"[dim]{t('cli_skipping_vuln_scan')}[/dim]")
        elif _ask_or_auto(t("cli_vuln_scan_code_prompt"), "sast_scan", default=True):
            scan_result = _do_vuln_scan(
                dest,
                apk_path=apk_path,
                package_hint=package,
                include_vuln_scan=vuln_enabled,
                include_leak_scan=leak_enabled,
            )

        # OSINT sobre el código decompilado (alimentado por hallazgos del scanner)
        leak_findings = scan_result.findings if scan_result else None
        _do_osint_scan(dest, package, scan_findings=leak_findings)

        return scan_result

    except DecompilerError as exc:
        console.print(f"[red]{t('cli_error_decompilation')}[/red] {exc}")
        return None


def _do_vuln_scan(
    source_dir: Path,
    apk_path: "Path | None" = None,
    package_hint: str | None = None,
    include_vuln_scan: bool = True,
    include_leak_scan: bool = True,
):
    """Escanea el directorio decompilado en busca de vulnerabilidades."""
    console.print()
    scan_result = None

    # Determinar motor de escaneo desde config
    engine = cfg_get(_CFG, "sast", "engine") or "auto"

    # ── Leer sección leak_scan ───────────────────────────────────────────
    use_native = bool(cfg_get(_CFG, "leak_scan", "native", default=True))
    use_apkleaks = bool(cfg_get(_CFG, "leak_scan", "apkleaks", default=True))
    use_gitleaks = bool(cfg_get(_CFG, "leak_scan", "gitleaks", default=False))

    # Derivar leak_engine para auto_scan (none|apk|code|both)
    if not include_leak_scan:
        leak_engine = "none"
    elif use_native and use_apkleaks:
        leak_engine = "both"
    elif use_apkleaks:
        leak_engine = "apk"
    elif use_native:
        leak_engine = "code"
    else:
        leak_engine = "none"

    default_semgrep_config = "p/android p/owasp-top-ten"
    semgrep_config = default_semgrep_config
    if str(engine).strip().lower() == "semgrep":
        semgrep_config = (
            cfg_get(_CFG, "sast", "config")
            or default_semgrep_config
        )
    semgrep_config = " ".join(
        token for token in str(semgrep_config).split() if token != "p/secrets"
    ) or default_semgrep_config

    # Permite ejecución separada: vuln scan y leak scan pueden activarse de forma independiente.
    apk_for_leaks = apk_path if include_leak_scan and use_apkleaks else None

    def _is_leak_finding(f) -> bool:
        rid = str(getattr(f, "rule_id", "")).upper()
        title = str(getattr(f, "title", "")).lower()
        category = str(getattr(f, "category", "")).lower()
        if rid.startswith("AL-") or rid.startswith("HC") or rid.startswith("GL-"):
            return True
        leak_terms = ("secret", "token", "apikey", "api key", "password", "credential", "jwt", "private key")
        text = f"{title} {category}"
        return any(t in text for t in leak_terms)

    # Anunciar en terminal qué motor se usará
    import shutil as _shutil
    if engine == "semgrep":
        engine_label = "[bold cyan]semgrep[/bold cyan]"
    elif engine == "regex":
        engine_label = "[bold]regex interno[/bold]"
    else:
        engine_label = (
            "[bold cyan]semgrep[/bold cyan]"
            if _shutil.which("semgrep")
            else "[bold]regex interno[/bold] [dim](semgrep no instalado)[/dim]"
        )
    console.print(
        "  " + t("cli_vuln_scan_header") +
        ("[green]" + t("cli_vuln_scan_enabled") + "[/green]" if include_vuln_scan else "[yellow]" + t("cli_vuln_scan_disabled") + "[/yellow]")
    )
    console.print(
        "  " + t("cli_vuln_engine_header") +
        (engine_label if include_vuln_scan else "[dim]" + t("cli_vuln_scan_disabled") + "[/dim]")
    )
    console.print(
        "  " + t("cli_leak_scan_header") +
        ("[green]" + t("cli_vuln_scan_enabled") + "[/green]" if include_leak_scan else "[yellow]" + t("cli_vuln_scan_disabled") + "[/yellow]")
    )
    # Detalle de motores de leak realmente activos
    leak_parts = []
    if include_leak_scan and use_native:
        leak_parts.append("native")
    if include_leak_scan and use_apkleaks:
        leak_parts.append("apkleaks")
    if include_leak_scan and use_gitleaks:
        leak_parts.append("gitleaks")
    leak_engine_label = ", ".join(leak_parts) if leak_parts else ("[dim]" + t("cli_leak_engines_disabled") + "[/dim]")
    console.print(f"  {t('cli_leak_engines_header')} {leak_engine_label}")

    if not include_vuln_scan:
        if include_leak_scan:
            try:
                leaks: list = []

                # 1) Regex nativo (reglas HC*) sobre código decompilado
                if use_native:
                    base_scan = auto_scan(
                        source_dir,
                        engine="regex",
                        progress_callback=None,
                        apk_path=None,
                        leak_engine="code",
                        include_code_leak_rules=True,
                        include_xml_leak_rules=False,
                        config=_CFG,
                    )
                    leaks.extend([f for f in base_scan.findings if _is_leak_finding(f)])

                # 2) apkleaks sobre el APK original
                if use_apkleaks and apk_for_leaks is not None:
                    try:
                        leaks.extend(scan_with_apkleaks(apk_for_leaks, config=_CFG))
                    except Exception as exc:  # noqa: BLE001
                        console.print(f"[yellow]⚠[/yellow] {t('cli_apkleaks_failed')} {exc}")

                # 3) gitleaks sobre código decompilado
                if use_gitleaks:
                    try:
                        leaks.extend(scan_with_gitleaks(source_dir, config=_CFG))
                    except Exception as exc:  # noqa: BLE001
                        console.print(f"[yellow]⚠[/yellow] gitleaks falló: {exc}")

                # Deduplicación: prefer HC (more context) over GL on same file+line
                hc_keys = {
                    (str(f.file), int(f.line))
                    for f in leaks if f.rule_id.startswith("HC")
                }
                seen: set[tuple[str, int, str, str]] = set()
                uniq = []
                for f in leaks:
                    # Drop GL findings that overlap with HC on same file+line
                    if f.rule_id.startswith("GL-") and (str(f.file), int(f.line)) in hc_keys:
                        continue
                    key = (str(f.file), int(f.line), str(f.rule_id), str(f.matched_text))
                    if key in seen:
                        continue
                    seen.add(key)
                    uniq.append(f)
                leaks = uniq

                leak_tag = "+".join(leak_parts) if leak_parts else ""
                scan_result = ScanResult(
                    base_dir=source_dir,
                    findings=leaks,
                    files_scanned=0,
                    scanner_engine="",
                    leak_engine=leak_tag,
                )
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]Error en leak scan:[/red] {exc}")
                return None
        else:
            scan_result = ScanResult(
                base_dir=source_dir,
                findings=[],
                files_scanned=0,
                scanner_engine="none",
            )

        _inject_manifest_component_findings(scan_result)
        print_vuln_report(scan_result, source_dir)
        pkg_name = package_hint or source_dir.name
        _save_vuln_json(scan_result, pkg_name, manifest=_MANIFEST_ANALYSIS)
        return scan_result

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(t("cli_scanning_vulns"), total=None)

            def on_progress(msg: str) -> None:
                progress.update(task, description=msg)

            scan_result = auto_scan(
                source_dir,
                engine=engine,
                semgrep_config=semgrep_config,
                progress_callback=on_progress,
                apk_path=apk_for_leaks,
                leak_engine=leak_engine,
                include_code_leak_rules=include_leak_scan and use_native,
                include_xml_leak_rules=include_leak_scan and use_native,
                config=_CFG,
            )

    except RuntimeError as exc:
        console.print(f"[yellow]⚠[/yellow]  {exc}")
        console.print(f"[dim]  {t('cli_retry_regex')}[/dim]")
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(t("cli_scanning_vulns_regex"), total=None)
                # Usar auto_scan con engine=regex para respetar la lógica sources/ + XML
                from nutcracker_core.vuln_scanner import auto_scan as _auto_scan
                scan_result = _auto_scan(
                    source_dir,
                    engine="regex",
                    progress_callback=lambda m: progress.update(task, description=m),
                    apk_path=apk_for_leaks,
                    leak_engine=leak_engine,
                    include_code_leak_rules=include_leak_scan and use_native,
                    include_xml_leak_rules=include_leak_scan and use_native,
                    config=_CFG,
                )
        except Exception as exc2:  # noqa: BLE001
            console.print(f"[red]{t('cli_error_vuln_scan')}[/red] {exc2}")
            return None
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{t('cli_error_vuln_scan')}[/red] {exc}")
        return None

    if scan_result:
        # Inyectar hallazgos de gitleaks si está habilitado
        if use_gitleaks and include_leak_scan:
            try:
                gl_findings = scan_with_gitleaks(source_dir, config=_CFG)
                if gl_findings:
                    # Dedup: skip gitleaks findings that overlap with existing
                    # HC findings on the same file+line (HC has more context)
                    existing_keys = {
                        (str(f.file), f.line)
                        for f in scan_result.findings
                        if f.rule_id.startswith("HC")
                    }
                    new_gl = [
                        f for f in gl_findings
                        if (str(f.file), f.line) not in existing_keys
                    ]
                    if new_gl:
                        scan_result.findings.extend(new_gl)
                    console.print(
                        f"  [dim]{t('cli_gitleaks_stats', detected=len(gl_findings), discarded=len(gl_findings) - len(new_gl), added=len(new_gl))}[/dim]"
                    )
                    if "gitleaks" not in scan_result.leak_engine:
                        scan_result.leak_engine += ("+gitleaks" if scan_result.leak_engine else "gitleaks")
            except Exception as exc:  # noqa: BLE001
                console.print(f"[yellow]⚠[/yellow] {t('cli_gitleaks_failed')} {exc}")

        engine_used = scan_result.scanner_engine
        console.print(
            f"  [dim]{t('cli_scanner_used_dim', engine=engine_used, files=scan_result.files_scanned, findings=len(scan_result.findings))}[/dim]"
        )

    _inject_manifest_component_findings(scan_result)
    print_vuln_report(scan_result, source_dir)

    # Guardar JSON con nombre canónico por paquete.
    pkg_name = package_hint or source_dir.name
    _save_vuln_json(scan_result, pkg_name, manifest=_MANIFEST_ANALYSIS)
    return scan_result


def _inject_manifest_component_findings(scan_result) -> None:
    """Agrega hallazgos COMP004/006/007/008 (componentes exportados sin
    permission) a partir de ``_MANIFEST_ANALYSIS.exported_components``.

    FIX (2026-07-28): vivía inline al final de ``_do_vuln_scan``, después del
    bloque que solo corre cuando ``include_vuln_scan`` está habilitado -- con
    ``sast_scan: false`` en config.yaml (el camino "solo leak scan" retorna
    antes de llegar ahí), estos hallazgos nunca se generaban pese a no tener
    nada que ver con SAST/semgrep: salen enteramente del manifest, no del
    código. Extraído a función propia para poder llamarlo desde ambos
    caminos de ``_do_vuln_scan`` (con y sin vuln_scan habilitado)."""
    if scan_result is None or not _MANIFEST_ANALYSIS:
        return
    if not getattr(_MANIFEST_ANALYSIS, "exported_components", None):
        return
    try:
        from nutcracker_core.vuln_scanner import VulnFinding
        _COMP_MAP = {
            "activity":  ("COMP006", "Activity exported sin permission",              "critical", "M6 - Componentes inseguros"),
            "service":   ("COMP007", "Service exported sin permission",               "high",     "M6 - Componentes inseguros"),
            "receiver":  ("COMP004", "BroadcastReceiver exported sin permission",     "high",     "M6 - Componentes inseguros"),
            "provider":  ("COMP008", "ContentProvider exported sin permission",       "critical", "M6 - Componentes inseguros"),
        }
        existing_comp = {(f.rule_id, f.matched_text) for f in scan_result.findings if f.rule_id.startswith("COMP")}
        new_comp = []
        for ec in _MANIFEST_ANALYSIS.exported_components:
            tag = ec.get("tag", "").lower()
            name = ec.get("name", "")
            if tag not in _COMP_MAP:
                continue
            rule_id, title, severity, category = _COMP_MAP[tag]
            matched = f'<{tag} android:name="{name}" android:exported="true">'
            if (rule_id, matched) in existing_comp:
                continue
            new_comp.append(VulnFinding(
                rule_id=rule_id,
                title=f"{title}: {name.split('.')[-1]}",
                severity=severity,
                category=category,
                file=None,
                line=0,
                matched_text=matched,
                description=(
                    f"{tag.capitalize()} `{name}` tiene android:exported=\"true\" sin "
                    f"android:permission. Cualquier app o comando ADB puede invocarlo directamente."
                ),
                recommendation=(
                    f"Añadir android:exported=\"false\" o proteger con "
                    f"android:permission=\"<custom-signature-permission>\"."
                ),
            ))
            existing_comp.add((rule_id, matched))
        if new_comp:
            scan_result.findings.extend(new_comp)
            console.print(f"  [dim]Componentes exportados (manifest): {len(new_comp)} hallazgo(s) COMP[/dim]")
    except Exception:
        pass


def _load_vuln_json(package: str):
    """Carga el JSON de vulnerabilidades guardado previamente, si existe."""
    import json
    from nutcracker_core.vuln_scanner import ScanResult, VulnFinding

    # Primario: reports/<package>/vuln.json
    # Fallback: decompiled/vuln_<package>.json (legacy)
    json_path = Path("./reports") / package / "vuln.json"
    if not json_path.exists():
        json_path = Path("./decompiled") / f"vuln_{package}.json"
    if not json_path.exists():
        return None
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        base_dir = Path("./decompiled") / package
        import re as _re
        _url_re = _re.compile(r'"(https?://[^"]{8,})"')
        _ai_reviewed = bool(data.get("ai_reviewed"))

        def _effective_sev(f: dict) -> str:
            """URL → INFO solo si el LLM no confirmó el finding como crítico/alto/medio.

            - Sin ai-review: aplicar heurística (URL → info).
            - Con ai-review y LLM lo dejó como TRUE_POSITIVE (sin _ai_note): respetar severidad original.
            - Con ai-review y LLM lo degradó (tiene _ai_note): ya tiene la severidad corregida, solo aplicar URL como fallback extra.
            """
            sev = f.get("severity", "info")
            if sev in ("info",):
                return sev
            # Si el LLM ya revisó este finding y lo mantuvo sin cambios (TRUE_POSITIVE),
            # confiamos en su criterio y no aplicamos la degradación automática.
            if _ai_reviewed and not f.get("_ai_note"):
                return sev
            # Sin revisión LLM o LLM lo DOWNGRADE: aplicar heurística URL → info
            if _url_re.search(f.get("matched_text", "")):
                return "info"
            return sev

        findings = [
            VulnFinding(
                rule_id=f["rule_id"],
                title=f["title"],
                severity=_effective_sev(f),
                category=f["category"],
                file=base_dir / f["file"],
                line=f["line"],
                matched_text=f["matched_text"],
                description=f["description"],
                recommendation=f["recommendation"],
            )
            for f in data.get("findings", [])
            if not f.get("_fp")  # FPs etiquetados por ai-review no van al PDF
        ]
        return ScanResult(base_dir=base_dir, findings=findings,
                          files_scanned=data.get("files_scanned", 0))
    except Exception:  # noqa: BLE001
        return None


# ── Persistencia del análisis (AnalysisResult) ────────────────────────────────


def _load_analysis_json(package: str):
    """Carga el AnalysisResult más reciente desde reports/<package>/."""
    import json
    from nutcracker_core.analyzer import AnalysisResult
    pkg_dir = Path("./reports") / package
    # Soportar también el formato plano anterior (reports/<package>.json)
    legacy = Path("./reports") / f"{package}.json"
    if pkg_dir.is_dir():
        jsons = sorted(
            (f for f in pkg_dir.glob("*.json") if f.stem[0].isdigit()),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        if jsons:
            try:
                data = json.loads(jsons[0].read_text(encoding="utf-8"))
                return AnalysisResult.from_dict(data)
            except Exception:  # noqa: BLE001
                pass
    if legacy.exists():
        try:
            data = json.loads(legacy.read_text(encoding="utf-8"))
            return AnalysisResult.from_dict(data)
        except Exception:  # noqa: BLE001
            pass
    return None


def _generate_pdf(result, vuln_scan=None, vuln_scan_enabled: bool = True) -> Path | None:
    """Genera el informe PDF final con los resultados de anti-root y vulnerabilidades."""
    # Si no se pasó un scan en esta sesión, intentar cargar el JSON guardado
    if vuln_scan is None:
        vuln_scan = _load_vuln_json(result.package)
        if vuln_scan is not None:
            console.print(
                f"[dim]  {t('cli_loading_prev_findings', count=len(vuln_scan.findings))}[/dim]"
            )

    reports_dir = Path("./reports") / result.package
    reports_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = reports_dir / f"nutcracker_{result.package}_report.pdf"
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            progress.add_task(t("cli_generating_pdf"), total=None)
            generate_pdf_report(result, pdf_path, scan=vuln_scan, manifest=_MANIFEST_ANALYSIS,
                                osint=_OSINT_RESULT, vuln_scan_enabled=vuln_scan_enabled)
        console.print(f"[green]✔[/green] {t('cli_pdf_saved')} [bold]{pdf_path}[/bold]")
        return pdf_path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{t('cli_error_pdf')}[/red] {exc}")
        return None


def _save_vuln_json(scan_result, package: str, manifest=None) -> None:
    """Guarda los hallazgos de vulnerabilidades en JSON.

    Escribe en dos ubicaciones:
      - reports/<package>/vuln.json  (primario, junto al AnalysisResult)
      - decompiled/vuln_<package>.json  (legacy, usado por aireview)
    """
    import json
    data = {
        "files_scanned": scan_result.files_scanned,
        "total_findings": len(scan_result.findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "file": f.relative_path(scan_result.base_dir),
                "line": f.line,
                "matched_text": f.matched_text,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in scan_result.findings
        ],
    }
    if manifest is not None and manifest.misconfigurations:
        data["manifest_misconfigs"] = [
            {
                "severity": m.severity,
                "category": m.category,
                "title": m.title,
                "description": m.description,
                "location": m.location,
                "recommendation": m.recommendation,
            }
            for m in manifest.misconfigurations
        ]
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    primary = Path("./reports") / package / "vuln.json"
    primary.parent.mkdir(parents=True, exist_ok=True)
    primary.write_text(payload, encoding="utf-8")
    # Legacy copy para aireview y otros usos directos de decompiled/
    legacy = Path("./decompiled") / f"vuln_{package}.json"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text(payload, encoding="utf-8")
    console.print(f"[dim]{t('cli_vuln_json_saved')}[/dim] [bold]{primary}[/bold]")
