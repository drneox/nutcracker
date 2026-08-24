"""
aipwn.py — Orquestador del comando `nutcracker aipwn`.

Coordi na el agente Frida con el contexto disponible de la app:
  - AnalysisResult (si se pasó desde scan/analyze)
  - decompiled_dir (si existe código decompilado)
  - config (llm + aipwn blocks)

Uso desde CLI:
    nutcracker aipwn com.example.app [--serial SERIAL] [--max-runs N] [--capture-sec N]
"""

from __future__ import annotations

import datetime
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING


from rich.console import Console
from rich.markup import escape as _escape
from rich.panel import Panel
from rich.rule import Rule
from nutcracker_core.i18n import t

from .frida_agent import FridaAgent, AgentResult
from .frida_capture import (
    FridaRunResult,
    any_device_online,
    check_app_installed,
    check_device_healthy,
    find_emulator_binary,
    launch_frida_capture,
    list_avds,
    reboot_device_and_wait,
    start_emulator_and_wait,
)

if TYPE_CHECKING:
    from nutcracker_core.analyzer import AnalysisResult
    from nutcracker_core.vuln_scanner import ScanResult

console = Console()


class _TeeWriter:
    """Escribe simultáneamente al terminal (con ANSI) y a un archivo de log (sin ANSI)."""

    _ANSI_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log = log_file

    def write(self, data: str) -> int:
        self._terminal.write(data)
        self._log.write(self._ANSI_RE.sub('', data))
        return len(data)

    def flush(self) -> None:
        self._terminal.flush()
        self._log.flush()

    def __getattr__(self, name):
        return getattr(self._terminal, name)


def run_aipwn(
    package: str,
    config: dict,
    serial: str | None = None,
    analysis_result: "AnalysisResult | None" = None,
    decompiled_dir: Path | None = None,
    max_frida_runs: int | None = None,
    capture_seconds: int | None = None,
    force: bool = False,
    exploit_mode: bool = False,
    scan_result: "ScanResult | None" = None,
    resume: bool = False,
    extra_iterations: int = 5,
    interactive: bool = False,
) -> AgentResult:
    """
    Punto de entrada principal del comando aipwn.

    Args:
        package:         Package ID de la app (ej: com.example.app)
        config:          Config global de nutcracker (dict desde config.yaml)
        serial:          Serial ADB del dispositivo (None = USB por defecto)
        analysis_result: AnalysisResult previo (opcional, mejora el contexto del agente)
        decompiled_dir:  Directorio con código fuente decompilado (opcional)
        max_frida_runs:  Override del config aipwn.max_frida_runs
        capture_seconds: Override del config aipwn.capture_seconds
        force:           Si True, omite la validación del script previo y va directo al agente
        exploit_mode:    Si True, lanza ExploitAgent tras bypass exitoso para confirmar vulns
        scan_result:     ScanResult de vuln_scanner para el modo exploit (requiere exploit_mode=True)
        resume:          Si True, continúa la última sesión sin conclusión de este paquete (ver
                         agent_memory.load_resume_state) en vez de arrancar una conversación nueva
                         -- botón "+N iteraciones" del dashboard. Si no hay sesión pendiente, sigue
                         igual que una corrida normal (sin resumir).
        extra_iterations: Cuántas iteraciones LLM más darle a la sesión reanudada, más allá de
                         donde se cortó. Sin efecto si ``resume=False`` o no hay sesión pendiente.
        interactive:     Si True y la corrida termina SIN éxito (fallo o corte por límite),
                         al finalizar se abre una sesión de chat interactiva en la terminal con
                         la conversación real del agente transferida al co-piloto (handoff vivo,
                         ver query_agent.run_interactive_cli). Sin efecto si el bypass funcionó.
    """
    aipwn_cfg = config.get("aipwn", config.get("autopwn", {}))
    llm_cfg = config.get("llm", {})

    # ── Logging a archivo ────────────────────────────────────────────────────
    from . import frida_agent as _fa_mod
    from . import frida_agent_tools as _fat_mod
    from . import frida_capture as _fc_mod

    _logs_dir = Path("logs")
    _logs_dir.mkdir(exist_ok=True)
    Path("aipwn_memory").mkdir(exist_ok=True)
    _log_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    _safe_pkg = Path(package).name if "/" in package or "\\" in package else package
    _log_path = _logs_dir / f"{_safe_pkg}_{_log_ts}_aipwn.txt"
    _log_path.parent.mkdir(parents=True, exist_ok=True)
    _log_file = _log_path.open("w", encoding="utf-8", errors="replace")

    _all_consoles = [console, _fa_mod.console, _fc_mod.console, _fat_mod.console]
    _orig_files = [c._file for c in _all_consoles]
    for c in _all_consoles:
        # Usar c.file (propiedad que resuelve None → stdout/stderr)
        # pero guardar c._file original (puede ser None) para restaurar
        c._file = _TeeWriter(c.file, _log_file)

    try:
        return _run_aipwn_inner(
            package=package,
            config=config,
            aipwn_cfg=aipwn_cfg,
            llm_cfg=llm_cfg,
            serial=serial,
            analysis_result=analysis_result,
            decompiled_dir=decompiled_dir,
            max_frida_runs=max_frida_runs,
            capture_seconds=capture_seconds,
            force=force,
            exploit_mode=exploit_mode,
            scan_result=scan_result,
            resume=resume,
            extra_iterations=extra_iterations,
            interactive=interactive,
        )
    finally:
        console.print(f"[dim][aipwn] {t('aipwn_log_saved', path=_log_path)}[/dim]")
        for c, orig in zip(_all_consoles, _orig_files):
            c._file = orig
        _log_file.close()


def _run_aipwn_inner(
    package: str,
    config: dict,
    aipwn_cfg: dict,
    llm_cfg: dict,
    serial: str | None = None,
    analysis_result: "AnalysisResult | None" = None,
    decompiled_dir: Path | None = None,
    max_frida_runs: int | None = None,
    capture_seconds: int | None = None,
    force: bool = False,
    exploit_mode: bool = False,
    scan_result: "ScanResult | None" = None,
    resume: bool = False,
    extra_iterations: int = 5,
    interactive: bool = False,
) -> AgentResult:
    """Lógica interna de aipwn (separada para facilitar el wrapper de logging)."""
    from .agent_memory import load_resume_state

    _resume_state = load_resume_state(package) if resume else None
    if resume and _resume_state is None:
        console.print(
            f"[yellow][aipwn] No hay sesión pendiente para reanudar de '{package}' -- "
            f"corriendo normal.[/yellow]"
        )

    # Parámetros con fallback a config
    _max_runs = max_frida_runs if max_frida_runs is not None else int(
        aipwn_cfg.get("max_frida_runs", 5)
    )
    _max_llm_iterations = int(aipwn_cfg.get("max_llm_iterations", 30))
    _capture_sec = capture_seconds if capture_seconds is not None else int(
        aipwn_cfg.get("capture_seconds", 30)
    )
    _scripts_dir = Path(str(aipwn_cfg.get("scripts_dir", "frida_scripts")))
    # Relay "browser-as-bridge" (plan.md): NUTCRACKER_FRIDA_HOST, si está
    # seteada (por engine.py::_run_job cuando el job trae job.frida_host),
    # tiene prioridad sobre strategies.frida_host del config -- apunta frida
    # al túnel local (127.0.0.1:PF) armado para esta corrida en particular,
    # en vez del host fijo del config (pensado para uso directo sin relay).
    _frida_host: str | None = (
        os.environ.get("NUTCRACKER_FRIDA_HOST", "").strip()
        or str(config.get("strategies", {}).get("frida_host", "")).strip()
        or None
    )

    # Validar LLM configurado
    provider = str(llm_cfg.get("provider", "")).strip()
    if not provider:
        console.print(
            f"[red][aipwn] {t('aipwn_error_no_llm')}[/red]\n"
            f"  {t('aipwn_error_llm_config_hint')}"
        )
        return AgentResult(
            success=False,
            script_path=None,
            explanation="",
            failure_reason="LLM no configurado",
            frida_runs=0,
            iterations=0,
            last_frida_result=None,
        )

    # Intentar detectar decompiled_dir automáticamente si no se pasó
    runtime_dump_dir: Path | None = None
    if decompiled_dir is None:
        decompiled_dir, runtime_dump_dir = _find_decompiled_dir(package)
    else:
        # Si se pasó explícitamente, buscar runtime_dump como complemento
        _, runtime_dump_dir = _find_decompiled_dir(package)

    # Cabecera
    console.print(Rule(f"[bold green]{t('aipwn_header')}[/bold green]"))
    console.print(f"  {t('package')}:    [bold]{package}[/bold]")
    console.print(f"  LLM:        {llm_cfg.get('model', '?')} {t('aipwn_via')} {provider}")
    console.print(f"  {t('aipwn_max_runs')}:   {_max_runs} {t('aipwn_frida_runs')}")
    console.print(f"  {t('aipwn_capture')}:    {_capture_sec}{t('aipwn_seconds')} {t('aipwn_per_run')}")
    if decompiled_dir and decompiled_dir.exists():
        java_count = len(list(decompiled_dir.rglob("*.java")))
        dex_count  = len(list(decompiled_dir.rglob("*.dex")))
        if java_count:
            src_info = f"{java_count} {t('aipwn_classes')}"
        else:
            src_info = f"{dex_count} .dex (sin jadx)"
        console.print(f"  {t('aipwn_source')}:     {decompiled_dir} ({src_info})")
    else:
        console.print(f"  [yellow]{t('aipwn_source')}:     {t('aipwn_no_decompilation')}[/yellow]")
    if runtime_dump_dir and runtime_dump_dir.exists():
        rt_count = len(list(runtime_dump_dir.rglob("*.java")))
        console.print(f"  [dim]runtime dump:  {runtime_dump_dir} ({rt_count} clases desencriptadas)[/dim]")
    if serial:
        console.print(f"  {t('aipwn_serial')}:     {serial}")
    console.print()

    # ── Paso 0a: asegurar dispositivo; auto-start del emulador si aplica ─────
    # Si no hay NINGÚN dispositivo online y la config apunta a emulador
    # (strategies.runtime_target: emulator), levantar el AVD solos en vez de
    # morir después contra un "no device". AVD: strategies.default_emulator_avd,
    # o el primero de la lista si hay uno solo/no está configurado.
    _adb = shutil.which("adb")
    if _adb and not any_device_online(_adb):
        _strategies = config.get("strategies", {})
        if str(_strategies.get("runtime_target", "")).strip() == "emulator":
            _emu_bin = find_emulator_binary()
            _avds = list_avds(_emu_bin) if _emu_bin else []
            _avd = str(_strategies.get("default_emulator_avd", "")).strip() or (
                _avds[0] if _avds else ""
            )
            if _emu_bin and _avd:
                console.print(f"[dim][aipwn] {t('aipwn_emulator_starting', avd=_avd)}[/dim]")
                _booted = start_emulator_and_wait(_emu_bin, _avd, _adb)
                if _booted:
                    serial = serial or _booted
                    console.print(f"[green][aipwn] {t('aipwn_emulator_started', serial=_booted)}[/green]")
                else:
                    console.print(f"[yellow][aipwn] {t('aipwn_emulator_start_failed')}[/yellow]")
            else:
                console.print(f"[yellow][aipwn] {t('aipwn_emulator_not_found')}[/yellow]")

    # ── Paso 0: verificar que la app está instalada; si no, descargar e instalar ─
    if _adb:
        _adb_base = [_adb] + (["--", "-s", serial] if serial else [])
        # normalizar: -s debe ir antes de shell, no con --
        _adb_base = [_adb] + (["-s", serial] if serial else [])
        if not check_app_installed(_adb_base, package):
            console.print(
                f"[yellow][aipwn] {t('aipwn_app_not_installed', package=package)}[/yellow]"
            )
            apk_path = _auto_download_apk(package, config)
            if apk_path is None:
                msg = t('aipwn_auto_install_download_failed', package=package)
                console.print(f"[red][aipwn] {msg}[/red]")
                return AgentResult(
                    success=False, script_path=None, explanation=msg,
                    failure_reason=msg, frida_runs=0, iterations=0,
                    last_frida_result=None,
                )
            console.print(f"[dim]  [aipwn] {t('aipwn_auto_installing', apk=apk_path.name)}[/dim]")
            install_ok = _adb_install(apk_path, serial, package)
            if not install_ok:
                msg = t('aipwn_auto_install_failed', package=package)
                console.print(f"[red][aipwn] {msg}[/red]")
                return AgentResult(
                    success=False, script_path=None, explanation=msg,
                    failure_reason=msg, frida_runs=0, iterations=0,
                    last_frida_result=None,
                )
            console.print(f"[green][aipwn] {t('aipwn_auto_install_ok', package=package)}[/green]")

    # ── Paso 0b: health check del emulador (system_server vivo) ──────────────
    # Un system_server muerto hace fallar TODO spawn con DeadSystemException
    # (job 18, 2026-08-24: el agente quemó 11 iteraciones contra un emulador
    # muerto y la app nunca levantó). Mejor rebootear acá al inicio — solo
    # emuladores locales; un físico jamás se rebootea automáticamente.
    if _adb and serial and serial.startswith("emulator-") and not check_device_healthy(_adb_base):
        console.print(f"[yellow][aipwn] {t('aipwn_device_unhealthy')}[/yellow]")
        if reboot_device_and_wait(_adb_base):
            console.print(f"[green][aipwn] {t('aipwn_device_recovered')}[/green]")
        else:
            msg = t('aipwn_device_recovery_failed')
            console.print(f"[red][aipwn] {msg}[/red]")
            return AgentResult(
                success=False, script_path=None, explanation=msg,
                failure_reason=msg, frida_runs=0, iterations=0,
                last_frida_result=None,
            )

    # ── Paso 1: intentar script previo ───────────────────────────────────────
    # Se salta también al reanudar: no tiene sentido re-probar un script viejo
    # cuando lo que se quiere es continuar la conversación tal cual quedó.
    if not force and _resume_state is None:
        prev_script = _find_latest_script(package, _scripts_dir)
        if prev_script:
            console.print(
                f"[bold cyan][aipwn][/bold cyan] "
                f"{t('aipwn_prev_script_found', script=prev_script.name)}"
            )
            console.print(f"[dim]  {t('aipwn_testing_prev_script')}[/dim]\n")
            prev_result = launch_frida_capture(
                package=package,
                script_js=prev_script.read_text(),
                serial=serial,
                frida_host=_frida_host,
                duration=_capture_sec,
                iteration=0,
            )
            console.print(f"[dim]  [aipwn] {_escape(prev_result.summary())}[/dim]")
            if prev_result.success:
                console.print()
                console.print(Rule(f"[bold]{t('aipwn_result_header')}[/bold]"))
                console.print(Panel(
                    f"[bold green]✔ {t('aipwn_prev_script_ok')}[/bold green]\n\n"
                    f"[bold]{t('aipwn_script_label')}[/bold] {prev_script}\n"
                    f"[dim]{t('aipwn_no_llm_needed')}[/dim]",
                    border_style="green",
                ))
                return AgentResult(
                    success=True,
                    script_path=prev_script,
                    explanation="Script previo reutilizado (bypass verificado)",
                    failure_reason="",
                    frida_runs=1,
                    iterations=0,
                    last_frida_result=prev_result,
                )
            console.print(
                f"[yellow][aipwn] {t('aipwn_prev_script_failed')}[/yellow]\n"
            )
        else:
            console.print(f"[dim]  {t('aipwn_no_prev_scripts')}[/dim]\n")

    # ── Paso 2: agente LLM ───────────────────────────────────────────────────
    if _resume_state is not None:
        console.print(
            f"[bold cyan][aipwn][/bold cyan] Reanudando sesión guardada "
            f"({_resume_state.get('saved_at', '?')}) -- "
            f"iteración {_resume_state.get('iteration', 0)}, "
            f"+{extra_iterations} más.\n"
        )
    agent = FridaAgent(
        package=package,
        decompiled_dir=decompiled_dir,
        analysis_result=analysis_result,
        config=config,
        serial=serial,
        frida_host=_frida_host,
        max_frida_runs=_max_runs,
        max_llm_iterations=_max_llm_iterations,
        capture_seconds=_capture_sec,
        scripts_dir=_scripts_dir,
        runtime_dump_dir=runtime_dump_dir,
        resume_state=_resume_state,
        extra_iterations=extra_iterations,
    )

    try:
        result = agent.run()
    except KeyboardInterrupt:
        console.print("\n[yellow][aipwn] Ejecución interrumpida — guardando memoria...[/yellow]")
        agent._save_memory(outcome="failure", notes="Interrupted by user (Ctrl+C)")
        raise

    # Resumen final
    console.print()
    console.print(Rule(f"[bold]{t('aipwn_result_header')}[/bold]"))
    if result.success:
        console.print(Panel(
            f"[bold green]✔ {t('aipwn_bypass_success')}[/bold green]\n\n"
            f"[bold]{t('aipwn_explanation_label')}[/bold] {result.explanation}\n\n"
            f"[bold]{t('aipwn_script_label')}[/bold] {result.script_path}\n"
            f"[dim]{t('aipwn_frida_runs_label')}: {result.frida_runs} | "
            f"{t('aipwn_llm_calls_label')}: {result.iterations}[/dim]",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]✘ {t('aipwn_bypass_failed')}[/bold red]\n\n"
            f"[bold]{t('aipwn_diagnosis_label')}[/bold] {result.failure_reason}\n"
            f"[dim]{t('aipwn_frida_runs_label')}: {result.frida_runs} | "
            f"{t('aipwn_llm_calls_label')}: {result.iterations}[/dim]",
            border_style="red",
        ))

    # ── Handoff vivo: continuar interactivo con la conversación real ─────────
    # Solo si el operador lo pidió (--interactive) y la corrida NO tuvo éxito
    # (fallo o corte por límite de iteraciones). El co-piloto hereda
    # agent.messages tal cual -- no el resumen de agent_memory -- para poder
    # afinar el bypass exactamente donde quedó (ver query_agent.py).
    if interactive and not result.success:
        from nutcracker_core.store.hooks import db_path_from_config
        from .query_agent import QueryAgent, run_interactive_cli

        query_agent = QueryAgent(
            package=package,
            decompiled_dir=decompiled_dir,
            runtime_dump_dir=runtime_dump_dir,
            analysis_result=analysis_result,
            llm_config=llm_cfg,
            db_path=db_path_from_config(config),
            serial=serial,
            frida_host=_frida_host,
            resume_messages=agent.messages,
        )
        try:
            run_interactive_cli(query_agent)
        except KeyboardInterrupt:
            console.print("\n[dim][aipwn] sesión interactiva interrumpida.[/dim]")

    # ── Modo exploit: confirmar vulns en runtime post-bypass ─────────────────
    if exploit_mode and scan_result and result.success:
        try:
            from .exploit_agent import ExploitAgent
            exploit_agent = ExploitAgent(
                package=package,
                scan_result=scan_result,
                config=config,
                serial=serial,
                screenshots_dir=Path("reports") / package / "exploit_screenshots",
                bypass_script_path=result.script_path,
                decompiled_dir=decompiled_dir,
            )
            exploit_report = exploit_agent.run()
            result.exploit_report = exploit_report
        except Exception as _ex_err:
            console.print(f"[yellow][aipwn] ExploitAgent error: {_ex_err}[/yellow]")
    elif exploit_mode and not result.success:
        console.print("[yellow][aipwn] --exploit skipped: bypass did not succeed[/yellow]")
    elif exploit_mode and not scan_result:
        console.print("[yellow][aipwn] --exploit skipped: no vuln scan found for this package[/yellow]")

    return result


def _find_latest_script(package: str, scripts_dir: Path) -> Path | None:
    """
    Busca el script de bypass más reciente para el package en scripts_dir.
    El nombre de archivo sigue el patrón: bypass_{package}_{timestamp}_agent.js
    Retorna el más reciente (por nombre, que es por timestamp) o None.
    """
    if not scripts_dir.exists():
        return None
    candidates = sorted(scripts_dir.glob(f"bypass_{package}_*.js"), reverse=True)
    return candidates[0] if candidates else None


def _find_decompiled_dir(package: str) -> "tuple[Path | None, Path | None]":
    """
    Busca directorios de código decompilado para el paquete dado.

    Retorna (decompiled_dir, runtime_dump_dir):
      - decompiled_dir:    jadx estático  → decompiled/<package>/
      - runtime_dump_dir: FART dump       → decompiled/runtime_dump_<package>/

    Ambos pueden ser None si no existen.
    """
    static_dir = Path("decompiled") / package
    runtime_dir = Path("decompiled") / f"runtime_dump_{package}"

    def _valid(p: Path) -> bool:
        return p.exists() and (any(p.rglob("*.java")) or any(p.rglob("*.dex")))

    return (
        static_dir if _valid(static_dir) else None,
        runtime_dir if _valid(runtime_dir) else None,
    )


def _auto_download_apk(package: str, config: dict) -> "Path | None":
    """
    Intenta descargar el APK del package usando GooglePlay (si hay credenciales)
    o APKPure como fallback. Retorna el Path al APK o None si falla.
    """
    from nutcracker_core.downloader import download_apk_from_config, APKDownloadError
    gp_cfg = config.get("google_play", {})
    has_gp = bool(gp_cfg.get("email", "").strip() and gp_cfg.get("aas_token", "").strip())
    if has_gp:
        console.print(f"[dim]  [aipwn] {t('aipwn_auto_downloading_gp', package=package)}[/dim]")
    else:
        console.print(f"[dim]  [aipwn] {t('aipwn_auto_downloading_apkpure', package=package)}[/dim]")
    try:
        return download_apk_from_config(package, config)
    except APKDownloadError as exc:
        console.print(f"[yellow]  [aipwn] Download failed: {exc}[/yellow]")
    return None


def _adb_install(apk_path: "Path", serial: "str | None", package: str) -> bool:
    """
    Instala el APK en el dispositivo usando apk_tools.install_apk, que maneja:
    splits, firma incompatible (UPDATE_INCOMPATIBLE), MISSING_SPLIT, NO_MATCHING_ABIS.
    Si serial es None, lo obtiene de `adb get-serialno`.
    """
    from nutcracker_core.apk_tools import install_apk as _install_apk
    adb = shutil.which("adb")
    if not adb:
        return False

    # Resolver serial si no se pasó (primer dispositivo USB)
    _serial = serial
    if not _serial:
        try:
            r = subprocess.run(
                [adb, "get-serialno"], capture_output=True, text=True, timeout=5
            )
            _serial = r.stdout.strip()
        except Exception:
            pass
    if not _serial:
        console.print("[yellow]  [aipwn] No device serial found — is a device connected?[/yellow]")
        return False

    def _cb(msg: str) -> None:
        console.print(f"[dim]  [aipwn] {msg}[/dim]")

    return _install_apk(
        serial=_serial,
        tools={"adb": adb},
        apk_path=apk_path,
        package_name=package,
        progress_callback=_cb,
    )
