#!/usr/bin/env python3
"""
nutcracker - CLI principal.

Uso:
    python nutcracker.py scan <url_o_package_id>           # descarga desde APKPure + analiza
    python nutcracker.py scan <url> --source google-play   # descarga desde Google Play + analiza
    python nutcracker.py analyze <ruta_apk>                # analiza una APK local
"""

import sys
import os
import subprocess
import time
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn

from nutcracker_core.analyzer import APKAnalyzer
from nutcracker_core.config import load_config, get as cfg_get
from nutcracker_core.decompiler import decompile, get_available_tool, install_instructions, DecompilerError
from nutcracker_core.deobfuscator import (
    apply_decrypt_map,
    check_adb,
    decompile_dumps,
)
from nutcracker_core.downloader import APKPureDownloader, GooglePlayDownloader, DirectURLDownloader, APKDownloadError, is_direct_apk_url
from nutcracker_core.device import (
    find_sdk_tools,
    get_frida_version,
    list_avds,
)
from nutcracker_core.frida_bypass import (
    fart_run_instructions,
    frida_run_instructions,
    generate_bypass_script,
    generate_fart_script,
)
from nutcracker_core import i18n
from nutcracker_core.i18n import t
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

    if serial:
        frida_cmd = [frida_bin, "-D", serial, "-f", package, "-l", str(script_path)]
    else:
        frida_cmd = [frida_bin, "-U", "-f", package, "-l", str(script_path)]

    console.print(f"[green]▶[/green]  [bold cyan]{' '.join(frida_cmd)}[/bold cyan]")
    os.execvp(frida_cmd[0], frida_cmd)


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
            if not _shutil.which("jadx"):
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
    scanner_engine = cfg_get(_CFG, "strategies", "scanner_engine", default="auto") or "auto"
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


# ── Banner ────────────────────────────────────────────────────────────────────

def _print_banner() -> None:
    from rich.text import Text
    from rich.panel import Panel
    from rich.align import Align
    from rich.console import Group

    # ── Mapa de colores ───────────────────────────────────────────────────
    _COLORS = {
        ".": None,
        "G": "#444444",   # gris oscuro (sombrero)
        "Y": "#FFD700",   # dorado (hombreras)
        "K": "#2A2A2A",   # cara
        "W": "#EEEEEE",   # blanco
        "r": "#FF1111",   # ojos rojos
        "B": "#996633",   # barba
        "L": "#555555",   # contorno
    }
    _SPECIAL_CHARS = {"S": ("★", "#44CC44")}

    _PIXELS = [
        "......GGGG......",
        ".....GGGGGG.....",
        ".....GGGGGG.....",
        ".....GGGSGG.....",
        ".....GGGGGG.....",
        "...WLKKKKKKLW...",
        "...WLrrKKrrLW...",
        "...WWWWWWWWWW...",
        "...WLWKKKKWLW...",
        "...WLBBBBBBLW...",
        "YYY.LBBBBBBL.YYY",
        ".YY..LBBBBL..YY.",
        ".....LBBBBL.....",
        "......LBBL......",
    ]

    w = len(_PIXELS[0])
    lines: list[Text] = []
    for y in range(0, len(_PIXELS), 2):
        top, bot = _PIXELS[y], _PIXELS[y + 1]
        line = Text()
        for x in range(w):
            ts = _SPECIAL_CHARS.get(top[x])
            bs = _SPECIAL_CHARS.get(bot[x])
            if ts or bs:
                ch, col = ts or bs
                other = _COLORS.get(bot[x] if ts else top[x])
                line.append(ch, style=f"{col} on {other}" if other else col)
                continue
            tc = _COLORS.get(top[x])
            bc = _COLORS.get(bot[x])
            if tc is None and bc is None:
                line.append(" ")
            elif tc == bc:
                line.append("█", style=tc)
            elif tc and bc is None:
                line.append("▀", style=tc)
            elif tc is None and bc:
                line.append("▄", style=bc)
            else:
                line.append("▀", style=f"{tc} on {bc}")
        lines.append(line)

    n = len(lines)
    name_rows = [
        "╔╗╔╦ ╦╔╦╗╔═╗╦═╗╔═╗╔═╗╦╔═╔═╗╦═╗",
        "║║║║ ║ ║ ║  ╠╦╝╠═╣║  ╠╩╗║╣ ╠╦╝",
        "╝╚╝╚═╝ ╩ ╚═╝╩╚═╩ ╩╚═╝╩ ╩╚═╝╩╚═",
    ]

    right: list[Text | None] = [None] * n
    for i, row in enumerate(name_rows):
        t = Text()
        t.append(row, style="bold red")
        right[1 + i] = t

    tag = Text()
    tag.append("★ ", style="bold green")
    tag.append("Mobile Security & Offensive Threat Intelligence", style="bold white")
    tag.append(" ★", style="bold green")
    right[min(4, n - 1)] = tag

    ver = Text()
    ver.append("v0.1", style="dim green")
    ver.append(" · ", style="dim")
    ver.append("nutcracker.sh", style="dim red link https://nutcracker.sh")
    right[min(5, n - 1)] = ver

    combined = Text()
    gap = "   "
    for i, sl in enumerate(lines):
        combined.append_text(sl)
        combined.append(gap)
        if right[i] is not None:
            combined.append_text(right[i])
        combined.append("\n")

    content = Align.center(combined)
    console.print(Panel(content, border_style="red", padding=(1, 2)))
    console.print()


# ── Grupo de comandos ──────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option("0.1.0", prog_name="nutcracker")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """nutcracker: detects anti-root protections in Android applications (APK)."""
    _print_banner()
    if ctx.invoked_subcommand is None:
        click.echo("usage: python nutcracker.py scan 'https://play.google.com/store/apps/details?id=...'")
        ctx.exit(0)


# ── Comando: scan ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("url")
@click.option(
    "--config", "-c",
    "config_path",
    default="config.yaml",
    show_default=True,
    metavar="ARCHIVO",
    help="Path to YAML config file.",
)
@click.option(
    "--source", "-s",
    default=None,
    type=click.Choice(["apk-pure", "google-play"], case_sensitive=False),
    help="Download source. Default: google-play if credentials in config, else apk-pure.",
)
@click.option(
    "--output-dir", "-o",
    default=None,
    help="Directory to save downloaded APKs.",
)
@click.option(
    "--keep-apk",
    is_flag=True,
    default=False,
    help="Keep the APK after analysis.",
)
@click.option(
    "--report", "-r",
    default=None,
    metavar="ARCHIVO",
    help="Path to save the JSON report.",
)
def scan(url: str, config_path: str, source: str | None, output_dir: str | None,
         keep_apk: bool, report: str | None) -> None:
    """
    Download an APK and analyze it for anti-root protections.

    URL can be:
      - Google Play URL (https://play.google.com/store/apps/details?id=...)
      - Package ID directly (com.example.app)
      - Direct URL to an .apk file (https://example.com/app.apk)
    """
    global _CFG
    config = load_config(config_path)
    _CFG = config
    _init_i18n(config)
    output_dir = output_dir or cfg_get(config, "downloader", "output_dir") or "./downloads"

    if not keep_apk:
        keep_apk = bool(cfg_get(config, "downloader", "keep_apk", default=False))

    # ── URL directa a un APK ──────────────────────────────────────────────────
    if is_direct_apk_url(url):
        apk_path: Path | None = None
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(t("cli_downloading_apk"), total=None)

                def _on_chunk(downloaded: int, total: int | None) -> None:
                    progress.update(task, completed=downloaded, total=total)

                _dl = DirectURLDownloader(output_dir)
                _from_cache = keep_apk and _dl.dest_path(url).exists()
                apk_path = _dl.download(url, progress_callback=_on_chunk, use_cache=keep_apk)
            if _from_cache:
                console.print(f"[green]✔[/green] {t('cli_apk_cached')} [bold]{apk_path}[/bold]")
            else:
                console.print(f"[green]✔[/green] {t('cli_apk_downloaded')} [bold]{apk_path}[/bold]")
        except APKDownloadError as exc:
            console.print(f"[red]{t('cli_error_download')}[/red] {exc}")
            sys.exit(1)
        _run_analysis(apk_path, report, keep_apk, gen_pdf=cfg_get(config, "reports", "save_pdf", default=True))
        return

    # Credenciales de Google Play
    email = cfg_get(config, "google_play", "email")
    aas_token = cfg_get(config, "google_play", "aas_token")

    # Auto-determinar fuente si no se especificó
    if source is None:
        # Si hay email configurado, priorizar Google Play y permitir autogenerar aas_token.
        source = "google-play" if email else "apk-pure"

    # Informe JSON automático si está configurado
    save_json_cfg = bool(
        cfg_get(config, "features", "report_json", default=cfg_get(config, "reports", "save_json", default=False))
    )
    if not report and save_json_cfg:
        reports_dir = cfg_get(config, "reports", "output_dir") or "./reports"
        Path(reports_dir).mkdir(parents=True, exist_ok=True)
        pkg = url.split("id=")[-1].split("&")[0].rstrip("/")
        report = str(Path(reports_dir) / f"{pkg}.json")
    save_pdf = bool(
        cfg_get(config, "features", "report_pdf", default=cfg_get(config, "reports", "save_pdf", default=True))
    )

    # Descargar
    apk_path = None
    try:
        if source == "google-play":
            if not email:
                console.print(f"[red]Error:[/red] {t('cli_gplay_requires_email')}")
                sys.exit(1)

            if not aas_token:
                console.print(
                    f"[yellow]Warning:[/yellow] {t('cli_gplay_token_empty')}"
                )
                script = Path(__file__).parent / "tools" / "extract_token.py"
                if not script.exists():
                    console.print(f"[red]Error:[/red] {t('cli_extract_token_not_found')}")
                    sys.exit(1)

                cmd = [sys.executable, str(script), "--config", config_path]
                preferred_serial = _select_token_serial(config)
                if preferred_serial:
                    cmd += ["--serial", preferred_serial]
                if _unattended():
                    cmd.append("--no-interactive")

                token_proc = subprocess.run(cmd)
                if token_proc.returncode != 0:
                    console.print(
                        f"[red]Error:[/red] {t('cli_token_gen_failed')}"
                    )
                    sys.exit(token_proc.returncode)

                # Recargar config para continuar en la misma ejecución usando el token recién guardado.
                config = load_config(config_path)
                _CFG = config
                aas_token = cfg_get(config, "google_play", "aas_token")

                if not aas_token:
                    console.print(
                        f"[red]Error:[/red] {t('cli_token_still_empty')}"
                    )
                    sys.exit(1)

            if aas_token:
                # Método preferido: apkeep con AAS token
                label = "Google Play (apkeep)"
                downloader: APKPureDownloader | GooglePlayDownloader = \
                    GooglePlayDownloader(email, aas_token, output_dir)
            else:
                console.print(
                    f"[red]Error:[/red] {t('cli_gplay_run_setup_token')}"
                )
                sys.exit(1)
        else:
            label = "APKPure"
            downloader = APKPureDownloader(output_dir)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            progress.add_task(t("cli_downloading_from", label=label), total=None)
            apk_path = downloader.download(url)

        console.print(f"[green]✔[/green] {t('cli_apk_downloaded')} [bold]{apk_path}[/bold]")
    except APKDownloadError as exc:
        console.print(f"[red]{t('cli_error_download')}[/red] {exc}")
        sys.exit(1)

    _run_analysis(apk_path, report, keep_apk, gen_pdf=cfg_get(config, "reports", "save_pdf", default=True))


# ── Comando: analyze (APK local) ──────────────────────────────────────────────

@cli.command()
@click.argument("apk_path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--config", "-c",
    "config_path",
    default="config.yaml",
    show_default=True,
    metavar="ARCHIVO",
)
@click.option(
    "--report", "-r",
    default=None,
    metavar="ARCHIVO",
    help="Path to save the JSON report.",
)
@click.option(
    "--launch", "-L",
    is_flag=True,
    default=False,
    help="After analysis, launch the app on device with the generated bypass script.",
)
@click.option(
    "--serial", "-s",
    default=None,
    metavar="SERIAL",
    help="ADB device serial for --launch (default: first available).",
)
def analyze(apk_path: str, config_path: str, report: str | None, launch: bool, serial: str | None) -> None:
    """Analyze a local APK for anti-root protections."""
    global _CFG, _LAUNCH_APP, _LAUNCH_SERIAL
    _LAUNCH_APP = launch
    _LAUNCH_SERIAL = serial
    config = load_config(config_path)
    _CFG = config
    _init_i18n(config)
    save_json_cfg = bool(
        cfg_get(config, "features", "report_json", default=cfg_get(config, "reports", "save_json", default=False))
    )
    if not report and save_json_cfg:
        reports_dir = cfg_get(config, "reports", "output_dir") or "./reports"
        Path(reports_dir).mkdir(parents=True, exist_ok=True)
        report = str(Path(reports_dir) / f"{Path(apk_path).stem}.json")
    save_pdf = bool(
        cfg_get(config, "features", "report_pdf", default=cfg_get(config, "reports", "save_pdf", default=True))
    )

    _run_analysis(Path(apk_path), report, keep_apk=True, gen_pdf=save_pdf)


# ── Comando: launch (lanzar app con bypass script) ────────────────────────────

@cli.command()
@click.argument("package")
@click.option(
    "--script", "-l",
    default=None,
    metavar="SCRIPT",
    help="Bypass JS script to use. If omitted, uses the latest generated for the package.",
)
@click.option(
    "--serial", "-s",
    default=None,
    metavar="SERIAL",
    help="ADB device serial (default: first available via -U).",
)
@click.option(
    "--scripts-dir",
    default="frida_scripts",
    show_default=True,
    metavar="DIR",
    help="Directory to search for bypass scripts.",
)
def launch(package: str, script: str | None, serial: str | None, scripts_dir: str) -> None:
    """Launch the app on device with the latest generated bypass script.

    \b
    Examples:
      python nutcracker.py launch com.appexample
      python nutcracker.py launch downloads/com.appexample/com.appexample.apk
      python nutcracker.py launch com.appexample --script frida_scripts/bypass_....js
      python nutcracker.py launch com.appexample --serial emulator-5554
    """
    scripts_path = Path(scripts_dir)

    # Aceptar APK path como argumento: extraer package del nombre del archivo
    pkg = package
    p = Path(package)
    if p.suffix.lower() == ".apk" or "/" in package:
        pkg = p.stem  # e.g. "com.appexample.apk" → "com.appexample"
        console.print(f"[dim]  {t('cli_apk_detected_pkg', pkg=pkg)}[/dim]")

    if script:
        script_path = Path(script)
        if not script_path.exists():
            console.print(f"[red]Error:[/red] {t('cli_script_not_found', script=script)}")
            raise SystemExit(1)
    else:
        script_path = _find_latest_bypass_script(pkg, scripts_path)
        if not script_path:
            console.print(
                f"[yellow]⚠[/yellow]  {t('cli_no_bypass_found', pkg=pkg, scripts_dir=scripts_dir)}"
            )
            raise SystemExit(1)

    console.print(f"[green]✔[/green] Script: [bold]{script_path}[/bold]")
    _launch_frida_bypass(pkg, script_path, serial)


@cli.command("setup-token")
@click.option(
    "--config", "config_path",
    default="config.yaml",
    show_default=True,
    metavar="ARCHIVO",
    help="Path to YAML config file.",
)
@click.option("--serial", default=None, help="ADB serial of the target device.")
@click.option(
    "--method",
    default="auto",
    type=click.Choice(["auto", "root", "dumpsys", "gsf"], case_sensitive=False),
    show_default=True,
    help="Token extraction method.",
)
@click.option("--no-interactive", is_flag=True, default=False, help="Skip confirmation prompts.")
def setup_token(config_path: str, serial: str | None, method: str, no_interactive: bool) -> None:
    """Interactive wizard to obtain and save google_play.aas_token."""
    script = Path(__file__).parent / "tools" / "extract_token.py"
    if not script.exists():
        console.print(f"[red]Error:[/red] {t('cli_extract_token_not_found')}")
        raise SystemExit(1)

    cfg = load_config(config_path)
    auto_serial = serial or _select_token_serial(cfg)

    cmd = [sys.executable, str(script), "--config", config_path, "--method", method.lower()]
    if auto_serial:
        cmd += ["--serial", auto_serial]
    if no_interactive:
        cmd.append("--no-interactive")

    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


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

            analyzer = APKAnalyzer(progress_callback=on_progress, engine=anti_root_engine)
            result = analyzer.analyze(apk_path)

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
        save_analysis_json(result, scan_result=vuln_scan)

        # ── Resumen MASVS v2 ─────────────────────────────────────────────
        try:
            from nutcracker_core.masvs import build_masvs_report
            _masvs = build_masvs_report(result, vuln_scan)
            print_masvs_summary(_masvs)
        except Exception:
            pass

        # ── Veredicto final en terminal ───────────────────────────────────
        _print_verdict(result, vuln_scan)

        # Generar PDF solo si está habilitado en config (save_pdf)
        if gen_pdf:
            _generate_pdf(result, vuln_scan)

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
    should_try_runtime = bool(dexguard_result) or (decomp_mode == "runtime")

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
                        _launch_frida_bypass(result.package, bp_path, _LAUNCH_SERIAL)
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
                    _launch_frida_bypass(result.package, script_path, _LAUNCH_SERIAL)
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
        manifest_analysis = _do_manifest_scan(clean_dir)
    else:
        console.print(f"[dim]{t('cli_skipping_manifest_scan')}[/dim]")

    # Escaneo de vulnerabilidades y leaks (antes de OSINT para alimentarlo)
    scan_result = None
    vuln_enabled = _feature_enabled("vuln_scan", default=True)
    leak_enabled = _feature_enabled("leak_scan", default=True)
    if not vuln_enabled and not leak_enabled:
        console.print(f"[dim]{t('cli_skipping_vuln_scan')}[/dim]")
    elif _ask_or_auto(
        t("cli_vuln_scan_deobf_prompt"),
        "vuln_scan",
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


def _do_manifest_scan(decompiled_dir: Path) -> "ManifestAnalysisResult | None":
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
    """Guarda el resultado OSINT en JSON."""
    import json
    reports_dir = Path("./reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / f"osint_{package}.json"
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
    tool, _ = get_available_tool()
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
            dest = decompile(apk_path, output_dir)

        console.print(f"[green]✔[/green] {t('cli_source_code_at')} [bold]{dest}[/bold]")

        java_files = list(dest.rglob("*.java"))
        smali_files = list(dest.rglob("*.smali"))
        if java_files:
            console.print(f"   {t('cli_java_files', count=len(java_files))}")
        elif smali_files:
            console.print(f"   {t('cli_smali_files', count=len(smali_files))}")

        # Análisis de misconfigs del manifest
        if _feature_enabled("manifest_scan", default=True):
            _do_manifest_scan(dest)
        else:
            console.print(f"[dim]{t('cli_skipping_manifest_scan')}[/dim]")

        # Escaneo de vulnerabilidades y leaks (antes de OSINT para alimentarlo)
        scan_result = None
        vuln_enabled = _feature_enabled("vuln_scan", default=True)
        leak_enabled = _feature_enabled("leak_scan", default=True)
        if not vuln_enabled and not leak_enabled:
            console.print(f"[dim]{t('cli_skipping_vuln_scan')}[/dim]")
        elif _ask_or_auto(t("cli_vuln_scan_code_prompt"), "vuln_scan", default=True):
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
    engine = cfg_get(_CFG, "strategies", "scanner_engine") or "auto"

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
            cfg_get(_CFG, "strategies", "scanner_config")
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
                    )
                    leaks.extend([f for f in base_scan.findings if _is_leak_finding(f)])

                # 2) apkleaks sobre el APK original
                if use_apkleaks and apk_for_leaks is not None:
                    try:
                        leaks.extend(scan_with_apkleaks(apk_for_leaks))
                    except Exception as exc:  # noqa: BLE001
                        console.print(f"[yellow]⚠[/yellow] {t('cli_apkleaks_failed')} {exc}")

                # 3) gitleaks sobre código decompilado
                if use_gitleaks:
                    try:
                        leaks.extend(scan_with_gitleaks(source_dir))
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

        print_vuln_report(scan_result, source_dir)
        pkg_name = package_hint or source_dir.name
        canonical_report = Path("./decompiled") / f"vuln_{pkg_name}.json"
        _save_vuln_json(scan_result, canonical_report)
        legacy_report = source_dir.parent / f"vuln_{source_dir.name}.json"
        if legacy_report.resolve() != canonical_report.resolve():
            _save_vuln_json(scan_result, legacy_report)
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
                gl_findings = scan_with_gitleaks(source_dir)
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

    print_vuln_report(scan_result, source_dir)

    # Guardar JSON con nombre canónico por paquete para que el PDF siempre
    # cargue el último scan correcto (incluyendo flujos DexGuard/FART).
    pkg_name = package_hint or source_dir.name
    canonical_report = Path("./decompiled") / f"vuln_{pkg_name}.json"
    _save_vuln_json(scan_result, canonical_report)

    # Compatibilidad: mantener también el path histórico local al source_dir.
    legacy_report = source_dir.parent / f"vuln_{source_dir.name}.json"
    if legacy_report.resolve() != canonical_report.resolve():
        _save_vuln_json(scan_result, legacy_report)
    return scan_result


def _load_vuln_json(package: str):
    """Carga el JSON de vulnerabilidades guardado previamente, si existe."""
    import json
    from nutcracker_core.vuln_scanner import ScanResult, VulnFinding

    json_path = Path("./decompiled") / f"vuln_{package}.json"
    if not json_path.exists():
        return None
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        base_dir = Path("./decompiled") / package
        findings = [
            VulnFinding(
                rule_id=f["rule_id"],
                title=f["title"],
                severity=f["severity"],
                category=f["category"],
                file=base_dir / f["file"],
                line=f["line"],
                matched_text=f["matched_text"],
                description=f["description"],
                recommendation=f["recommendation"],
            )
            for f in data.get("findings", [])
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
        jsons = sorted(pkg_dir.glob("*.json"), reverse=True)
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


def _generate_pdf(result, vuln_scan=None) -> None:
    """Genera el informe PDF final con los resultados de anti-root y vulnerabilidades."""
    # Si no se pasó un scan en esta sesión, intentar cargar el JSON guardado
    if vuln_scan is None:
        vuln_scan = _load_vuln_json(result.package)
        if vuln_scan is not None:
            console.print(
                f"[dim]  {t('cli_loading_prev_findings', count=len(vuln_scan.findings))}[/dim]"
            )

    reports_dir = Path("./reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = reports_dir / f"{result.package}.pdf"
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            progress.add_task(t("cli_generating_pdf"), total=None)
            generate_pdf_report(result, pdf_path, scan=vuln_scan, manifest=_MANIFEST_ANALYSIS, osint=_OSINT_RESULT)
        console.print(f"[green]✔[/green] {t('cli_pdf_saved')} [bold]{pdf_path}[/bold]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{t('cli_error_pdf')}[/red] {exc}")


def _save_vuln_json(scan_result, output_path: Path) -> None:
    """Guarda los hallazgos de vulnerabilidades en JSON."""
    import json
    output_path.parent.mkdir(parents=True, exist_ok=True)
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
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    console.print(f"[dim]{t('cli_vuln_json_saved')}[/dim] [bold]{output_path}[/bold]")


# ── Comando: batch ───────────────────────────────────────────────────────────

@cli.command()
@click.argument("list_file", type=click.Path(dir_okay=False), required=False, default=None)
@click.option(
    "--config", "-c",
    "config_path",
    default="config.yaml",
    show_default=True,
    metavar="ARCHIVO",
    help="Path to YAML config file.",
)
@click.option(
    "--output-dir", "-o",
    default=None,
    help="Directory to save PDF/JSON reports.",
)
@click.option(
    "--keep-apk",
    is_flag=True,
    default=False,
    help="Keep downloaded APKs after each analysis.",
)
@click.option(
    "--stop-on-error",
    is_flag=True,
    default=False,
    help="Stop on first error (default: continue).",
)
def batch(
    list_file: str | None,
    config_path: str,
    output_dir: str | None,
    keep_apk: bool,
    stop_on_error: bool,
) -> None:
    """
    Scan a list of APKs or URLs in batch mode.

    LIST_FILE is a text file with one entry per line:
      - Google Play URLs   (https://play.google.com/...)
      - Package IDs        (com.example.app)
      - Direct APK URLs    (https://cdn.example.com/app.apk)
      - Local APK paths    (/path/to/app.apk)

    Lines starting with '#' or empty lines are ignored.
    """
    global _CFG
    started_at = time.perf_counter()
    config = load_config(config_path)
    _CFG = config
    _init_i18n(config)

    batch_cfg   = cfg_get(config, "batch") or {}
    _keep_apk   = keep_apk or bool(batch_cfg.get("keep_apk",   cfg_get(config, "downloader", "keep_apk", default=False)))
    _stop_on_err = stop_on_error or bool(batch_cfg.get("stop_on_error", False))
    reports_dir = output_dir or batch_cfg.get("reports_dir") or cfg_get(config, "reports", "output_dir") or "./reports"
    dl_dir      = batch_cfg.get("download_dir") or cfg_get(config, "downloader", "output_dir") or "./downloads"
    save_pdf    = cfg_get(config, "reports", "save_pdf", default=True)

    # Resolver list_file: CLI > config batch.list_file
    resolved_list_file = list_file or batch_cfg.get("list_file")
    if not resolved_list_file:
        console.print(f"[red]✘[/red] {t('cli_batch_list_missing')}")
        raise SystemExit(1)
    resolved_list_file = Path(resolved_list_file)
    if not resolved_list_file.exists():
        console.print(f"[red]✘[/red] {t('cli_batch_file_not_found', path=resolved_list_file)}")
        raise SystemExit(1)

    # Leer lista de targets
    raw_lines = resolved_list_file.read_text(encoding="utf-8").splitlines()
    targets = [l.strip() for l in raw_lines if l.strip() and not l.strip().startswith("#")]

    if not targets:
        console.print(f"[yellow]{t('cli_batch_empty_list')}[/yellow]")
        return

    console.print(f"[bold cyan]Batch scan:[/bold cyan] {t('cli_batch_scan_header', count=len(targets), file=list_file)}")
    console.rule()

    results_summary: list[dict] = []

    for idx, target in enumerate(targets, 1):
        console.print(f"\n[bold][[{idx}/{len(targets)}]][/bold] {target}")

        apk_path: Path | None = None
        is_local = Path(target).exists() and target.lower().endswith(".apk")

        # ── Descarga si no es local ───────────────────────────────────────────
        if not is_local:
            try:
                if is_direct_apk_url(target):
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        DownloadColumn(),
                        TransferSpeedColumn(),
                        console=console,
                        transient=True,
                    ) as progress:
                        task = progress.add_task(t("cli_batch_downloading"), total=None)
                        def _on_chunk(dl: int, tot: int | None) -> None:
                            progress.update(task, completed=dl, total=tot)
                        apk_path = DirectURLDownloader(dl_dir).download(target, progress_callback=_on_chunk, use_cache=_keep_apk)
                else:
                    # Google Play / APKPure
                    email     = cfg_get(config, "google_play", "email")
                    aas_token = cfg_get(config, "google_play", "aas_token")
                    if email and aas_token:
                        dl = GooglePlayDownloader(email, aas_token, dl_dir)
                    else:
                        dl = APKPureDownloader(dl_dir)
                    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                                  console=console, transient=True) as progress:
                        progress.add_task(t("cli_batch_downloading"), total=None)
                        apk_path = dl.download(target)
                console.print(f"  [green]✔[/green] {t('cli_batch_downloaded', name=apk_path.name)}")
            except APKDownloadError as exc:
                console.print(f"  [red]{t('cli_batch_download_error')}[/red] {exc}")
                results_summary.append({"target": target, "status": "error_download", "error": str(exc)})
                if _stop_on_err:
                    break
                continue
        else:
            apk_path = Path(target)

        # ── Análisis ──────────────────────────────────────────────────────────
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          console=console, transient=True) as progress:
                task = progress.add_task(t("cli_batch_analyzing"), total=None)
                def on_prog(msg: str) -> None:
                    progress.update(task, description=msg)
                analyzer = APKAnalyzer(progress_callback=on_prog)
                result = analyzer.analyze(apk_path)

            # PDF individual por app
            pkg = result.package
            pdf_path: Path | None = None
            if save_pdf:
                Path(reports_dir).mkdir(parents=True, exist_ok=True)
                pdf_dest = Path(reports_dir) / f"{pkg}.pdf"
                scan_result = _post_analysis_flow(result, apk_path)
                # Guardar JSON una vez que todos los datos están completos
                save_analysis_json(result, scan_result=scan_result)
                from nutcracker_core.pdf_reporter import generate_pdf_report
                pdf_path = generate_pdf_report(result, pdf_dest, scan=scan_result, manifest=_MANIFEST_ANALYSIS)
                console.print(f"  [green]✔[/green] PDF: [bold]{pdf_path}[/bold]")
            else:
                scan_result = _post_analysis_flow(result, apk_path)
                # Guardar JSON una vez que todos los datos están completos
                save_analysis_json(result, scan_result=scan_result)

            status = "protected_broken" if result.protection_broken \
                else ("protected" if result.protected else "unprotected")

            # Enriquecer datos para reporte batch consolidado
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            leaks_count = 0
            top_findings: list[tuple[str, str, str]] = []
            cat_max_sev: dict[str, str] = {}  # categoría → peor severidad
            if scan_result:
                seen_rules: set[str] = set()
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                for f in scan_result.findings:
                    sev = getattr(f, "severity", "info").lower()
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                    rid = getattr(f, "rule_id", "")
                    cat = getattr(f, "category", "")
                    # Peor severidad por categoría
                    if cat:
                        prev = cat_max_sev.get(cat, "info")
                        if sev_order.get(sev, 5) < sev_order.get(prev, 5):
                            cat_max_sev[cat] = sev
                    # Contar leaks
                    if rid.upper().startswith(("AL-", "HC", "GL-")):
                        leaks_count += 1
                    # Top findings (únicos por rule_id, ordenados por severidad)
                    if rid not in seen_rules:
                        seen_rules.add(rid)
                        top_findings.append((rid, getattr(f, "title", ""), sev))
                top_findings.sort(key=lambda x: sev_order.get(x[2], 5))
                top_findings = top_findings[:5]

            results_summary.append({
                "target":  target,
                "package": pkg,
                "status":  status,
                "pdf":     str(pdf_path) if pdf_path else None,
                "findings": len(scan_result.findings) if scan_result else 0,
                **sev_counts,
                "leaks": leaks_count,
                "top_findings": top_findings,
                "categories": cat_max_sev,
            })
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]{t('cli_batch_analysis_error')}[/red] {exc}")
            results_summary.append({"target": target, "status": "error_analysis", "error": str(exc)})
            if _stop_on_err:
                break

        finally:
            if not _keep_apk and apk_path and apk_path.exists() and not is_local:
                apk_path.unlink()

    # ── Resumen final ─────────────────────────────────────────────────────────
    console.rule()
    console.print(f"\n[bold]{t('cli_batch_summary_header', count=len(results_summary))}[/bold]\n")
    ok      = [r for r in results_summary if "error" not in r["status"]]
    errors  = [r for r in results_summary if "error" in r["status"]]
    broken  = [r for r in ok if r["status"] == "protected_broken"]
    console.print(f"  [green]{t('cli_batch_ok_label')}[/green]              {len(ok)}")
    console.print(f"  [red]{t('cli_batch_errors_label')}[/red]         {len(errors)}")
    console.print(f"  [yellow]{t('cli_batch_broken_label')}[/yellow]  {len(broken)}")

    if errors:
        console.print(f"\n[dim]{t('cli_batch_error_targets')}[/dim]")
        for r in errors:
            console.print(f"  - {r['target']}  ({r['error'][:80]})")

    # ── Reporte batch consolidado ─────────────────────────────────────────────
    if save_pdf and len(results_summary) > 1:
        from nutcracker_core.pdf_reporter import generate_batch_report
        batch_pdf = Path(reports_dir) / "batch_report.pdf"
        generate_batch_report(results_summary, batch_pdf)
        console.print(f"\n[bold green]✔[/bold green] {t('cli_batch_consolidated_report')} [bold]{batch_pdf}[/bold]")

    _print_elapsed(t("cli_elapsed_batch"), time.perf_counter() - started_at)


# ── Comando: regen-pdf ────────────────────────────────────────────────────────

@cli.command("regen-pdf")
@click.argument("package")
def regen_pdf(package: str) -> None:
    """Regenerate the PDF for a package from its saved JSON in reports/.

    PACKAGE is the package name, e.g.: com.example.myapp
    """
    result = _load_analysis_json(package)
    if result is None:
        console.print(f"[red]{t('cli_regen_pdf_not_found', package=package)}[/red]")
        raise SystemExit(1)
    console.print(f"[dim]{t('cli_regen_pdf_loaded', package=result.package, analyzed_at=result.analyzed_at)}[/dim]")

    # Cargar vuln scan si existe
    vuln_scan = _load_vuln_json(package)
    if vuln_scan is not None:
        console.print(f"[dim]{t('cli_regen_pdf_findings', count=len(vuln_scan.findings))}[/dim]")

    # Cargar manifest si existe
    manifest = None
    try:
        from nutcracker_core.manifest_analyzer import ManifestAnalyzer
        # Intentar desde dexguard_dump o directorio normal
        for candidate in [
            Path("./decompiled") / f"dexguard_dump_{package}" / "source",
            Path("./decompiled") / package,
        ]:
            manifest_path = candidate / "resources" / "AndroidManifest.xml"
            if not manifest_path.exists():
                manifest_path = candidate / "AndroidManifest.xml"
            if manifest_path.exists():
                ma = ManifestAnalyzer()
                manifest = ma.analyze(manifest_path)
                console.print(f"[dim]{t('cli_manifest_loaded', path=manifest_path)}[/dim]")
                break
    except Exception:  # noqa: BLE001
        pass

    global _MANIFEST_ANALYSIS
    _MANIFEST_ANALYSIS = manifest

    _generate_pdf(result, vuln_scan)


# ── Punto de entrada ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
