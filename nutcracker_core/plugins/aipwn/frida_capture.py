"""
frida_capture.py — Ejecución de Frida con captura de output en tiempo real.

A diferencia de _launch_frida_bypass (que usa os.execvp y reemplaza el proceso),
aquí usamos subprocess.Popen para capturar stdout + logcat en paralelo y analizar
el resultado programáticamente.

Uso:
    from nutcracker_core.frida_capture import launch_frida_capture, FridaRunResult

    result = launch_frida_capture(
        package="com.example.app",
        script_js="Java.perform(function() { ... });",
        serial=None,
        duration=30,
    )
    if result.success:
        print("Bypass exitoso!")
"""

from __future__ import annotations

import re
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


from rich.console import Console
from rich.markup import escape as _escape
from nutcracker_core.i18n import t

console = Console()

# ── Patrones de análisis ──────────────────────────────────────────────────────

_HOOK_OK_RE = re.compile(
    r"\[Bypass\].*✔|hook installed|Intercepted|hooked successfully",
    re.IGNORECASE,
)
_HOOK_FAIL_RE = re.compile(
    r"unable to find (class|method)|Error:.*find|no overload|ClassNotFound|"
    r"java\.lang\.ClassNotFoundException",
    re.IGNORECASE,
)
_SSL_ERROR_RE = re.compile(
    r"CERTIFICATE_VERIFY_FAILED|SSLHandshakeException|ssl_verify_peer|"
    r"certificate.*pinning|CertPathValidatorException",
    re.IGNORECASE,
)
# Crash definitivo: proceso muerto por señal o por crash no capturado.
# NOTA: RuntimeException EXCLUIDA — los hooks Frida loguean excepciones capturadas
# como 'Error: java.lang.RuntimeException: ...' aunque la app sigue corriendo.
# FATAL EXCEPTION es el indicador real de crash en Android (AndroidRuntime lo emite).
_CRASH_RE = re.compile(
    r"Process.*crash|SIGKILL|SIGSEGV|FATAL EXCEPTION",
    re.IGNORECASE,
)
_ANTI_FRIDA_RE = re.compile(
    r"Frida detected|tampering detected|integrity.*fail|"
    r"debugger.*detected|anti.frida|"
    # RASP / runtime self-protection
    r"rasp.detect|anti.rasp|anti_rasp|detected.*rasp|"
    r"runtime.*tamper|runtime.*protect.*detect|protection.*activated|"
    # Hook / injection detection
    r"hook.*detect|inject.*detect|instrumentation.*detect|"
    r"ptrace.*detect|overlay.*detect",
    re.IGNORECASE,
)
_EMULATOR_RE = re.compile(
    r"emulator.detected|virtual.device|not.*real.*device|device.*not.*supported|"
    r"running.*emulator|emulator.*running|not.*physical.*device|physical.*device.*required|"
    r"detected.*emulator|genymotion|bluestacks|nox.*player|memu.*player|"
    r"ro\.product\.model.*sdk|build\.fingerprint.*generic",
    re.IGNORECASE,
)
# Patrones de bloqueo por entorno inseguro: root, integridad, emulador, etc.
# IMPORTANTE: no incluir "frida" ni "debugger" sueltos — nuestros propios
# scripts loguean esas palabras y causarían falsos positivos en security_blocked.
# IMPORTANTE: estos patrones deben indicar BLOQUEO ACTIVO, no meros logs de
# verificación. "security check running" no es bloqueo; "root detected, aborting"
# sí lo es. Preferir patrones con verbo de resultado (detected, blocked, failed,
# aborted) en lugar de sustantivos genéricos (check, verification).
_SECURITY_BLOCK_RE = re.compile(
    # Root / Jailbreak — detección confirmada
    r"rooted.device|root.*detected|device.*rooted|"
    r"superuser.*detected|su.*binary.*found|magisk.*detected|busybox.*detected|"
    # Play Integrity / SafetyNet — fallo de attestation
    r"safetynet.*fail|play.*integrity.*fail|attestation.*fail|ctsprofile.*fail|"
    r"basicintegrity.*false|devicerecognized.*false|"
    # Firma de APK tampered
    r"apk.*tampered|app.*tampered|apk.*modified|"
    # Anti-tampering / Xposed
    r"xposed.*detected|xposed.*framework|hooking.*detected",
    re.IGNORECASE,
)


# ── Resultado ─────────────────────────────────────────────────────────────────

@dataclass
class FridaRunResult:
    """Resultado de una ejecución de Frida con captura de output."""

    iteration: int
    script_js: str                         # contenido JS ejecutado
    output: str                            # stdout completo de frida
    logcat: str                            # logcat filtrado
    hooks_installed: list[str] = field(default_factory=list)
    hooks_failed: list[str] = field(default_factory=list)
    ssl_errors: list[str] = field(default_factory=list)
    app_crashed: bool = False
    anti_frida_detected: bool = False
    emulator_detected: bool = False
    security_blocked: bool = False   # cualquier señal de entorno inseguro
    app_running: bool = False
    success: bool = False
    # bypass_confirmed: el bypass funcionó — app corriendo sin detecciones.
    # app_crashed aquí significa FATAL EXCEPTION / SIGKILL real del paquete objetivo.
    bypass_confirmed: bool = False

    def to_dict(self) -> dict:
        # Extraer líneas relevantes del crash para que el LLM pueda razonar desde evidencia
        crash_lines: list[str] = []
        if self.app_crashed:
            combined = self.output + "\n" + self.logcat
            for line in combined.splitlines():
                if _CRASH_RE.search(line) or "at " in line or "Caused by" in line or "Exception" in line:
                    crash_lines.append(line.strip())
            crash_lines = crash_lines[:40]  # máximo 40 líneas del stack trace

        return {
            "iteration": self.iteration,
            "hooks_installed": self.hooks_installed,
            "hooks_failed": self.hooks_failed,
            "ssl_errors": self.ssl_errors,
            "app_crashed": self.app_crashed,
            "crash_lines": crash_lines,
            "anti_frida_detected": self.anti_frida_detected,
            "success": self.success,
            "output_preview": self.output[:2000] if len(self.output) > 2000 else self.output,
            "logcat_preview": self.logcat[:2000] if len(self.logcat) > 2000 else self.logcat,
            "emulator_detected": self.emulator_detected,
            "security_blocked": self.security_blocked,
            "app_running": self.app_running,
            "app_running_note": (
                "app_running=False without crash means the app likely detected an unsafe environment and exited."
                if not self.app_running and not self.app_crashed else ""
            ),
            "bypass_confirmed": self.bypass_confirmed,
            "bypass_confirmed_note": (
                "BYPASS CONFIRMED: app is running with no active protections detected. "
                "Call report_success IMMEDIATELY."
                if self.bypass_confirmed else
                "Bypass not yet confirmed — protections still active or app not running."
            ),
        }

    def summary(self) -> str:
        parts = []
        if self.success:
            parts.append(t('frida_summary_success'))
        else:
            parts.append(t('frida_summary_fail'))
        if self.hooks_installed:
            parts.append(f"hooks_ok={len(self.hooks_installed)}")
        if self.hooks_failed:
            parts.append(f"hooks_fallidos={len(self.hooks_failed)}: {self.hooks_failed[:3]}")
        if self.ssl_errors:
            parts.append(f"errores_ssl={len(self.ssl_errors)}")
        if self.app_crashed:
            parts.append("app_crashed=True")
        if self.emulator_detected:
            parts.append("emulator_detected=True")
        if self.security_blocked:
            parts.append("security_blocked=True")
        if self.app_running:
            parts.append("app_running=True")
        elif not self.app_crashed:
            parts.append("app_running=False")
        if self.anti_frida_detected:
            parts.append("anti_frida=True")
        return " | ".join(parts)


# ── Verificación de instalación ──────────────────────────────────────────────

def check_app_installed(adb_args: list[str], package: str) -> bool:
    """
    Comprueba si el package está instalado en el dispositivo.
    Usa `pm list packages` para una verificación precisa.
    """
    adb = shutil.which("adb")
    if not adb:
        return False
    try:
        r = subprocess.run(
            adb_args + ["shell", "pm", "list", "packages", package],
            capture_output=True, text=True, timeout=10,
        )
        # pm list packages <filter> devuelve líneas como "package:com.example.app"
        return f"package:{package}" in r.stdout
    except Exception:
        return False


# ── Auto-recovery de emulador (DeadSystemException) ─────────────────────────
# Visto en vivo (job 18, 2026-08-24): el system_server del emulador se murió y
# a partir de ahí TODO spawn de frida fallaba con DeadSystemException -- el
# agente quemó 11 iteraciones de LLM contra un dispositivo muerto y la app
# nunca llegó a levantarse en pantalla. La recuperación real es rebootear el
# emulador (adb kill-server NO alcanza: el problema es el sistema Android de
# adentro, no el daemon adb del host).

_DEAD_SYSTEM_MARKERS = (
    "DeadSystemException",
    "DeadSystemRuntimeException",
    "DeadObjectException",
)


def _looks_like_dead_system(output: str) -> bool:
    """True si el output de frida muestra un system_server muerto."""
    return any(m in output for m in _DEAD_SYSTEM_MARKERS)


def check_device_healthy(adb_args: list[str]) -> bool:
    """True si el system_server está vivo y el boot completó.

    Cualquier excepción/timeout se trata como "no sano" — el caller decide si
    rebootea o aborta."""
    try:
        pid = subprocess.run(
            adb_args + ["shell", "pidof", "system_server"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if not pid:
            return False
        boot = subprocess.run(
            adb_args + ["shell", "getprop", "sys.boot_completed"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        return boot == "1"
    except Exception:
        return False


def reboot_device_and_wait(adb_args: list[str], timeout: float = 180.0) -> bool:
    """Reinicia el dispositivo y espera a que el boot complete (system_server
    vivo de nuevo). True si recuperó, False si agotó el timeout.

    El caller decide a qué dispositivo se aplica esto -- el auto-recovery de
    aipwn solo lo usa con emuladores locales (serial "emulator-*"), nunca con
    un físico sin que el usuario lo pida explícito."""
    try:
        subprocess.run(adb_args + ["reboot"], capture_output=True, timeout=10)
    except Exception:
        return False
    time.sleep(5)  # darle tiempo al apagado antes de esperar el boot
    try:
        subprocess.run(adb_args + ["wait-for-device"], capture_output=True, timeout=timeout)
    except Exception:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline:
        if check_device_healthy(adb_args):
            return True
        time.sleep(3)
    return False


# ── Auto-start del emulador ──────────────────────────────────────────────────

def find_emulator_binary() -> str | None:
    """Localiza el binario ``emulator`` del Android SDK.

    Orden: $ANDROID_HOME, $ANDROID_SDK_ROOT, el default de macOS
    (~/Library/Android/sdk), al lado de un `adb` que venga del SDK, y por
    último PATH. En esta máquina adb viene de Homebrew pero el SDK está en la
    ruta default de macOS, así que hacen falta todas las candidatas."""
    candidates: list[Path] = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        base = os.environ.get(env, "").strip()
        if base:
            candidates.append(Path(base) / "emulator" / "emulator")
    candidates.append(Path.home() / "Library" / "Android" / "sdk" / "emulator" / "emulator")
    adb = shutil.which("adb")
    if adb:
        candidates.append(Path(adb).resolve().parent.parent / "emulator" / "emulator")
    for c in candidates:
        if c.exists():
            return str(c)
    return shutil.which("emulator")


def list_avds(emulator_bin: str) -> list[str]:
    """AVDs disponibles (``emulator -list-avds``)."""
    try:
        r = subprocess.run(
            [emulator_bin, "-list-avds"], capture_output=True, text=True, timeout=15,
        )
        return [line.strip() for line in r.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def any_device_online(adb_bin: str) -> list[str]:
    """Serials de dispositivos en estado ``device`` (online) según adb."""
    try:
        r = subprocess.run([adb_bin, "devices"], capture_output=True, text=True, timeout=10)
        serials = []
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) == 2 and parts[1] == "device":
                serials.append(parts[0])
        return serials
    except Exception:
        return []


def start_emulator_and_wait(
    emulator_bin: str,
    avd: str,
    adb_bin: str,
    timeout: float = 240.0,
) -> str | None:
    """Lanza el AVD en segundo plano (detached -- sobrevive a que aipwn salga)
    y espera a que el boot complete. Devuelve el serial (``emulator-5554``…)
    del emulador ya sano, o None si agotó el timeout."""
    subprocess.Popen(
        [emulator_bin, "-avd", avd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        subprocess.run([adb_bin, "wait-for-device"], capture_output=True, timeout=timeout)
    except Exception:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline:
        serials = [s for s in any_device_online(adb_bin) if s.startswith("emulator-")]
        if serials and check_device_healthy([adb_bin, "-s", serials[0]]):
            return serials[0]
        time.sleep(3)
    return None


# ── Setup frida-server ────────────────────────────────────────────────────────

_DEFAULT_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"


def _resolve_frida_server_path(
    adb_args: list[str],
    shell_fn: "Callable[[str], str] | None" = None,
) -> str:
    """Busca en ``/data/local/tmp/`` un binario ``frida-server-<versión>*``
    que coincida con la versión del cliente Frida instalado en este host --
    un mismatch de versión cliente/server es la causa más común de "conecta
    pero nunca engancha" (confirmado en vivo, 2026-08-21: dispositivo con
    varias versiones guardadas -- ``frida-server`` a secas de una versión
    vieja, y ``frida-server-17.16.4`` exacto al cliente sin usar porque el
    código siempre lanzaba el binario sin sufijo).

    Con match → devuelve esa ruta completa. Sin match (o si algo falla) →
    ``_DEFAULT_FRIDA_SERVER_PATH`` (comportamiento de siempre)."""
    try:
        import frida as _frida
        client_version = _frida.__version__
    except Exception:  # noqa: BLE001
        return _DEFAULT_FRIDA_SERVER_PATH

    # Glob en vez de un nombre exacto -- la convención de sufijo de
    # arquitectura no es consistente entre binarios (algunos tienen
    # "-android-arm64", otros no), así que se toma el primero que matchee.
    ls_cmd = f"ls {_DEFAULT_FRIDA_SERVER_PATH}-{client_version}* 2>/dev/null"
    try:
        if shell_fn is not None:
            out = shell_fn(ls_cmd)
        else:
            r = subprocess.run(adb_args + ["shell", ls_cmd], capture_output=True, text=True, timeout=5)
            out = r.stdout
    except Exception:  # noqa: BLE001
        return _DEFAULT_FRIDA_SERVER_PATH

    match = next((line.strip() for line in out.splitlines() if line.strip()), "")
    if match:
        console.print(f"[dim]  [aipwn] frida-server versionado encontrado: {match} (cliente={client_version})[/dim]")
        return match
    return _DEFAULT_FRIDA_SERVER_PATH


def setup_frida_server(
    adb_args: list[str],
    package: str,
    serial: str | None = None,
    frida_host: str | None = None,
    shell_fn: "Callable[[str], str] | None" = None,
) -> bool:
    """
    Mata frida-server existente, reinicia como root y fuerza el cierre de la app.

    Retorna True si todo fue exitoso, False si adb no está disponible.

    ``shell_fn`` (opcional): callable ``str -> str`` que ejecuta un comando de
    shell en el device y devuelve su stdout, en vez de shellear a un `adb`
    LOCAL vía ``adb_args``. Lo usa ``QueryAgent`` (dashboard/co-piloto) cuando
    el device está conectado por relay WebUSB en vez de USB directo al host
    del dashboard -- en ese caso no hay ningún `adb` local con ruta al
    dispositivo (ver ``DeviceIO`` en plugins/aipwn/query_tools.py y el shim de
    ``toolbox/relay_adb_shim/`` que resuelve el mismo problema para jobs de la
    cola). Con ``shell_fn=None`` (CLI, jobs de la cola) el comportamiento es
    exactamente el de antes -- cero cambios."""
    if shell_fn is not None:
        console.print(f"[dim]  [aipwn] {t('frida_restarting_server')}[/dim]")
        server_path = _resolve_frida_server_path(adb_args, shell_fn=shell_fn)
        shell_fn("su -c 'killall frida-server 2>/dev/null; pkill -f frida-server 2>/dev/null; true'")
        time.sleep(1)
        if frida_host:
            shell_fn(f"su -c 'nohup {server_path} -l 0.0.0.0 > /dev/null 2>&1 &'")
        else:
            shell_fn(f"su -c 'nohup {server_path} > /dev/null 2>&1 &'")
        time.sleep(2)
        shell_fn(f"am force-stop {package}")
        time.sleep(1)
        return True

    adb = shutil.which("adb")
    if not adb:
        console.print(f"[red]{t('frida_error_adb_not_found')}[/red]")
        return False

    console.print(f"[dim]  [aipwn] {t('frida_restarting_server')}[/dim]")
    server_path = _resolve_frida_server_path(adb_args)
    subprocess.run(
        adb_args + ["shell", "su -c 'killall frida-server 2>/dev/null; pkill -f frida-server 2>/dev/null; true'"],
        capture_output=True,
    )
    time.sleep(1)
    if frida_host:
        subprocess.run(
            adb_args + ["shell", f"su -c 'nohup {server_path} -l 0.0.0.0 > /dev/null 2>&1 &'"],
            capture_output=True,
        )
    else:
        subprocess.run(
            adb_args + ["shell", f"su -c 'nohup {server_path} > /dev/null 2>&1 &'"],
            capture_output=True,
        )
    time.sleep(2)
    subprocess.run(
        adb_args + ["shell", f"am force-stop {package}"],
        capture_output=True,
    )
    time.sleep(1)
    return True


# ── Ejecución capturada ───────────────────────────────────────────────────────

def launch_frida_capture(
    package: str,
    script_js: str,
    serial: str | None = None,
    frida_host: str | None = None,
    duration: int = 30,
    iteration: int = 1,
    shell_fn: "Callable[[str], str] | None" = None,
    logcat_fn: "Callable[[float], str] | None" = None,
    _recovery_retried: bool = False,
) -> FridaRunResult:
    """
    Ejecuta Frida con el script JS dado, captura output en tiempo real y
    retorna un FridaRunResult con el análisis del resultado.

    Args:
        package:   Package ID de la app (ej: com.example.app)
        script_js: Contenido del script Frida (.js)
        serial:    Serial ADB del dispositivo (None = USB por defecto)
        frida_host: Host:puerto de frida-server remoto (ej. "192.168.1.10:27042")
        duration:  Segundos de observación antes de matar Frida
        iteration: Número de iteración (para display)
        shell_fn:  callable ``str -> str`` opcional para correr comandos de
                   shell en el device SIN pasar por un `adb` local -- ver
                   ``setup_frida_server``. Reemplaza también la limpieza de
                   logcat (``logcat -c``) y el chequeo final de ``pidof``.
                   ``None`` (default) = comportamiento de siempre (CLI, jobs
                   de la cola), 100% sin cambios.
        logcat_fn: callable ``float (segundos) -> str`` opcional que devuelve
                   el logcat capturado durante esa ventana. Requerido junto
                   con ``shell_fn`` para correlacionar SSL errors/crashes en
                   modo relay -- ahí no hay streaming línea-a-línea real (el
                   RPC de logcat del relay tampoco lo es, ver
                   ``toolbox/relay_adb_shim/adb::_cmd_logcat``), así que se
                   captura la ventana completa en un hilo de fondo en vez de
                   ir línea por línea como en el modo `adb` directo.
    """
    if shell_fn is None:
        adb = shutil.which("adb")
        if not adb:
            console.print(f"[red]{t('frida_error_adb_not_found')}[/red]")
            return FridaRunResult(iteration=iteration, script_js=script_js, output="", logcat="")
        adb_args = [adb] + (["-s", serial] if serial else [])
    else:
        adb_args = []  # no se usa en este modo -- todo pasa por shell_fn/logcat_fn

    frida_bin = str(Path(sys.executable).parent / "frida")
    if not Path(frida_bin).exists():
        frida_bin = shutil.which("frida") or ""
    if not frida_bin:
        console.print(f"[red]{t('frida_error_frida_not_found')}[/red]")
        return FridaRunResult(iteration=iteration, script_js=script_js, output="", logcat="")

    # Escribir script a archivo temporal
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".js",
        prefix=f"nutcracker_aipwn_{package}_",
        delete=False,
    ) as tmp:
        tmp.write(script_js)
        script_path = Path(tmp.name)

    try:
        setup_frida_server(adb_args, package, serial=serial, frida_host=frida_host, shell_fn=shell_fn)

        # Limpiar logcat antes de lanzar Frida para evitar que eventos de runs
        # anteriores (stack traces, crashes, ssl errors) contaminen el análisis.
        if shell_fn is not None:
            shell_fn("logcat -c")
        else:
            subprocess.run(adb_args + ["logcat", "-c"], capture_output=True, timeout=5)

        if frida_host:
            frida_cmd = [frida_bin, "-H", frida_host, "-f", package, "-l", str(script_path)]
        elif serial:
            frida_cmd = [frida_bin, "-D", serial, "-f", package, "-l", str(script_path)]
        else:
            frida_cmd = [frida_bin, "-U", "-f", package, "-l", str(script_path)]

        console.print(f"[dim]  [aipwn] {t('frida_running_cmd', cmd=' '.join(frida_cmd))}[/dim]")

        # frida en sí SIEMPRE corre local (el binario `frida` del host) --
        # con frida_host apunta al túnel TCP crudo del relay (27042, no es el
        # puerto de control de adbd, ver relay.py), que sí funciona sin adb.
        frida_proc = subprocess.Popen(
            frida_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        all_frida_lines: list[str] = []
        all_logcat_lines: list[str] = []
        early_exit_event = threading.Event()

        def stream_frida(proc: subprocess.Popen) -> None:
            for raw in proc.stdout:  # type: ignore[union-attr]
                line = raw.rstrip()
                all_frida_lines.append(line)
                _print_frida_line(line)
            early_exit_event.set()

        t_frida = threading.Thread(target=stream_frida, args=(frida_proc,), daemon=True)
        t_frida.start()

        logcat_proc: subprocess.Popen | None = None
        if shell_fn is not None and logcat_fn is not None:
            # Modo relay: una sola captura acotada en un hilo de fondo (sin
            # streaming línea-a-línea real -- ver docstring de logcat_fn).
            def _capture_logcat_window() -> None:
                text = logcat_fn(float(duration) + 5)
                all_logcat_lines.extend(text.splitlines())

            t_logcat = threading.Thread(target=_capture_logcat_window, daemon=True)
            t_logcat.start()
        else:
            logcat_cmd = adb_args + ["logcat", "-v", "time",
                                      "*:W", "OkHttp:D", "SSL:E", "CONSCRYPT:E"]
            logcat_proc = subprocess.Popen(
                logcat_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            def stream_logcat(proc: subprocess.Popen) -> None:
                for raw in proc.stdout:  # type: ignore[union-attr]
                    line = raw.rstrip()
                    all_logcat_lines.append(line)
                    _print_logcat_line(line)

            t_logcat = threading.Thread(target=stream_logcat, args=(logcat_proc,), daemon=True)
            t_logcat.start()

        # Polling loop: esperar hasta que Frida termine o se agote el tiempo
        elapsed = 0.0
        poll_interval = 1.0
        while elapsed < duration:
            early_exit_event.wait(timeout=poll_interval)
            elapsed += poll_interval

            # Si Frida murió solo (EOF en stdout + proceso terminado), no esperar más
            if early_exit_event.is_set() and frida_proc.poll() is not None:
                console.print(f"[dim]  [aipwn] Early exit: Frida process ended at {elapsed:.0f}s[/dim]")
                break

        # Detach graceful: enviar 'exit' para que la CLI de Frida se desconecte
        # limpiamente (la app sigue corriendo -- no se pasa --kill-on-exit al
        # construir frida_cmd más arriba). FIX (encontrado en vivo, job 2823,
        # frida 17.16.4): el meta-comando viejo "%detach" ya no existe en la
        # REPL moderna ("Unknown command: detach"), y como el error se traga
        # en el except de abajo, el detach terminaba fallando siempre en
        # silencio y cayendo al terminate()/kill() de más abajo -- funcional
        # pero no realmente "graceful". El propio banner de la CLI documenta
        # "exit/quit -> Exit" como el comando real.
        if frida_proc.poll() is None:
            try:
                frida_proc.stdin.write("exit\n")  # type: ignore[union-attr]
                frida_proc.stdin.flush()              # type: ignore[union-attr]
            except Exception:
                pass
            try:
                frida_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                frida_proc.terminate()
                try:
                    frida_proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    frida_proc.kill()
        if logcat_proc is not None:
            logcat_proc.terminate()
        t_frida.join(timeout=3)
        # En modo relay, logcat_fn puede tardar hasta ~duration+5s en volver
        # (es una sola captura bloqueante, no streaming) -- darle margen real
        # en vez del join(timeout=3) fijo del modo adb directo (ese sí es
        # instantáneo porque solo hay que cortar un Popen ya en curso).
        t_logcat.join(timeout=float(duration) + 8 if shell_fn is not None else 3)

    finally:
        script_path.unlink(missing_ok=True)

    output = "\n".join(all_frida_lines)
    logcat = "\n".join(all_logcat_lines)

    # ── Auto-recovery: system_server muerto (DeadSystemException) ──────────
    # Si el spawn falló porque el sistema Android del emulador está caído,
    # rebootear y reintentar el spawn UNA vez (la recursión rehace también el
    # setup de frida-server, que muere con el reboot). Solo emuladores con adb
    # local: en modo relay (shell_fn) un reboot mataría el túnel WebUSB, y un
    # físico nunca se rebootea solo.
    if (
        not _recovery_retried
        and shell_fn is None
        and serial
        and serial.startswith("emulator-")
        and _looks_like_dead_system(output)
    ):
        console.print(f"[yellow][aipwn] {t('aipwn_device_unhealthy')}[/yellow]")
        if reboot_device_and_wait(adb_args):
            console.print(f"[green][aipwn] {t('aipwn_device_recovered')}[/green]")
            return launch_frida_capture(
                package, script_js, serial=serial, frida_host=frida_host,
                duration=duration, iteration=iteration,
                _recovery_retried=True,
            )
        console.print(f"[red][aipwn] {t('aipwn_device_recovery_failed')}[/red]")
        output += f"\n[aipwn] {t('aipwn_device_recovery_failed')}"

    # Comprobar si el proceso del app sigue vivo al finalizar
    app_running = False
    try:
        if shell_fn is not None:
            app_running = bool(shell_fn(f"pidof {package}").strip())
        else:
            r = subprocess.run(
                adb_args + ["shell", "pidof", package],
                capture_output=True, text=True, timeout=5,
            )
            app_running = bool(r.stdout.strip())
    except Exception:
        pass

    return _parse_result(iteration, script_js, output, logcat, app_running=app_running, package=package)


# ── Parseo del output ─────────────────────────────────────────────────────────

def _parse_result(
    iteration: int,
    script_js: str,
    output: str,
    logcat: str,
    app_running: bool = False,
    package: str = "",
) -> FridaRunResult:
    combined = output + "\n" + logcat

    hooks_installed = [
        line for line in output.splitlines() if _HOOK_OK_RE.search(line)
    ]
    hooks_failed = [
        line for line in output.splitlines() if _HOOK_FAIL_RE.search(line)
    ]
    ssl_errors = [
        line for line in combined.splitlines() if _SSL_ERROR_RE.search(line)
    ]
    # app_crashed: solo contar crashes del paquete objetivo.
    # Frida output: buscar crashes definitivos (FATAL EXCEPTION, SIGKILL, SIGSEGV).
    # Logcat: FATAL EXCEPTION no incluye el paquete en la misma línea — aparece en
    # la línea siguiente ("Process: com.example.app, PID: ..."). Se usa ventana de
    # N líneas siguientes para asociar el crash al paquete correcto.
    _crash_lines = [line for line in output.splitlines() if _CRASH_RE.search(line)]
    logcat_lines = logcat.splitlines()
    if package:
        for i, line in enumerate(logcat_lines):
            if not _CRASH_RE.search(line):
                continue
            # La línea con FATAL EXCEPTION/Process crash tiene el paquete en la
            # misma línea O en alguna de las 5 líneas siguientes.
            window = logcat_lines[i:i + 6]
            if any(package in w for w in window):
                _crash_lines.append(line)
    else:
        _crash_lines += [line for line in logcat_lines if _CRASH_RE.search(line)]
    app_crashed = bool(_crash_lines)
    anti_frida = bool(_ANTI_FRIDA_RE.search(combined))
    emulator_detected = bool(_EMULATOR_RE.search(combined))
    # security_blocked se evalúa solo sobre el output de Frida (logs del script),
    # no sobre el logcat completo del sistema. El logcat contiene mensajes de otros
    # procesos y del propio SDK antes de que los hooks tomaran efecto, lo que causa
    # falsos positivos. Si el script hookea exitosamente las protecciones, sus logs
    # se imprimen en stdout de Frida, no en logcat.
    security_blocked = bool(_SECURITY_BLOCK_RE.search(output))

    # Si el proceso murió sin un crash explícito, el app se auto-cerró (detección activa)
    app_exited_silently = not app_running and not app_crashed

    # Un hook que falla por ClassNotFoundException en una clase opcional (SDK de tercero
    # que no existe en esta app) no debe bloquear el éxito.
    # Sólo cuentan como críticos: errores de overload/firma, métodos SSL específicos,
    # o ClassNotFoundException de clases SSL/OkHttp (están en classloader custom pero son reales).
    _OPTIONAL_FAIL_RE = re.compile(r"ClassNotFoundException", re.IGNORECASE)
    _SSL_CRITICAL_RE = re.compile(
        r'okhttp3\.|ssl|certificate|pinner|trustmanager|conscrypt|x509',
        re.IGNORECASE,
    )
    hooks_failed_critical = [
        h for h in hooks_failed
        if not _OPTIONAL_FAIL_RE.search(h) or _SSL_CRITICAL_RE.search(h)
    ]

    # security_blocked es informativo pero NO bloquea success:
    # si el app sigue corriendo con hooks instalados y sin SSL errors, el bypass
    # funcionó. Los mensajes de "security_blocked" pueden ser nuestros propios
    # logs del script o checks que la app registra pero no actúa. El cierre del
    # app (app_exited_silently) ya captura el caso en que la protección expulsa
    # al usuario.
    success = (
        len(hooks_installed) > 0
        and len(hooks_failed_critical) == 0
        and len(ssl_errors) == 0
        and not anti_frida
        and not emulator_detected
        and not app_crashed
        and not app_exited_silently
    )

    # bypass_confirmed: señal definitiva para el agente.
    # app_crashed ya está filtrado al paquete, así que si es True es real.
    # Requiere hooks_installed > 0 para evitar falsos positivos cuando la app
    # corre pero el script no instaló ningún hook (protección activa pero silenciosa).
    bypass_confirmed = (
        app_running
        and len(hooks_installed) > 0
        and not app_crashed
        and not security_blocked
        and not anti_frida
        and not emulator_detected
        and not ssl_errors
        and len(hooks_failed_critical) == 0
    )

    return FridaRunResult(
        iteration=iteration,
        script_js=script_js,
        output=output,
        logcat=logcat,
        hooks_installed=hooks_installed,
        hooks_failed=hooks_failed,
        ssl_errors=ssl_errors,
        app_crashed=app_crashed,
        anti_frida_detected=anti_frida,
        emulator_detected=emulator_detected,
        security_blocked=security_blocked,
        app_running=app_running,
        success=success,
        bypass_confirmed=bypass_confirmed,
    )


# ── Helpers de display ────────────────────────────────────────────────────────

def _print_frida_line(line: str) -> None:
    safe = _escape(line)
    if _HOOK_OK_RE.search(line):
        console.print(f"[green][Frida][/green]   {safe}")
    elif _HOOK_FAIL_RE.search(line):
        console.print(f"[red][Frida][/red]   {safe}")
    elif line.strip():
        console.print(f"[dim][Frida]   {safe}[/dim]")


def _print_logcat_line(line: str) -> None:
    safe = _escape(line)
    if _SSL_ERROR_RE.search(line):
        console.print(f"[red][logcat][/red]  {safe}")
    elif _CRASH_RE.search(line):
        console.print(f"[red][logcat][/red]  {safe}")
    elif _ANTI_FRIDA_RE.search(line):
        console.print(f"[yellow][logcat][/yellow]  {safe}")
    elif line.strip():
        console.print(f"[dim][logcat]  {safe}[/dim]")
