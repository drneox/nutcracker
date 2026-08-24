"""query_agent.py — Co-piloto interactivo de pentest.

A diferencia de ``FridaAgent`` (frida_agent.py, bypass autónomo con un
objetivo fijo y presupuesto estricto de iteraciones/runs de Frida), este
agente es **conversacional**: responde a mensajes del operador uno por uno,
puede usar tanto las tools estáticas (findings, componentes, secretos,
decompilado) como las dinámicas (Frida, screenshot, interacción de UI vía
ADB/relay), y no persigue una conclusión propia -- cada turno termina cuando
el LLM responde sin más tool_calls, esperando el próximo mensaje humano.

Funciona sin dispositivo (modo estático puro, ``device=None``) y sin ningún
job ``aipwn`` corriendo -- ver ``query_tools.py``.

Si hubo corridas autónomas previas de ``nutcracker aipwn`` para el mismo
paquete, la conversación arranca con un mensaje semilla (handoff): el
resumen de sesiones de ``agent_memory`` y el último script de bypass
generado, para que el operador pueda pedir "afina el bypass" sin empezar
de cero -- ver ``_build_handoff_context``.

Handoff vivo: si la corrida autónoma terminó SIN conclusión (límite de
iteraciones, LLM cortado) y el operador pidió continuar (``--interactive``
en la CLI, o el dashboard cargando el ``resume_state`` pendiente), el
agente recibe la conversación REAL de esa corrida (``resume_messages``) en
vez de la semilla -- ver ``run_interactive_cli`` y ``dashboard/ws.py``."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from rich.console import Console
from rich.markup import escape as _escape

from .frida_agent import LLMClient, _screenshot_image_message, _tool_result_message
from .frida_agent_tools import ToolContext
from .query_tools import QUERY_TOOL_SCHEMAS, DeviceIO, dispatch_query_tool

if TYPE_CHECKING:
    from nutcracker_core.analyzer import AnalysisResult

console = Console()


_QUERY_SYSTEM_PROMPT = """\
You are an interactive pentesting co-pilot embedded in nutcracker's dashboard, \
helping a human security operator explore package `{package}`.

You have two kinds of tools:

**Static/reports** (always available, no device needed): list_findings, \
get_finding_detail, list_components, list_secrets, get_exploit_results, \
read_decompiled_class, search_in_decompiled, list_classes_matching, \
get_certificate_pins, get_app_analysis, strings_native_lib, \
disassemble_native_lib, get_apk_signature.

**Queue** (dashboard chat only): enqueue_scan (start a NEW static or aipwn run \
for this or another package, right away) and get_job_status (check progress of \
a queued/running job). When the operator asks to (re)run a scan, enqueue it \
and report the job id -- do NOT tell them to go use the CLI instead.

**Dynamic** (require a connected device -- serial USB or a WebUSB relay \
session, set up by the operator before or during this chat): \
take_screenshot, get_logcat, ui_tap, ui_input_text, ui_swipe, ui_press_key, \
run_frida_script, enumerate_runtime_classes, get_class_methods, \
get_loaded_native_libs, enumerate_native_exports, resolve_native_symbol, \
probe_security_violations, sniff_network_calls, capture_traffic, \
intercept_and_modify, setup_mitm_proxy, teardown_mitm_proxy, \
trace_method_execution, get_frida_output_history.

**Traffic interception -- pick the right layer for what the operator asked:**
- `sniff_network_calls`: quick Java-only check (method+URL+code). Fine for a \
fast look at a normal Android app, but sees NOTHING in Flutter/React-Native \
apps (they don't use the Java OkHttp stack) -- don't waste a turn on it if \
you already know the app is Flutter/RN, go straight to `capture_traffic`.
- `capture_traffic`: full passive capture (headers+body) at BOTH the Java \
layer AND the native TLS layer (SSL_write/SSL_read on libssl/boringssl/ \
libflutter/libcrypto) -- this is what actually works for Flutter/RN/native \
apps, and gives more detail than sniff_network_calls even for plain Java \
apps. Default choice when the operator asks "what does this app send" / \
"where does login go" / anything traffic-related, unless they specifically \
want the quick Java-only check.
- `intercept_and_modify`: same two layers, but ACTIVE -- can block a request, \
or rewrite a request/response body/header while the app runs. Use when the \
operator wants to tamper with what's sent/received, not just observe. \
IMPORTANT to communicate: replacing a *response* at the native layer can only \
rewrite up to the ORIGINAL buffer length (can't grow it) -- if a longer \
replacement gets truncated, tell the operator and suggest the Java/OkHttp \
layer instead (no such limit there).
- `setup_mitm_proxy`/`teardown_mitm_proxy`: when the operator wants to see/ \
edit EVERYTHING with a real proxy UI (Burp/mitmproxy), not just what you log \
here. Installs the CA (device must be rooted), sets the device's proxy, and \
runs the pinning bypass. Tell the operator upfront: the device must reach \
the proxy over its OWN network (same LAN) -- this does NOT go through the \
relay tunnel, so it won't work if the device has no route to wherever the \
proxy is running.

If the operator asks about your underlying mechanism (e.g. "do you have adb \
integrated?", "can you run adb shell?", "can you run logcat?"): you do NOT \
expose a raw/arbitrary shell tool, but under the hood several tools ARE the \
equivalent adb command: take_screenshot = `adb exec-out screencap`, \
get_logcat = `adb logcat` (clears the buffer first, captures a bounded \
window you choose), and ui_tap/ui_input_text/ui_swipe/ui_press_key are each \
`adb shell input ...` (tap/text/swipe/keyevent) -- routed either over a \
direct USB serial or through the WebUSB relay tunnel, transparently, \
whichever this session is using. Answer that precisely instead of just \
saying "no, I don't have adb" -- that undersells what these tools already \
do. What you genuinely cannot do is run an ARBITRARY shell command outside \
of those specific actions (e.g. no `pm list packages`, no `cat /data/...`, \
no `ps`) -- only run_frida_script gives you arbitrary code execution, via \
JavaScript in the target process, not a device shell.

How to work:
- This is a CONVERSATION, not an autonomous mission. Do what the operator \
asks, one request at a time. After answering (with or without tool calls), \
STOP and wait for their next message -- do not keep chaining actions on your \
own initiative beyond what was asked.
- If the operator asks "do you see this screen?" or asks you to interact \
with the UI (tap, type, navigate), call take_screenshot FIRST if you haven't \
seen the current screen recently, describe what you see, then act with \
ui_tap/ui_input_text/ui_swipe/ui_press_key as needed, and take another \
screenshot to confirm the result. Always give feedback about what you did \
and what you observed.
- If a dynamic tool fails because there is no device connected, tell the \
operator plainly (don't retry blindly) and suggest connecting one (serial or \
relay) instead of silently switching to static-only analysis.
- If a device-mutating tool (Frida attach, UI input, traffic interception) is \
rejected because an autonomous aipwn job is running on this package, do NOT \
retry it or try sibling tools with the same effect: the job owns the device \
until it finishes. Tell the operator, and offer static tools or read-only \
ones (take_screenshot, get_logcat) meanwhile.
- Ground your answers in real data from the tools -- don't speculate about \
findings/secrets/components without calling the corresponding tool first.
- When asked to run a Frida script, confirm briefly what it will hook before \
running it if the action is invasive (e.g. patching checks, killing the \
process) -- this operator can undo very little once a script runs.
- When writing a run_frida_script script: NEVER use the static, two-argument \
`Module.findExportByName(lib, sym)` or `Module.getExportByName(lib, sym)` -- \
REMOVED in Frida 17, throws "TypeError: not a function" immediately (this is \
the single most common cause of your own scripts crashing, confirmed live). \
Use `Module.findGlobalExportByName(sym)` for a global search, or \
`Process.findModuleByName(lib)` (null if not loaded) then `.findExportByName(sym)` \
on that module object for a specific library -- both return null instead of \
throwing when the symbol/module isn't found.
- Your goal is to help the operator find NEW vulnerabilities by combining \
what's already known (findings, aipwn results) with live exploration -- \
suggest concrete next steps when it's useful, but keep control with the \
operator.
"""


@dataclass
class QueryEvent:
    kind: str  # "tool" | "tool_result" | "image" | "assistant" | "error"
    data: dict[str, Any]


_MAX_HANDOFF_SCRIPT_CHARS = 8_000

# Nota que se agrega al system prompt cuando el co-piloto hereda la
# conversación REAL de una corrida autónoma (handoff vivo) -- sin esto el
# LLM seguiría comportándose como agente autónomo porque el historial viene
# con ese tono.
_HANDOFF_SYSTEM_NOTE = """

IMPORTANT -- live handoff: the conversation that follows this system message \
was an AUTONOMOUS aipwn bypass run that ended WITHOUT a definitive conclusion \
(iteration limit reached or the LLM stopped calling tools). The human operator \
has now taken over interactively. From this point on you are in conversational \
co-pilot mode: respond to the operator one message at a time and do NOT keep \
chaining actions toward the old goal on your own. Some tools the autonomous \
agent used no longer exist in this mode (e.g. report_success/report_failure, \
get_heuristic_bypass_script) -- use the tools listed above, and if you need an \
effect they provided, explain it to the operator instead."""


def _build_handoff_context(package: str, scripts_dir: Path = Path("frida_scripts")) -> str:
    """Construye el mensaje semilla con lo que dejaron las corridas autónomas
    previas de ``nutcracker aipwn`` para este paquete: el resumen de sesiones
    de ``agent_memory`` (qué hooks funcionaron/fallaron) y el último script
    de bypass generado (truncado a ~8 KB). Retorna '' si no hay nada previo
    -- la conversación arranca entonces sin semilla, como siempre.

    Import perezoso de ``.aipwn`` (orquestador CLI) para no pagar frida_capture
    al cargar este módulo -- mismo patrón que ``_execute_frida``."""
    from .agent_memory import build_memory_context, load_sessions
    from .aipwn import _find_latest_script

    parts: list[str] = []
    mem = build_memory_context(load_sessions(package))
    if mem:
        parts.append(
            "[SYSTEM] Context from previous autonomous aipwn sessions for this "
            "package -- build on it, do not restart from scratch:"
        )
        parts.append(mem)

    script = _find_latest_script(package, scripts_dir)
    if script is not None:
        try:
            content = script.read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = ""
        if content:
            parts.append(
                f"\n[SYSTEM] Latest bypass script from those sessions: {script} "
                f"(use it as the starting point if the operator asks to refine "
                f"the bypass; truncated to {_MAX_HANDOFF_SCRIPT_CHARS} chars):\n"
                f"```javascript\n{content[:_MAX_HANDOFF_SCRIPT_CHARS]}\n```"
            )

    return "\n".join(parts)


class QueryAgent:
    """Una instancia = una conversación (vive lo que dura la conexión
    WebSocket, ver ``dashboard/ws.py::ws_query``)."""

    def __init__(
        self,
        package: str,
        decompiled_dir: Path | None,
        runtime_dump_dir: Path | None,
        analysis_result: "AnalysisResult | None",
        llm_config: dict,
        db_path: str,
        serial: str | None = None,
        frida_host: str | None = None,
        device: "DeviceIO | None" = None,
        capture_seconds: int = 15,
        resume_messages: list[dict] | None = None,
        enqueue_fn=None,
    ) -> None:
        self.package = package
        self.db_path = db_path
        self.device = device
        # Callback para encolar jobs (enqueue_scan) -- la inyecta el dashboard
        # (ws.py); None en la CLI interactiva, donde la tool avisa que no aplica.
        self.enqueue_fn = enqueue_fn
        self.llm = LLMClient(llm_config)
        self.frida_runs_used = 0

        # En modo relay no hay ningún `adb` local con ruta al device (solo el
        # navegador la tiene) -- device_shell/device_logcat le dan a las tools
        # dinámicas (launch_frida_capture, _run_frida_spawngated, ver
        # frida_agent_tools.py::ToolContext) un canal real (DeviceIO -> RPC
        # del relay) en vez de fallar shelleando a un adb sin ruta al device
        # (ver query_tools.py::_check_device_ready). None en serial/sin
        # device -- comportamiento de siempre.
        device_shell = None
        device_logcat = None
        if device is not None and device.is_relay:
            device_shell = device.shell
            device_logcat = lambda duration: device.logcat(duration_seconds=duration)  # noqa: E731

        self.ctx = ToolContext(
            package=package,
            decompiled_dir=decompiled_dir,
            analysis_result=analysis_result,
            serial=serial,
            frida_host=frida_host,
            capture_seconds=capture_seconds,
            scripts_dir=Path(tempfile.gettempdir()) / "nutcracker_query_scripts",
            on_frida_run=self._execute_frida,
            runtime_dump_dir=runtime_dump_dir,
            device_shell=device_shell,
            device_logcat=device_logcat,
        )

        if resume_messages:
            # ── Handoff vivo: heredar la conversación REAL de una corrida
            # autónoma que quedó sin conclusión (no solo el resumen de
            # agent_memory, que es lo que hace _build_handoff_context). Se
            # reemplaza el system prompt autónomo por el del co-piloto +
            # nota de handoff: desde acá el agente responde al operador
            # turno a turno en vez de perseguir el objetivo solo.
            self.messages = list(resume_messages)
            _prompt = _QUERY_SYSTEM_PROMPT.format(package=package) + _HANDOFF_SYSTEM_NOTE
            if self.messages and self.messages[0].get("role") == "system":
                self.messages[0] = {"role": "system", "content": _prompt}
            else:
                self.messages.insert(0, {"role": "system", "content": _prompt})
        else:
            self.messages = [
                {"role": "system", "content": _QUERY_SYSTEM_PROMPT.format(package=package)},
            ]

            # ── Handoff desde corridas autónomas previas ─────────────────────
            _handoff = _build_handoff_context(package)
            if _handoff:
                self.messages.append({"role": "user", "content": _handoff})

        # Rich interpreta CUALQUIER "[algo]" como un tag de estilo y lo
        # descarta en silencio si no reconoce el nombre -- confirmado en vivo
        # que esto pasa incluso con el patrón "[aipwn]" ya usado en el resto
        # del proyecto (frida_agent.py/frida_capture.py). Para que el prefijo
        # de log SÍ se vea, hay que escaparlo -- precomputado acá para no
        # repetir el escape en cada print de ask().
        self._log_prefix = _escape(f"[query:{package}]")

    def _execute_frida(self, script_js: str, rationale: str, iteration: int):
        from .frida_capture import launch_frida_capture

        self.frida_runs_used += 1

        return launch_frida_capture(
            package=self.package,
            script_js=script_js,
            serial=self.ctx.serial,
            frida_host=self.ctx.frida_host,
            duration=self.ctx.capture_seconds,
            iteration=self.frida_runs_used,
            shell_fn=self.ctx.device_shell,
            logcat_fn=self.ctx.device_logcat,
        )

    def _prune_messages(self, max_chars: int = 60_000) -> None:
        """Recorta resultados de tools viejos si el historial crece demasiado
        -- mismo criterio que ``FridaAgent._prune_messages``, simplificado
        (acá no hay presión de presupuesto, solo evitar prompts gigantes en
        conversaciones largas)."""
        total = sum(len(str(m.get("content") or "")) for m in self.messages)
        if total <= max_chars:
            return
        protected = {0, len(self.messages) - 1, len(self.messages) - 2}
        for i, msg in enumerate(self.messages):
            if total <= max_chars:
                break
            if i in protected:
                continue
            if msg.get("role") == "tool" and isinstance(msg.get("content"), str):
                original_len = len(msg["content"])
                msg["content"] = msg["content"][:300] + "\n[... truncated to save context ...]"
                total -= original_len - len(msg["content"])

    def ask(self, user_message: str, max_steps: int = 15) -> Iterator[QueryEvent]:
        """Procesa un mensaje del operador. Genera eventos a medida que el
        agente actúa (tool/tool_result/image) y termina con un evento
        ``assistant`` (o ``error``) cuando el LLM responde sin más
        tool_calls -- ese es el fin del turno, se espera el próximo mensaje.

        Cada paso también se imprime por consola (``console.print``) -- el
        WebSocket es el único canal que ve el operador en el navegador, pero
        stdout de ESTE proceso es lo único inspeccionable desde afuera (logs,
        `tail`, etc.) sin depender de que alguien pegue la conversación a
        mano. Ver plan.md, hallazgo 2026-08-21: antes `ask()` no imprimía
        nada -- ni siquiera controlando el proceso había forma de ver la
        conversación sin el pegado manual del operador."""
        console.print(f"[bold magenta]{self._log_prefix}[/bold magenta] operador: {_escape(user_message)}")
        self.messages.append({"role": "user", "content": user_message})

        step = 0
        while True:
            step += 1
            if step > max_steps:
                msg = f"Se alcanzó el límite de {max_steps} pasos para esta respuesta -- pedime que continúe si hace falta."
                console.print(f"[yellow]{self._log_prefix}[/yellow] {msg}")
                yield QueryEvent("error", {"text": msg})
                return

            self._prune_messages()

            try:
                response = self.llm.chat(self.messages, tools=QUERY_TOOL_SCHEMAS)
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]{self._log_prefix}[/red] error del LLM: {exc}")
                yield QueryEvent("error", {"text": f"Error del LLM: {exc}"})
                return

            self.messages.append(response.raw_message)

            if response.content:
                console.print(f"[bold cyan]{self._log_prefix}[/bold cyan] agente: {_escape(response.content)}")
                yield QueryEvent("assistant", {"text": response.content, "thinking": response.thinking})

            if not response.tool_calls:
                return

            for tc in response.tool_calls:
                console.print(f"[cyan]{self._log_prefix}[/cyan] → {tc.name}({_escape(str(tc.arguments))})")
                yield QueryEvent("tool", {"name": tc.name, "arguments": tc.arguments})

                result = dispatch_query_tool(
                    self.ctx, tc.name, tc.arguments,
                    db_path=self.db_path, device=self.device,
                    frida_iteration=self.frida_runs_used + 1,
                    enqueue_fn=self.enqueue_fn,
                )
                self.messages.append(_tool_result_message(tc, result))
                console.print(f"[dim]{self._log_prefix}   ↳ {_escape(result[:500])}[/dim]")
                yield QueryEvent("tool_result", {"name": tc.name, "result": result[:2000]})

                if tc.name == "take_screenshot":
                    img_msg = _screenshot_image_message(result, self.llm.provider)
                    if img_msg:
                        self.messages.append(img_msg)
                        try:
                            payload = json.loads(result)
                        except json.JSONDecodeError:
                            payload = {}
                        if payload.get("screenshot_b64"):
                            yield QueryEvent("image", {
                                "b64": payload["screenshot_b64"],
                                "format": payload.get("img_format", "jpeg"),
                            })

            # Sigue el loop: la próxima llamada al LLM ve los resultados de
            # las tools y puede responder texto final o encadenar más tools.
            # las tools y puede responder texto final o encadenar más tools.


def run_interactive_cli(agent: QueryAgent) -> None:
    """Loop REPL de terminal para el handoff vivo post-aipwn (flag
    ``--interactive``): el operador conversa con el co-piloto que heredó la
    conversación real de la corrida autónoma inconclusa.

    No imprime eventos por su cuenta: ``ask()`` ya imprime cada paso por
    consola (operador/agente/tools) -- acá solo hay que consumir el
    generador para que el turno corra completo. Termina con "exit"/"salir",
    Ctrl+C o Ctrl+D."""
    console.print(
        "[bold green]Modo interactivo[/bold green] -- la corrida autónoma quedó "
        "sin conclusión y el co-piloto heredó la conversación completa.\n"
        "[dim]Podés pedirle que afine el bypass, pruebe otra variante o explique "
        "qué intentó. Escribí 'exit' para salir.[/dim]"
    )
    while True:
        try:
            user_message = console.input("\n[bold green]you> [/bold green]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]fin de la sesión interactiva.[/dim]")
            break
        if not user_message:
            continue
        if user_message.lower() in {"exit", "quit", "salir"}:
            console.print("[dim]fin de la sesión interactiva.[/dim]")
            break
        for _event in agent.ask(user_message):
            pass
