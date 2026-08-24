"""query_tools.py — Catálogo de herramientas del co-piloto de consulta
(query_agent.py::QueryAgent).

Combina tres grupos, todos invocables por el LLM vía function-calling:

  1. Reusadas de ``frida_agent_tools.py`` tal cual (estáticas de disco +
     runtime de introspección/acción) -- ver ``_REUSED_TOOL_NAMES`` abajo.
  2. Nuevas de consulta sobre el store/reportes ya generados (findings,
     componentes del manifest, secretos, resultados de aipwn) -- funcionan
     sin ningún job corriendo ni dispositivo conectado.
  3. Nuevas de interacción de UI + captura de pantalla, a través de
     :class:`DeviceIO` -- abstrae el transporte (serial USB directo al host,
     o relay WebUSB del navegador) para que el resto del código no sepa cuál
     de los dos está en uso.

Deliberadamente EXCLUIDAS (ver plan): ``patch_native_lib``,
``relaunch_with_gadget`` (reinstalan/parchean el APK) y las de terminación
autónoma ``report_success``/``report_failure`` (este agente es interactivo,
no persigue un bypass solo -- termina cada turno esperando al operador).
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
from typing import Any

from . import frida_agent_tools as _aipwn_tools
from .frida_agent_tools import ToolContext, dispatch_tool as _aipwn_dispatch_tool

# ── Transporte de dispositivo: serial USB directo, o relay WebUSB ───────────

class DeviceIO:
    """Abstrae cómo se llega al dispositivo para operaciones fuera de Frida
    (screencap, ``input`` de UI): por ``adb`` local directo (serial) o por los
    RPCs del relay WebUSB (``relay_manager``, ver ``dashboard/relay.py``)
    cuando el celular está en el navegador del operador en vez de pinchado al
    host del dashboard (caso VPS).

    ``relay_session``/``loop`` solo se usan en modo relay: el agente corre en
    un hilo de threadpool (ver ``ws.py``), así que las corrutinas de
    ``RelaySession.rpc`` se despachan al event loop real vía
    ``asyncio.run_coroutine_threadsafe`` y se esperan de forma síncrona acá.
    """

    def __init__(
        self,
        serial: str | None = None,
        relay_session: Any = None,
        loop: Any = None,
    ) -> None:
        self.serial = serial
        self.relay_session = relay_session
        self._loop = loop

    @property
    def is_relay(self) -> bool:
        return self.relay_session is not None

    def screencap(self, timeout: float = 30.0) -> bytes:
        if self.is_relay:
            data_b64 = self._relay_rpc("screencap", timeout=timeout).get("data_b64", "")
            return base64.b64decode(data_b64) if data_b64 else b""
        import subprocess
        adb_cmd = ["adb"] + (["-s", self.serial] if self.serial else []) + ["exec-out", "screencap", "-p"]
        result = subprocess.run(adb_cmd, capture_output=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else b""

    def shell(self, command: str, timeout: float = 30.0) -> str:
        if self.is_relay:
            result = self._relay_rpc("shell", command=command, timeout=timeout)
            return result.get("stdout", "")
        import subprocess
        adb_cmd = ["adb"] + (["-s", self.serial] if self.serial else []) + ["shell", command]
        result = subprocess.run(adb_cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout

    def logcat(self, args: list[str] | None = None, duration_seconds: float = 15.0) -> str:
        """``adb logcat`` nunca termina solo -- a diferencia de ``shell()``,
        acá el timeout es esperado (se corta el comando después de
        ``duration_seconds`` y se devuelve lo que se haya capturado hasta
        ese momento), no un error. Usado para correlacionar SSL errors/
        crashes con una corrida de Frida (ver ``frida_capture.py::
        launch_frida_capture``, parámetro ``logcat_fn``)."""
        args = args or []
        if self.is_relay:
            result = self._relay_rpc(
                "logcat", timeout=duration_seconds + 10,
                args=args, duration_seconds=duration_seconds,
            )
            return result.get("stdout", "")
        import subprocess
        adb_cmd = ["adb"] + (["-s", self.serial] if self.serial else []) + ["logcat"] + args
        try:
            proc = subprocess.Popen(adb_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except (OSError, FileNotFoundError):
            return ""
        try:
            stdout, _ = proc.communicate(timeout=duration_seconds)
            return stdout or ""
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                stdout, _ = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
            return stdout or ""

    def _relay_rpc(self, op: str, timeout: float = 30.0, **fields) -> dict:
        import asyncio
        if self._loop is None:
            raise RuntimeError("DeviceIO en modo relay requiere el event loop del WebSocket")
        future = asyncio.run_coroutine_threadsafe(
            self.relay_session.rpc(op, timeout=timeout, **fields), self._loop,
        )
        return future.result(timeout=timeout + 5)


# ── Tools reusadas de frida_agent_tools.py sin modificar ────────────────────
# "take_screenshot" NO está acá -- se reemplaza por la versión de este módulo
# (más abajo) que usa DeviceIO en vez de adb directo, para soportar relay.

_REUSED_TOOL_NAMES: frozenset[str] = frozenset({
    # Estáticas -- leen decompiled_dir/runtime_dump_dir o el APK en disco,
    # no requieren dispositivo ni Frida.
    "read_decompiled_class",
    "search_in_decompiled",
    "list_classes_matching",
    "get_certificate_pins",
    "get_app_analysis",
    "strings_native_lib",
    "disassemble_native_lib",
    "get_apk_signature",
    # Runtime -- requieren dispositivo + Frida, pero solo introspección/acción
    # ya existente (no reinstalan el APK).
    "enumerate_runtime_classes",
    "get_class_methods",
    "get_loaded_native_libs",
    "enumerate_native_exports",
    "resolve_native_symbol",
    "probe_security_violations",
    "sniff_network_calls",
    "capture_traffic",
    "intercept_and_modify",
    "trace_method_execution",
    "run_frida_script",
    "get_frida_output_history",
})

# Subconjunto de _REUSED_TOOL_NAMES (+ las nuevas de UI/pantalla, ver abajo)
# que de verdad requieren un dispositivo -- usado por _check_device_ready para
# el preflight uniforme. "get_frida_output_history" queda AFUERA a propósito:
# lee ctx.frida_run_history en memoria, no toca adb/Frida.
_RUNTIME_DEVICE_TOOL_NAMES: frozenset[str] = frozenset({
    "enumerate_runtime_classes", "get_class_methods", "get_loaded_native_libs",
    "enumerate_native_exports", "resolve_native_symbol", "probe_security_violations",
    "sniff_network_calls", "capture_traffic", "intercept_and_modify",
    "trace_method_execution", "run_frida_script",
    "take_screenshot", "get_logcat", "ui_tap", "ui_input_text", "ui_swipe", "ui_press_key",
    "setup_mitm_proxy", "teardown_mitm_proxy",
})


# Tools dinámicas que SÍ saben usar el device conectado por relay (nunca
# shellean a un `adb` local): las de UI/pantalla propias (siempre via
# DeviceIO) y TODAS las runtime reusadas de frida_agent_tools.py --
# ver _run_frida_query (frida_host salta el gate de adb, nunca lo usó
# realmente) y ToolContext.device_shell/device_logcat (usado por
# _run_frida_spawngated y launch_frida_capture) para el detalle de cada
# camino. Separado como set explícito (en vez de "todo lo que está en
# _RUNTIME_DEVICE_TOOL_NAMES") a propósito: si se agrega una tool dinámica
# nueva más adelante sin adaptarla a relay, este chequeo la sigue
# rechazando con un mensaje claro en vez de dejarla pasar por descuido.
_OWN_DEVICE_TOOL_NAMES: frozenset[str] = frozenset({
    "take_screenshot", "get_logcat", "ui_tap", "ui_input_text", "ui_swipe", "ui_press_key",
    "setup_mitm_proxy", "teardown_mitm_proxy",
})
_RELAY_READY_REUSED_TOOL_NAMES: frozenset[str] = frozenset({
    "run_frida_script", "enumerate_runtime_classes", "get_class_methods",
    "get_loaded_native_libs", "enumerate_native_exports", "resolve_native_symbol",
    "probe_security_violations", "sniff_network_calls", "trace_method_execution",
    "capture_traffic", "intercept_and_modify",
})


def _check_device_ready(ctx: ToolContext, device: "DeviceIO | None", name: str) -> str | None:
    """Preflight uniforme antes de CUALQUIER tool dinámica -- evita que cada
    una falle a su manera propia y le dé al LLM señales inconsistentes para
    la misma causa raíz (visto en vivo: ``sniff_network_calls`` entierra
    "ERROR: adb no encontrado" en texto crudo, ``run_frida_script`` devuelve
    ``app_running: false`` con una nota que ni menciona adb -- sugiriendo
    falsamente detección anti-Frida --, y ``enumerate_runtime_classes`` lo
    envuelve en "no se pudo parsear la respuesta de Frida". El LLM no podía
    reconocer que las tres eran el mismo problema y seguía reintentando
    herramientas distintas a ciegas, quemando turnos del operador).

    Devuelve el mensaje de error si algo falta, o ``None`` si el pipeline de
    dispositivo está listo para intentar la llamada real."""
    if device is None and ctx.serial is None and ctx.frida_host is None:
        return (
            "no hay ningún dispositivo conectado a esta sesión de chat (ni serial ni "
            "relay) -- avisale al operador y esperá a que conecte uno antes de "
            "reintentar cualquier herramienta dinámica."
        )
    if device is not None and device.is_relay:
        # En relay, ni "adb instalado" ni "hay serial" dicen nada -- lo único
        # que importa es si ESTA tool en particular sabe hablarle al device
        # por el túnel (ver los dos sets de arriba). El resto NO tiene sentido
        # reintentarlas por otra vía -- fallarían todas por el mismo motivo
        # estructural (adb local sin ruta al device tunelizado).
        if name in _OWN_DEVICE_TOOL_NAMES or name in _RELAY_READY_REUSED_TOOL_NAMES:
            return None
        # No debería llegar acá con el catálogo actual (todas las tools
        # dinámicas ya están adaptadas a relay) -- red de seguridad por si se
        # agrega una tool nueva sin adaptarla.
        return (
            f"'{name}' todavía no soporta el modo relay -- solo funciona con un "
            "dispositivo conectado por serial USB directo al host del dashboard."
        )
    import shutil
    if shutil.which("adb") is None:
        return (
            "el host del dashboard no tiene el binario `adb` instalado/en PATH -- "
            "ninguna herramienta dinámica (Frida/ADB) puede funcionar hasta que se "
            "instale, sin importar el dispositivo conectado. No tiene sentido "
            "reintentar otras herramientas dinámicas por este mismo motivo."
        )
    return None


_reused_schemas = [
    s for s in _aipwn_tools.TOOL_SCHEMAS
    if s["function"]["name"] in _REUSED_TOOL_NAMES
]


# ── Schemas nuevos: consulta sobre store/reportes ────────────────────────────

_QUERY_TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "list_findings",
            "description": (
                "List findings from the latest static analysis run for this package, "
                "stored in the nutcracker database. Each finding has rule_id, title, "
                "severity, category, MASVS/MASWE/CWE ids, file, line, and (when available) "
                "description/recommendation. Optionally filter by severity or category."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "Filter by exact severity: critical, high, medium, low, or info. Empty = no filter.",
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by substring match on the OWASP category (e.g. 'M1', 'Credenciales'). Empty = no filter.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_finding_detail",
            "description": (
                "Get full detail of one finding by rule_id (and optionally file/line to "
                "disambiguate when a rule fires more than once), including the aireview "
                "verdict (TRUE_POSITIVE / FALSE_POSITIVE / unreviewed) when available."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "Rule id, e.g. HC002"},
                    "file": {"type": "string", "description": "Optional: file path to disambiguate"},
                    "line": {"type": "integer", "description": "Optional: line number to disambiguate"},
                },
                "required": ["rule_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_components",
            "description": (
                "Parse the decoded AndroidManifest.xml and list exported activities, "
                "services, receivers and content providers (reversing/attack-surface "
                "targets), dangerous permissions, and app-level flags (debuggable, "
                "allowBackup, cleartextTraffic, target/min SDK)."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_secrets",
            "description": (
                "List hardcoded secrets/credentials found by static analysis (regex rules, "
                "apkleaks, gitleaks, and strings.xml/manifest scanning), each with its "
                "location and validity status: aireview verdict (real vs false positive) "
                "and whether aipwn confirmed it dynamically with a real PoC."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_exploit_results",
            "description": (
                "Get the aipwn exploitation report for this package: findings confirmed "
                "with a real PoC (poc_command/poc_frida, evidence, impact) vs unverifiable "
                "ones, from the most recent aipwn run."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "take_screenshot",
            "description": (
                "Capture the current device screen (via the device connection of this "
                "session -- serial USB or relay) and send it to you as an image so you can "
                "see what's on screen. Use this whenever the operator asks 'do you see this "
                "screen' or before/after acting on the UI."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_logcat",
            "description": (
                "Capture a window of `adb logcat` from the connected device right now, "
                "without writing a Frida script -- routed over the device connection of "
                "this session (serial USB or relay), same as take_screenshot/ui_*. The "
                "buffer is cleared first, so you only see events that happen DURING the "
                "capture window -- ask the operator to reproduce the behavior (open a "
                "screen, tap a button) while this runs if you need to correlate it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "duration_seconds": {
                        "type": "integer",
                        "description": "How long to capture, in seconds (default 10)",
                    },
                    "filter_spec": {
                        "type": "string",
                        "description": (
                            "Optional logcat filter spec, e.g. '*:W OkHttp:D SSL:E' "
                            "(default: all levels/tags)"
                        ),
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ui_tap",
            "description": "Tap the screen at pixel coordinates (x, y), e.g. to tap a text field or button.",
            "parameters": {
                "type": "object",
                "properties": {
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                },
                "required": ["x", "y"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ui_input_text",
            "description": (
                "Type text into the currently focused input field (tap it first with ui_tap "
                "if needed). Use this to enter a username, password, or any other text."
            ),
            "parameters": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ui_swipe",
            "description": "Swipe from (x1, y1) to (x2, y2), e.g. to scroll a list or dismiss a screen.",
            "parameters": {
                "type": "object",
                "properties": {
                    "x1": {"type": "integer"}, "y1": {"type": "integer"},
                    "x2": {"type": "integer"}, "y2": {"type": "integer"},
                    "duration_ms": {"type": "integer", "description": "Swipe duration in ms (default 300)"},
                },
                "required": ["x1", "y1", "x2", "y2"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ui_press_key",
            "description": (
                "Press a hardware/software key, e.g. BACK, HOME, ENTER, or a numeric Android "
                "keycode. Common names: BACK, HOME, ENTER, DEL, TAB, APP_SWITCH."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "keycode": {"type": "string", "description": "e.g. 'BACK', 'ENTER', or a numeric keycode like '66'"},
                },
                "required": ["keycode"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "setup_mitm_proxy",
            "description": (
                "Set up a classic MITM proxy pipeline (Burp/mitmproxy) so the operator can see/edit "
                "ALL traffic with a full UI, not just what capture_traffic/intercept_and_modify log here: "
                "installs the operator's CA into the device's system trust store (requires root -- this "
                "session's device must be rooted), sets the device's global HTTP proxy, and runs the "
                "heuristic pinning bypass so pinning doesn't break the proxied TLS. IMPORTANT: the device "
                "must be able to reach the proxy over its OWN network (same LAN as the proxy machine) -- "
                "this does NOT tunnel through the relay. Consumes ONE Frida run slot (the pinning bypass)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "proxy": {"type": "string", "description": "host:port of the proxy (e.g. '192.168.1.50:8080'). Falls back to config.yaml aipwn.mitm.proxy if omitted."},
                    "ca_cert_path": {"type": "string", "description": "Local path (on the dashboard host) to the proxy's CA cert (PEM). Falls back to config.yaml aipwn.mitm.ca_cert_path if omitted."},
                    "install_ca": {"type": "boolean", "description": "Whether to install the CA (default true)."},
                    "bypass_pinning": {"type": "boolean", "description": "Whether to run the heuristic pinning bypass (default true)."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "teardown_mitm_proxy",
            "description": "Remove the device's global HTTP proxy set by setup_mitm_proxy. Does not remove the installed CA.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

QUERY_TOOL_SCHEMAS: list[dict] = _reused_schemas + _QUERY_TOOL_SCHEMAS


# ── Fuentes de datos en disco (reportes JSON) ────────────────────────────────

def _vuln_json_path(package: str) -> Path | None:
    for candidate in (
        Path("reports") / package / "vuln.json",
        Path("decompiled") / f"vuln_{package}.json",
    ):
        if candidate.exists():
            return candidate
    return None


def _load_vuln_json(package: str) -> dict:
    path = _vuln_json_path(package)
    if path is None:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _load_review_json(package: str) -> dict[tuple, dict]:
    """``decompiled/vuln_<pkg>_review.json`` -- verdicts de aireview
    (TRUE_POSITIVE/FALSE_POSITIVE/DOWNGRADE), keyed por (rule_id, file, line)."""
    path = Path("decompiled") / f"vuln_{package}_review.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[tuple, dict] = {}
    for entry in data.get("reviews", data if isinstance(data, list) else []):
        if not isinstance(entry, dict):
            continue
        key = (entry.get("rule_id"), entry.get("file"), entry.get("line"))
        out[key] = entry
    return out


def _load_exploit_report(package: str) -> dict:
    path = Path("reports") / package / f"exploit_report_{package}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


# ── Tools nuevas: findings/store ─────────────────────────────────────────────

def tool_list_findings(
    ctx: ToolContext, db_path: str, severity: str = "", category: str = "",
) -> str:
    from nutcracker_core.store import db, repository

    conn = db.connect(db_path)
    try:
        runs = repository.history(conn, ctx.package, limit=1)
        if not runs:
            return json.dumps({
                "count": 0, "findings": [],
                "note": f"no hay runs registrados en la DB para '{ctx.package}' -- "
                        "¿se corrió `nutcracker scan/analyze` alguna vez para este package?",
            })
        run_id = runs[0]["id"]
        rows = [dict(r) for r in repository.findings_for_run(conn, run_id)]
    finally:
        conn.close()

    if severity:
        rows = [f for f in rows if (f.get("severity") or "").lower() == severity.strip().lower()]
    if category:
        needle = category.strip().lower()
        rows = [f for f in rows if needle in (f.get("category") or "").lower()]

    # Enriquecer con description/recommendation/matched_text de vuln.json
    vuln_data = _load_vuln_json(ctx.package)
    extras_by_key = {
        (f.get("rule_id"), f.get("file"), f.get("line")): f
        for f in vuln_data.get("findings", [])
    }
    for f in rows:
        extra = extras_by_key.get((f.get("rule_id"), f.get("file"), f.get("line")))
        if extra:
            for k in ("description", "recommendation", "matched_text"):
                if extra.get(k):
                    f[k] = extra[k]

    return json.dumps({"run_id": run_id, "count": len(rows), "findings": rows[:80]}, default=str)


def tool_get_finding_detail(
    ctx: ToolContext, rule_id: str, file: str = "", line: int | None = None,
) -> str:
    vuln_data = _load_vuln_json(ctx.package)
    matches = [
        f for f in vuln_data.get("findings", [])
        if f.get("rule_id") == rule_id
        and (not file or f.get("file") == file)
        and (line is None or f.get("line") == line)
    ]
    if not matches:
        return json.dumps({"error": f"no se encontró rule_id='{rule_id}' en vuln.json de '{ctx.package}'"})

    reviews = _load_review_json(ctx.package)
    out = []
    for f in matches:
        entry = dict(f)
        review = reviews.get((f.get("rule_id"), f.get("file"), f.get("line")))
        entry["aireview_verdict"] = (review or {}).get("verdict", "unreviewed")
        out.append(entry)
    return json.dumps({"matches": out}, default=str)


def tool_list_components(ctx: ToolContext) -> str:
    from nutcracker_core.manifest_analyzer import analyze_decompiled_dir

    decompiled_dir = ctx.runtime_dump_dir or ctx.decompiled_dir
    if decompiled_dir is None or not decompiled_dir.exists():
        return json.dumps({"error": "no hay directorio decompilado disponible para este package"})

    result = analyze_decompiled_dir(decompiled_dir)
    return json.dumps({
        "package": result.package,
        "app_label": result.app_label,
        "target_sdk": result.target_sdk,
        "min_sdk": result.min_sdk,
        "debuggable": result.debuggable,
        "allow_backup": result.allow_backup,
        "cleartext_traffic": result.cleartext_traffic,
        "has_network_security_config": result.has_network_security_config,
        "exported_components": result.exported_components,
        "dangerous_permissions": result.dangerous_permissions,
        "misconfigurations": [
            {
                "severity": m.severity, "category": m.category, "title": m.title,
                "description": m.description, "location": m.location,
                "recommendation": m.recommendation,
            }
            for m in result.misconfigurations
        ],
    }, default=str)


_SECRET_KEYWORDS = ("secret", "credential", "password", "token", "api_key", "apikey", "key", "leak")


def tool_list_secrets(ctx: ToolContext) -> str:
    from nutcracker_core.manifest_analyzer import analyze_decompiled_dir

    vuln_data = _load_vuln_json(ctx.package)
    reviews = _load_review_json(ctx.package)
    exploit_report = _load_exploit_report(ctx.package)
    confirmed_rule_ids = {
        r.get("rule_id") for r in exploit_report.get("results", [])
        if r.get("status") == "confirmed"
    }

    secrets = []
    for f in vuln_data.get("findings", []):
        haystack = f"{f.get('rule_id', '')} {f.get('title', '')} {f.get('category', '')}".lower()
        if not any(kw in haystack for kw in _SECRET_KEYWORDS):
            continue
        entry = dict(f)
        review = reviews.get((f.get("rule_id"), f.get("file"), f.get("line")))
        entry["aireview_verdict"] = (review or {}).get("verdict", "unreviewed")
        entry["aipwn_confirmed"] = f.get("rule_id") in confirmed_rule_ids
        secrets.append(entry)

    decompiled_dir = ctx.runtime_dump_dir or ctx.decompiled_dir
    if decompiled_dir is not None and decompiled_dir.exists():
        try:
            manifest_result = analyze_decompiled_dir(decompiled_dir)
            for m in manifest_result.misconfigurations:
                if m.category == "secrets":
                    secrets.append({
                        "rule_id": "MANIFEST_SECRET", "title": m.title,
                        "severity": m.severity, "file": m.location,
                        "description": m.description, "aireview_verdict": "unreviewed",
                        "aipwn_confirmed": False,
                    })
        except Exception:  # noqa: BLE001
            pass

    return json.dumps({"count": len(secrets), "secrets": secrets}, default=str)


def tool_get_exploit_results(ctx: ToolContext) -> str:
    report = _load_exploit_report(ctx.package)
    if not report:
        return json.dumps({
            "error": f"no hay reporte de explotación para '{ctx.package}' -- "
                     "¿se corrió `nutcracker aipwn <package> --report` alguna vez?",
        })
    return json.dumps(report, default=str)


# ── Tools nuevas: pantalla + interacción de UI (via DeviceIO) ───────────────

def tool_take_screenshot(device: "DeviceIO | None") -> str:
    if device is None:
        return json.dumps({
            "error": "no hay dispositivo conectado a esta sesión -- conectá un serial o "
                     "una sesión de relay antes de pedir la pantalla.",
        })
    try:
        png_bytes = device.screencap()
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"screencap falló: {e}"})
    if not png_bytes or png_bytes[:4] != b"\x89PNG":
        return json.dumps({"error": "screencap no devolvió un PNG válido"})

    black_screen_warning = False
    try:
        import io as _io
        from PIL import Image, ImageStat
        img = Image.open(_io.BytesIO(png_bytes)).convert("L")
        stat = ImageStat.Stat(img)
        if stat.mean[0] < 12:
            black_screen_warning = True
        max_width = 720
        if img.width > max_width:
            ratio = max_width / img.width
            img = img.resize((max_width, int(img.height * ratio)), Image.LANCZOS)
        buf = _io.BytesIO()
        img.save(buf, format="JPEG", quality=75, optimize=True)
        final_bytes = buf.getvalue()
        img_format = "jpeg"
    except Exception:  # noqa: BLE001
        final_bytes = png_bytes
        img_format = "png"

    b64 = base64.b64encode(final_bytes).decode()
    result: dict = {
        "status": "captured",
        "size_kb": len(final_bytes) // 1024,
        "img_format": img_format,
        "screenshot_b64": b64,
    }
    if black_screen_warning:
        result["black_screen_warning"] = True
    return json.dumps(result)


def tool_get_logcat(device: "DeviceIO | None", duration_seconds: int = 10, filter_spec: str = "") -> str:
    if device is None:
        return json.dumps({"error": "no hay dispositivo conectado a esta sesión"})
    duration_seconds = max(1, min(int(duration_seconds), 60))
    try:
        device.shell("logcat -c")  # buffer limpio -- solo eventos NUEVOS durante la ventana
    except Exception:  # noqa: BLE001
        pass
    args = filter_spec.split() if filter_spec else []
    text = device.logcat(args=args, duration_seconds=float(duration_seconds))
    lines = text.splitlines()
    return json.dumps({
        "duration_seconds": duration_seconds,
        "line_count": len(lines),
        "lines": lines[-500:],
    })


def tool_ui_tap(device: "DeviceIO | None", x: int, y: int) -> str:
    if device is None:
        return json.dumps({"error": "no hay dispositivo conectado a esta sesión"})
    device.shell(f"input tap {int(x)} {int(y)}")
    return json.dumps({"status": "ok", "action": "tap", "x": x, "y": y})


def tool_ui_input_text(device: "DeviceIO | None", text: str) -> str:
    if device is None:
        return json.dumps({"error": "no hay dispositivo conectado a esta sesión"})
    # `input text` de Android interpreta %s como espacio -- convención nativa,
    # no hace falta escapar comillas para texto normal.
    escaped = text.replace(" ", "%s")
    device.shell(f"input text {escaped}")
    return json.dumps({"status": "ok", "action": "input_text", "text": text})


def tool_ui_swipe(
    device: "DeviceIO | None", x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300,
) -> str:
    if device is None:
        return json.dumps({"error": "no hay dispositivo conectado a esta sesión"})
    device.shell(f"input swipe {int(x1)} {int(y1)} {int(x2)} {int(y2)} {int(duration_ms)}")
    return json.dumps({"status": "ok", "action": "swipe", "from": [x1, y1], "to": [x2, y2]})


def tool_ui_press_key(device: "DeviceIO | None", keycode: str) -> str:
    if device is None:
        return json.dumps({"error": "no hay dispositivo conectado a esta sesión"})
    device.shell(f"input keyevent {keycode}")
    return json.dumps({"status": "ok", "action": "press_key", "keycode": keycode})


# ── MITM proxy pipeline (setup_mitm_proxy / teardown_mitm_proxy) ────────────

def _mitm_config_defaults() -> tuple[str, str]:
    """``proxy``/``ca_cert_path`` desde ``config.yaml`` (aipwn.mitm.*) cuando
    el LLM no los pasó como argumento. Nunca lanza -- config faltante o
    inválida devuelve strings vacíos, que el caller reporta como error claro."""
    try:
        from nutcracker_core.config import get as cfg_get, load_config
        cfg = load_config()
        proxy = str(cfg_get(cfg, "aipwn", "mitm", "proxy", default="") or "")
        ca_cert_path = str(cfg_get(cfg, "aipwn", "mitm", "ca_cert_path", default="") or "")
        return proxy, ca_cert_path
    except Exception:  # noqa: BLE001
        return "", ""


def _install_mitm_ca(device: "DeviceIO", ca_cert_path: str) -> tuple[bool, str]:
    """Instala la CA en el trust store del sistema (requiere root -- el
    device de esta sesión ya está confirmado rooteado por el operador, ver
    plan.md). Sube el cert por ``device.shell`` en base64 -- funciona igual
    en serial y relay, sin necesitar un RPC de "push" que hoy no existe (ver
    toolbox/relay_adb_shim/adb -- push sigue sin implementar ahí)."""
    ca_path = Path(ca_cert_path)
    if not ca_path.exists():
        return False, f"CA cert no encontrado en '{ca_cert_path}'"

    try:
        hash_result = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(ca_path), "-noout"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"no se pudo correr openssl en el host del dashboard: {exc}"

    cert_hash = hash_result.stdout.strip().splitlines()[0] if hash_result.stdout.strip() else ""
    if not cert_hash:
        return False, "no se pudo calcular el hash de la CA -- ¿openssl instalado en el host del dashboard?"

    cert_b64 = base64.b64encode(ca_path.read_bytes()).decode()
    tmp_remote = "/data/local/tmp/nutcracker_mitm_ca.pem"
    system_dest = f"/system/etc/security/cacerts/{cert_hash}.0"
    device.shell(f"echo {cert_b64} | base64 -d > {tmp_remote}")
    device.shell(
        f"su -c 'mount -o rw,remount /system; cp {tmp_remote} {system_dest}; "
        f"chmod 644 {system_dest}; mount -o ro,remount /system'"
    )
    verify = device.shell(f"ls {system_dest}")
    if system_dest not in verify and cert_hash not in verify:
        return False, f"no se pudo verificar la instalación en {system_dest} (¿remount falló?)"
    return True, system_dest


def tool_setup_mitm_proxy(
    ctx: ToolContext,
    device: "DeviceIO | None",
    proxy: str = "",
    ca_cert_path: str = "",
    install_ca: bool = True,
    bypass_pinning: bool = True,
    frida_iteration: int = 1,
) -> str:
    if device is None:
        return json.dumps({"error": "no hay dispositivo conectado a esta sesión"})

    default_proxy, default_ca = _mitm_config_defaults()
    proxy = proxy or default_proxy
    ca_cert_path = ca_cert_path or default_ca
    if not proxy:
        return json.dumps({
            "error": "falta 'proxy' (host:port) -- pasalo como argumento o configuralo en "
                     "config.yaml bajo aipwn.mitm.proxy",
        })

    steps: list[str] = []
    device.shell(f"settings put global http_proxy {proxy}")
    steps.append(f"proxy global seteado a {proxy}")

    ca_installed = False
    ca_error = None
    if install_ca:
        if not ca_cert_path:
            ca_error = "install_ca=true pero falta 'ca_cert_path' (o config.yaml aipwn.mitm.ca_cert_path)"
        else:
            ca_installed, detail = _install_mitm_ca(device, ca_cert_path)
            if ca_installed:
                steps.append(f"CA instalada en {detail}")
            else:
                ca_error = detail

    bypass_ran = False
    bypass_summary = None
    if bypass_pinning:
        prompt_result = _aipwn_tools.tool_get_heuristic_bypass_script(ctx)
        if prompt_result.startswith("ERROR") or not ctx.heuristic_script:
            bypass_summary = prompt_result
        else:
            frida_result = ctx.on_frida_run(
                ctx.heuristic_script, "setup_mitm_proxy: bypass de pinning para el tráfico proxeado",
                frida_iteration,
            )
            ctx.frida_run_history.append(frida_result)
            bypass_ran = True
            bypass_summary = frida_result.summary()
            steps.append("bypass heurístico de pinning corrido")

    return json.dumps({
        "proxy": proxy, "ca_installed": ca_installed, "ca_error": ca_error,
        "bypass_ran": bypass_ran, "bypass_summary": bypass_summary, "steps": steps,
    })


def tool_teardown_mitm_proxy(device: "DeviceIO | None") -> str:
    if device is None:
        return json.dumps({"error": "no hay dispositivo conectado a esta sesión"})
    device.shell("settings delete global http_proxy")
    return json.dumps({"status": "ok", "proxy_removed": True})


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch_query_tool(
    ctx: ToolContext,
    name: str,
    arguments: dict[str, Any],
    *,
    db_path: str,
    device: "DeviceIO | None" = None,
    frida_iteration: int = 1,
) -> str:
    """Ejecuta la herramienta ``name`` y devuelve el resultado como string
    (JSON en casi todos los casos) para agregar al historial de mensajes.
    Nunca lanza -- cualquier excepción se captura y se devuelve como
    ``{"error": ...}`` para que el LLM la vea y pueda reintentar/ajustar."""
    try:
        if name in _RUNTIME_DEVICE_TOOL_NAMES:
            device_error = _check_device_ready(ctx, device, name)
            if device_error:
                return json.dumps({"error": device_error})
        if name in _REUSED_TOOL_NAMES:
            result, _extra = _aipwn_dispatch_tool(ctx, name, arguments, frida_iteration)
            return result
        if name == "list_findings":
            return tool_list_findings(
                ctx, db_path,
                severity=arguments.get("severity", ""),
                category=arguments.get("category", ""),
            )
        if name == "get_finding_detail":
            return tool_get_finding_detail(
                ctx, arguments["rule_id"],
                file=arguments.get("file", ""), line=arguments.get("line"),
            )
        if name == "list_components":
            return tool_list_components(ctx)
        if name == "list_secrets":
            return tool_list_secrets(ctx)
        if name == "get_exploit_results":
            return tool_get_exploit_results(ctx)
        if name == "take_screenshot":
            return tool_take_screenshot(device)
        if name == "get_logcat":
            return tool_get_logcat(
                device,
                duration_seconds=int(arguments.get("duration_seconds", 10)),
                filter_spec=arguments.get("filter_spec", ""),
            )
        if name == "ui_tap":
            return tool_ui_tap(device, arguments["x"], arguments["y"])
        if name == "ui_input_text":
            return tool_ui_input_text(device, arguments["text"])
        if name == "ui_swipe":
            return tool_ui_swipe(
                device, arguments["x1"], arguments["y1"], arguments["x2"], arguments["y2"],
                duration_ms=int(arguments.get("duration_ms", 300)),
            )
        if name == "ui_press_key":
            return tool_ui_press_key(device, arguments["keycode"])
        if name == "setup_mitm_proxy":
            return tool_setup_mitm_proxy(
                ctx, device,
                proxy=arguments.get("proxy", ""),
                ca_cert_path=arguments.get("ca_cert_path", ""),
                install_ca=bool(arguments.get("install_ca", True)),
                bypass_pinning=bool(arguments.get("bypass_pinning", True)),
                frida_iteration=frida_iteration,
            )
        if name == "teardown_mitm_proxy":
            return tool_teardown_mitm_proxy(device)
        return json.dumps({"error": f"herramienta desconocida: '{name}'"})
    except KeyError as exc:
        return json.dumps({"error": f"falta el argumento requerido {exc.args[0]!r} para '{name}'"})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"'{name}' falló: {exc}"})
