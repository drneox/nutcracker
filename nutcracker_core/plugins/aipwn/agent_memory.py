"""agent_memory.py — Memoria persistente por paquete para FridaAgent.

Guarda un historial de sesiones en:
    aipwn_memory/{package}_memory.json

Cada sesión registra qué hooks funcionaron, cuáles fallaron, clases clave
y el resultado global para que el agente no repita los mismos errores en
ejecuciones futuras contra el mismo paquete.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

_MEMORY_DIR = Path("aipwn_memory")
_MAX_SESSIONS = 10  # sesiones a conservar por paquete
_RESUME_SUFFIX = "_resume_state.json"


def load_sessions(package: str, memory_dir: Path = _MEMORY_DIR) -> list[dict]:
    """Carga el historial de sesiones de un paquete. Retorna [] si no existe."""
    path = memory_dir / f"{package}_memory.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("sessions", [])
    except (json.JSONDecodeError, OSError):
        return []


def save_session(
    package: str,
    outcome: str,          # "success" | "failure"
    frida_runs: int,
    iterations: int,
    protections: list[str],
    working_hooks: list[str],
    failed_hooks: list[str],
    key_classes: list[str],
    notes: str = "",
    memory_dir: Path = _MEMORY_DIR,
    runtime_classes: list[str] | None = None,
) -> None:
    """Agrega una sesión al historial persistente del paquete."""
    memory_dir.mkdir(parents=True, exist_ok=True)
    path = memory_dir / f"{package}_memory.json"

    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {"package": package, "sessions": []}
    else:
        data = {"package": package, "sessions": []}

    session: dict = {
        "date": datetime.date.today().isoformat(),
        "outcome": outcome,
        "frida_runs": frida_runs,
        "iterations": iterations,
    }
    if protections:
        session["protections"] = protections
    if working_hooks:
        session["working_hooks"] = working_hooks
    if failed_hooks:
        session["failed_hooks"] = failed_hooks
    if key_classes:
        session["key_classes"] = key_classes
    if runtime_classes:
        session["runtime_classes"] = runtime_classes
    if notes:
        session["notes"] = notes[:2000]

    data["sessions"].append(session)
    data["sessions"] = data["sessions"][-_MAX_SESSIONS:]

    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def build_memory_context(sessions: list[dict]) -> str:
    """
    Construye un bloque de texto listo para inyectar en el system prompt.
    Muestra las últimas 5 sesiones, la más reciente primero.
    Retorna '' si no hay sesiones anteriores.
    """
    if not sessions:
        return ""

    lines = [
        "\n## Past Sessions Memory — do NOT repeat failed approaches",
        "(Most recent first. Build on what worked; avoid what crashed or was detected.)",
    ]
    for s in reversed(sessions[-5:]):
        icon = "✓" if s.get("outcome") == "success" else "✗"
        lines.append(
            f"\n### {icon} {s.get('date', '?')} — {s.get('outcome', '?')} "
            f"({s.get('frida_runs', 0)} Frida runs, {s.get('iterations', 0)} LLM iterations)"
        )
        if s.get("protections"):
            lines.append(f"- Protections detected: {', '.join(s['protections'])}")
        if s.get("working_hooks"):
            lines.append(f"- Working hooks (reuse): {', '.join(s['working_hooks'])}")
        if s.get("failed_hooks"):
            lines.append(f"- Failed/crashing hooks (AVOID): {', '.join(s['failed_hooks'])}")
        if s.get("runtime_classes"):
            lines.append(
                f"- Runtime class names confirmed (safe for Java.use): {', '.join(s['runtime_classes'])}"
            )
        if s.get("key_classes"):
            lines.append(
                f"- Static analysis class names (JADX/JADX — may differ from runtime; "
                f"verify with enumerate_runtime_classes before Java.use): {', '.join(s['key_classes'])}"
            )
        if s.get("notes"):
            lines.append(f"- Notes: {s['notes']}")

    return "\n".join(lines)


# ── Estado de reanudación (botón "+5 iteraciones" del dashboard) ────────────
#
# Distinto de save_session()/load_sessions() de arriba: eso es un RESUMEN
# (hooks que funcionaron/fallaron, clases clave) pensado para inyectarse como
# contexto en una sesión NUEVA. Esto es la conversación COMPLETA
# (self.messages tal cual, con cada tool call y su resultado) para poder
# CONTINUAR literalmente la misma sesión donde quedó, no empezar de cero con
# un resumen. analysis_result/decompiled_dir no se persisten acá a propósito:
# la CLI ya los re-deriva frescos desde disco en cada invocación (ver
# plugins/aipwn/__init__.py::aipwn_cmd), así que reanudar simplemente vuelve a
# cargarlos igual que un análisis normal -- no hay nada nuevo que serializar.


def _resume_path(package: str, memory_dir: Path = _MEMORY_DIR) -> Path:
    return memory_dir / f"{package}{_RESUME_SUFFIX}"


def save_resume_state(
    package: str,
    messages: list[dict],
    frida_runs_used: int,
    iteration: int,
    memory_dir: Path = _MEMORY_DIR,
) -> None:
    """Guarda la conversación completa para poder reanudarla más tarde con
    más presupuesto de iteraciones. Se llama SOLO cuando el agente termina
    sin una conclusión definitiva (límite de iteraciones, LLM sin tool_calls,
    error de LLM agotando reintentos) -- ver FridaAgent.run(). Un
    report_success/report_failure es una conclusión real: no hay nada que
    reanudar, y el llamador debe usar clear_resume_state() en ese caso."""
    memory_dir.mkdir(parents=True, exist_ok=True)
    path = _resume_path(package, memory_dir)
    path.write_text(
        json.dumps({
            "package": package,
            "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "messages": messages,
            "frida_runs_used": frida_runs_used,
            "iteration": iteration,
        }, ensure_ascii=False),
        encoding="utf-8",
    )


def load_resume_state(package: str, memory_dir: Path = _MEMORY_DIR) -> dict | None:
    """None si no hay sesión pendiente, o si el archivo quedó corrupto (una
    reanudación con estado roto no debe tumbar el job -- mejor forzar un
    análisis fresco que uno que crashea al cargar)."""
    path = _resume_path(package, memory_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def clear_resume_state(package: str, memory_dir: Path = _MEMORY_DIR) -> None:
    _resume_path(package, memory_dir).unlink(missing_ok=True)


def has_resume_state(package: str, memory_dir: Path = _MEMORY_DIR) -> bool:
    return _resume_path(package, memory_dir).exists()
