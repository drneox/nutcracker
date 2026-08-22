"""Check dinámico: confirma android:debuggable=true en el dispositivo real vía
ADB (run-as + JDWP), sin LLM.

Complementa al check estático INFO001 (que solo lee el manifest declarado) con
una confirmación en tiempo de ejecución: un manifest puede declarar
debuggable=false pero el build real instalado en el device puede diferir
(builds de staging, APKs re-firmados, etc.), o viceversa.

Lógica portada de plugins/aipwn/exploit_agent.py::_tool_check_debuggable,
reimplementada aquí como pieza core reutilizable e inyectable para tests, sin
depender de la clase interna del plugin de IA (el checks framework es core;
la IA es plugin — ver plan.md, "Principios rectores").
"""

from __future__ import annotations

from ..base import Check, CheckFinding, CheckMeta
from ..registry import register_dynamic
from .context import DynamicCheckContext


class DebuggableDynamicCheck(Check):
    meta = CheckMeta(
        id="DYN-DEBUGGABLE",
        title="android:debuggable confirmado en runtime (run-as / JDWP)",
        kind="dynamic",
        severity="high",
        masvs=["MASVS-RESILIENCE-4"],
        maswe=["MASWE-0067"],
        cwe=["CWE-489"],
        source="dynamic",
    )

    def run(self, ctx: DynamicCheckContext) -> list[CheckFinding]:
        run_as_out = ctx.adb_run(["shell", "run-as", ctx.package, "id"])
        run_as_works = "uid=" in run_as_out

        pid_str = ctx.adb_run(["shell", "pidof", ctx.package]).strip()
        jdwp_out = ctx.adb_run(["jdwp"])
        jdwp_confirms = bool(pid_str) and pid_str.isdigit() and pid_str in jdwp_out.split()

        detected = run_as_works or jdwp_confirms
        detail = (
            f"run-as {'funcionó' if run_as_works else 'falló'}; "
            f"JDWP {'confirma' if jdwp_confirms else 'no confirma'} (pid={pid_str or '?'})"
        )
        return [CheckFinding(
            check_id=self.meta.id,
            title=self.meta.title,
            detected=detected,
            severity=self.meta.severity if detected else "info",
            detail=detail,
            masvs=self.meta.masvs,
            maswe=self.meta.maswe,
            cwe=self.meta.cwe,
        )]


def register() -> None:
    register_dynamic(DebuggableDynamicCheck())
