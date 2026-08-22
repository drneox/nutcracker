"""Check dinámico: detecta tráfico HTTP en claro observado en logcat durante
la ejecución real de la app, sin LLM.

Versión deterministas y solo-ADB de la confirmación de cleartext traffic:
complementa al check estático NET001 (que busca literales "http://" en el
código decompilado, sin garantía de que ese código se ejecute) con evidencia
de tráfico HTTP real durante la corrida. No incluye la parte de
plugins/aipwn/exploit_agent.py::_tool_confirm_cleartext_traffic que inspecciona
campos estáticos vía Frida — eso requiere instrumentación en vivo y queda para
el agente de IA (plugin); este check cubre la porción puramente determinista.
"""

from __future__ import annotations

import time

from ..base import Check, CheckFinding, CheckMeta
from ..registry import register_dynamic
from .context import DynamicCheckContext


class CleartextTrafficDynamicCheck(Check):
    meta = CheckMeta(
        id="DYN-CLEARTEXT-TRAFFIC",
        title="Tráfico HTTP en claro observado en logcat durante la ejecución",
        kind="dynamic",
        severity="high",
        masvs=["MASVS-NETWORK-1"],
        maswe=["MASWE-0050"],
        cwe=["CWE-319"],
        source="dynamic",
    )

    def __init__(self, settle_seconds: float = 3.0, logcat_lines: int = 200) -> None:
        self._settle_seconds = settle_seconds
        self._logcat_lines = logcat_lines

    def run(self, ctx: DynamicCheckContext) -> list[CheckFinding]:
        ctx.adb_run(["shell", "logcat", "-c"])
        if self._settle_seconds:
            time.sleep(self._settle_seconds)

        logcat_out = ctx.adb_run(["shell", "logcat", "-d", "-t", str(self._logcat_lines)])
        http_lines = [
            line for line in logcat_out.splitlines()
            if "http://" in line.lower() and "https://" not in line.lower()
        ]

        detected = len(http_lines) > 0
        sample = http_lines[0][:200] if http_lines else ""
        detail = f"{len(http_lines)} línea(s) con http:// en logcat" + (f" — ej: {sample}" if sample else "")

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
    register_dynamic(CleartextTrafficDynamicCheck())
