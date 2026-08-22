"""Contexto compartido por los checks dinámicos (Fase 2.2 del plan)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable

# (argv sin el binario "adb", p.ej. ["shell", "run-as", "com.example", "id"]) -> stdout
AdbRunner = Callable[[list[str]], str]


def default_adb_runner(serial: str | None, adb_bin: str = "adb", timeout: int = 10) -> AdbRunner:
    """Runner real: invoca el binario adb del sistema. Los tests inyectan un
    runner falso en su lugar (ver DynamicCheckContext), así los checks
    dinámicos son deterministas y no requieren un dispositivo conectado."""

    def _run(args: list[str]) -> str:
        cmd = [adb_bin] + (["-s", serial] if serial else []) + args
        try:
            # FIX (prueba con dispositivo físico real, 2026-07-24): capturar
            # solo stdout descartaba el mensaje real de comandos como `run-as`
            # (p.ej. "run-as: package not debuggable: <pkg>"), que adb escribe
            # a stderr — quedaba en detail/logs solo un string vacío en vez
            # del diagnóstico útil. stderr=STDOUT los combina en orden real.
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    return _run


@dataclass
class DynamicCheckContext:
    """Contexto mínimo para checks dinámicos: package + serial + runner de adb
    inyectable (permite testear sin dispositivo real)."""

    package: str
    serial: str | None = None
    adb_run: AdbRunner = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.adb_run is None:
            self.adb_run = default_adb_runner(self.serial)
