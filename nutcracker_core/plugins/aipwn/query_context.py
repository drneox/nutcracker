"""Resolución de contexto por package para el co-piloto de consulta
(query_agent.py) -- reusa exactamente la misma lógica que ya usa `nutcracker
aipwn` (CLI) para localizar el análisis estático más reciente y los
directorios decompilados, sin duplicarla."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nutcracker_core.analyzer import AnalysisResult


def resolve_package_context(
    package: str,
) -> tuple[Path | None, Path | None, "AnalysisResult | None"]:
    """Devuelve ``(decompiled_dir, runtime_dump_dir, analysis_result)`` para
    el análisis más reciente de ``package`` -- mismas fuentes que usa
    ``nutcracker aipwn`` (ver ``plugins/aipwn/__init__.py::_load_analysis_json``
    y ``plugins/aipwn/aipwn.py::_find_decompiled_dir``). Cualquiera de los
    tres puede venir en ``None`` si el package nunca fue analizado."""
    from nutcracker_core.plugins.aipwn import _load_analysis_json
    from nutcracker_core.plugins.aipwn.aipwn import _find_decompiled_dir

    analysis_result = _load_analysis_json(package)
    decompiled_dir, runtime_dump_dir = _find_decompiled_dir(package)
    return decompiled_dir, runtime_dump_dir, analysis_result
