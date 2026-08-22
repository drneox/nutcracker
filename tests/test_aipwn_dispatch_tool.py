"""Tests de nutcracker_core/plugins/aipwn/frida_agent_tools.py::dispatch_tool.

Bug encontrado en vivo (2026-08-03): cuando el LLM devuelve JSON truncado para
un tool call (típicamente por quedarse sin max_tokens a mitad de generar un
script_js largo), LLMClient._do_completion ya lo detecta y cae a
``arguments = {}`` -- pero cada handler de dispatch_tool accedía a sus
argumentos requeridos con ``arguments["clave"]`` directo, así que un dict
vacío tumbaba la sesión de aipwn entera con un KeyError sin manejar:

    KeyError: 'script_js'

en nutcracker_core/plugins/aipwn/frida_agent_tools.py, dispatch_tool().
"""

from __future__ import annotations

from pathlib import Path

from nutcracker_core.plugins.aipwn.frida_agent_tools import ToolContext, dispatch_tool


def _make_ctx(tmp_path: Path) -> ToolContext:
    return ToolContext(
        package="com.example.app",
        decompiled_dir=None,
        analysis_result=None,
        serial=None,
        capture_seconds=15,
        scripts_dir=tmp_path,
        on_frida_run=lambda script_js, rationale, iteration: None,
    )


def test_dispatch_tool_missing_required_arg_returns_error_instead_of_crashing(tmp_path):
    """El caso central del bug: run_frida_script sin script_js (JSON truncado
    del LLM) no debe propagar un KeyError -- debe volver como resultado de
    herramienta con error, para que el agente lo vea y pueda reintentar."""
    ctx = _make_ctx(tmp_path)

    result, extra = dispatch_tool(ctx, "run_frida_script", {}, frida_iteration=1)

    assert extra is None
    assert "ERROR" in result
    assert "script_js" in result
    assert "run_frida_script" in result


def test_dispatch_tool_missing_required_arg_mentions_max_tokens_hint(tmp_path):
    """El mensaje debe orientar hacia la causa real más probable (truncamiento
    por max_tokens), no solo decir "falta un argumento" en abstracto."""
    ctx = _make_ctx(tmp_path)

    result, _ = dispatch_tool(ctx, "search_in_decompiled", {}, frida_iteration=1)

    assert "pattern" in result
    assert "max_tokens" in result


def test_dispatch_tool_unknown_tool_still_returns_error_string(tmp_path):
    """Comportamiento preexistente: no debe romperse con el fix nuevo."""
    ctx = _make_ctx(tmp_path)

    result, extra = dispatch_tool(ctx, "not_a_real_tool", {}, frida_iteration=1)

    assert extra is None
    assert "desconocida" in result


def test_dispatch_tool_report_success_keeps_its_own_specific_message(tmp_path):
    """report_success ya tenía su propio chequeo defensivo (arguments.get) --
    el try/except nuevo no debe interferir ni duplicar el mensaje."""
    ctx = _make_ctx(tmp_path)

    result, extra = dispatch_tool(ctx, "report_success", {}, frida_iteration=1)

    assert extra is None
    assert "script_js is required" in result


def test_dispatch_tool_works_normally_with_valid_arguments(tmp_path):
    """No debe cambiar nada del camino feliz -- argumentos completos siguen
    ejecutando la herramienta con normalidad."""
    ctx = _make_ctx(tmp_path)

    result, extra = dispatch_tool(
        ctx, "get_heuristic_bypass_script", {}, frida_iteration=1,
    )

    assert extra is None
    assert isinstance(result, str)
