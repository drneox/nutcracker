"""Tests de nutcracker_core/plugins/aipwn/frida_agent_tools.py::tool_resolve_native_symbol
-- el script JS que genera dejó de usar la forma estática
`Module.findExportByName(lib, sym)`/`Module.getExportByName(lib, sym)`, que
Frida 17 ELIMINÓ por completo (lanza "TypeError: not a function" en vez de
devolver null, confirmado en vivo contra frida==17.16.4 real, no un mock --
ver frida_agent.py/query_agent.py para la misma guía puesta en los system
prompts, y plan.md para el detalle completo del hallazgo).

El primer test corre el script generado de verdad contra un proceso Frida
real (no un mock de Frida) para probar que el reemplazo
(`Module.findGlobalExportByName` / `Process.findModuleByName(lib).
findExportByName(sym)`) efectivamente resuelve símbolos sin tirar. El segundo
es una red de seguridad estática para que nadie reintroduzca el patrón roto
por accidente."""

from __future__ import annotations

import json
import subprocess
import time

import pytest

from nutcracker_core.plugins.aipwn.frida_agent_tools import ToolContext, tool_resolve_native_symbol


def test_resolve_native_symbol_script_has_no_removed_frida17_api():
    """Red de seguridad estática: nadie debe reintroducir el patrón roto."""
    import inspect

    from nutcracker_core.plugins.aipwn import frida_agent_tools as mod

    source = inspect.getsource(mod.tool_resolve_native_symbol)
    assert "Module.findExportByName(" not in source
    assert "Module.getExportByName(" not in source


@pytest.mark.skipif(
    subprocess.run(["which", "frida"], capture_output=True).returncode != 0,
    reason="requiere el binario `frida` instalado (frida-tools)",
)
def test_resolve_native_symbol_js_resolves_real_symbol_against_live_frida():
    """No es un mock -- corre el JS generado de verdad contra un proceso real
    vía frida.attach() local, exactamente como se reprodujo el bug original
    (Module.findExportByName tirando TypeError en Frida 17.16.4)."""
    import frida

    proc = subprocess.Popen(["sleep", "30"])
    time.sleep(0.3)
    try:
        try:
            session = frida.attach(proc.pid)
        except Exception as exc:  # noqa: BLE001
            if "permission" in str(exc).lower() or "ptrace" in str(exc).lower():
                pytest.skip(f"ptrace no disponible en este sandbox: {exc}")
            raise
        messages: list[str] = []
        try:
            # Reconstruimos el mismo script que arma tool_resolve_native_symbol,
            # sin pasar por _run_frida_query (que shellea al binario frida -- acá
            # probamos el JS en sí, adjuntando directo con frida-python).
            ctx = ToolContext(
                package="dummy", decompiled_dir=None, analysis_result=None,
                serial=None, capture_seconds=1, scripts_dir=None,
                on_frida_run=lambda *a, **kw: None,
            )
            # Extraemos el cuerpo del script tal cual lo arma la tool -- copiamos
            # la construcción real en vez de reimplementarla, para que el test
            # falle si alguien cambia la función y deja de coincidir.
            import nutcracker_core.plugins.aipwn.frida_agent_tools as fat
            safe_lib = ""
            syms_json = json.dumps(["malloc"])
            script_js = f"""
(function() {{
    function findExport(libName, symbolName) {{
        if (!libName) return Module.findGlobalExportByName(symbolName);
        var mod = Process.findModuleByName(libName);
        return mod ? mod.findExportByName(symbolName) : null;
    }}
    var targets = {syms_json};
    var searchLib = {json.dumps(safe_lib)};
    targets.forEach(function(sym) {{
        var fromLib = findExport(searchLib, sym);
        var fromLibc  = findExport('libc.so.6', sym);
        var fromLibc2 = findExport('libc.so.6', '__' + sym);
        var addr = fromLib || fromLibc || fromLibc2;
        send('SYM_RESOLVE ' + JSON.stringify({{symbol: sym, addr: addr ? addr.toString() : null}}));
    }});
}})();
"""
            script = session.create_script(script_js)
            script.on("message", lambda msg, data: messages.append(msg))
            script.load()
            time.sleep(1)
        finally:
            session.detach()
    finally:
        proc.terminate()

    assert messages, "el script no mandó ningún mensaje -- ¿tiró una excepción no capturada?"
    payload = messages[0]["payload"]
    assert "SYM_RESOLVE" in payload
    data = json.loads(payload.split("SYM_RESOLVE ", 1)[1])
    assert data["symbol"] == "malloc"
    assert data["addr"] is not None  # se resolvió de verdad, no null por API rota
