"""Relay "browser-as-bridge" (plan.md, 2026-08-04): aipwn.py debe preferir
NUTCRACKER_FRIDA_HOST (seteada por engine.py::_run_job cuando el job trae
job.frida_host, ver queue/engine.py) por sobre strategies.frida_host del
config -- así un job encolado con relay=True apunta frida al túnel local
(127.0.0.1:PF) en vez del host fijo pensado para uso directo sin relay.

Mismo patrón que tests/test_aipwn_adb_transport_reconnect.py: stub de
FridaAgent para llegar hasta donde aipwn.py construye sus kwargs sin correr
el agente real."""

from __future__ import annotations

from nutcracker_core.plugins.aipwn import aipwn as aipwn_mod
from nutcracker_core.plugins.aipwn.frida_agent import AgentResult


def _base_config(frida_host: str | None = None) -> dict:
    config: dict = {"llm": {"provider": "openai", "model": "test-model"}}
    if frida_host is not None:
        config["strategies"] = {"frida_host": frida_host}
    return config


class _CapturingStubAgent:
    captured_kwargs: dict = {}

    def __init__(self, **kw):
        _CapturingStubAgent.captured_kwargs = kw

    def run(self):
        return AgentResult(success=True, script_path=None, explanation="stub",
                            failure_reason="", frida_runs=0, iterations=0,
                            last_frida_result=None)


_UNSET = object()  # distingue "no tocar el env" de "asegurar que no esté seteada"


def _run_inner(monkeypatch, config_frida_host: str | None, env_frida_host=_UNSET):
    monkeypatch.setattr(aipwn_mod.shutil, "which", lambda name: "/usr/bin/adb")
    monkeypatch.setattr(aipwn_mod, "check_app_installed", lambda adb_args, pkg: True)
    monkeypatch.setattr(aipwn_mod, "FridaAgent", _CapturingStubAgent)
    if env_frida_host is None:
        monkeypatch.delenv("NUTCRACKER_FRIDA_HOST", raising=False)
    elif env_frida_host is not _UNSET:
        monkeypatch.setenv("NUTCRACKER_FRIDA_HOST", env_frida_host)
    # _UNSET: no tocar -- lo que el test haya seteado por su cuenta queda.

    config = _base_config(config_frida_host)
    aipwn_mod._run_aipwn_inner(
        package="com.example.app",
        config=config,
        aipwn_cfg={},
        llm_cfg=config["llm"],
        force=True,  # salta "Paso 1: script previo"
    )
    return _CapturingStubAgent.captured_kwargs


def test_env_override_takes_priority_over_config(monkeypatch):
    kwargs = _run_inner(
        monkeypatch,
        config_frida_host="192.168.1.4:27042",
        env_frida_host="127.0.0.1:54321",
    )
    assert kwargs["frida_host"] == "127.0.0.1:54321"


def test_falls_back_to_config_without_env_override(monkeypatch):
    kwargs = _run_inner(
        monkeypatch,
        config_frida_host="192.168.1.4:27042",
        env_frida_host=None,
    )
    assert kwargs["frida_host"] == "192.168.1.4:27042"


def test_none_when_neither_env_nor_config_set(monkeypatch):
    kwargs = _run_inner(monkeypatch, config_frida_host=None, env_frida_host=None)
    assert kwargs["frida_host"] is None


def test_blank_env_var_does_not_shadow_config(monkeypatch):
    """Una env var vacía/solo-espacios (heredada de un padre que la seteó a
    "") no debe pisar un frida_host real del config -- mismo criterio que
    .strip() or None ya aplicaba al valor del config antes de este fix."""
    monkeypatch.setenv("NUTCRACKER_FRIDA_HOST", "   ")
    kwargs = _run_inner(monkeypatch, config_frida_host="192.168.1.4:27042")
    assert kwargs["frida_host"] == "192.168.1.4:27042"


# ── Paso 1 (probar script previo) también debe honrar frida_host ───────────
#
# Bug encontrado en vivo (job 2823, 2026-08-04): launch_frida_capture() en el
# paso "probar script previo" no recibía frida_host -- con relay activo caía
# a `frida -D <serial>` (busca el device por USB) en vez de `-H
# 127.0.0.1:PF` (el túnel), y fallaba siempre con "Device '<serial>' not
# found" pese a que el script cacheado sí hubiera funcionado. El agente
# quemaba 13 iteraciones de LLM re-explorando desde cero en vez de 0.

def test_previous_script_step_passes_frida_host_to_launch_frida_capture(monkeypatch, tmp_path):
    scripts_dir = tmp_path / "frida_scripts"
    scripts_dir.mkdir()
    prev_script = scripts_dir / "bypass_com.example.app_20260804_120000_agent.js"
    prev_script.write_text("console.log('cached bypass');")

    monkeypatch.setattr(aipwn_mod.shutil, "which", lambda name: "/usr/bin/adb")
    monkeypatch.setattr(aipwn_mod, "check_app_installed", lambda adb_args, pkg: True)
    monkeypatch.setenv("NUTCRACKER_FRIDA_HOST", "127.0.0.1:54321")

    captured: dict = {}

    def _fake_launch(**kwargs):
        captured.update(kwargs)
        from nutcracker_core.plugins.aipwn.frida_capture import FridaRunResult
        return FridaRunResult(iteration=0, script_js=kwargs["script_js"], output="", logcat="", success=True)

    monkeypatch.setattr(aipwn_mod, "launch_frida_capture", _fake_launch)

    aipwn_mod._run_aipwn_inner(
        package="com.example.app",
        config=_base_config(),
        aipwn_cfg={"scripts_dir": str(scripts_dir)},
        llm_cfg=_base_config()["llm"],
        force=False,  # NO saltar el paso 1 -- es justo lo que este test cubre
    )

    assert captured.get("frida_host") == "127.0.0.1:54321"
