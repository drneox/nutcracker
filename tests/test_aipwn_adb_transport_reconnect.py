"""FIX (encontrado en uso real, 2026-07-31): con un serial de red
("<ip>:5555") el transporte adb puede morir sin que el teléfono se haya ido
(dozing, reinicio del daemon adb) -- se vio en vivo un
"adb.exe: device '192.0.2.10:5555' not found" al instalar com.example.app
vía aipwn. adb_transport.ensure_available() ya existía (usado por
downloader.py/queue/engine.py/serve.py) pero aipwn.py y FridaAgent.run() no lo
llamaban antes de check_app_installed() -- este test cubre que ahora sí."""

from __future__ import annotations

from types import SimpleNamespace

import click
from click.testing import CliRunner

from nutcracker_core.plugins.aipwn import aipwn as aipwn_mod
from nutcracker_core.plugins.aipwn.frida_agent import AgentResult, FridaAgent


# ── aipwn._run_aipwn_inner: Paso 0 ──────────────────────────────────────────

def _base_config() -> dict:
    return {"llm": {"provider": "openai", "model": "test-model"}}


def _run_inner(**overrides):
    kwargs = dict(
        package="com.example.app",
        config=_base_config(),
        aipwn_cfg={},
        llm_cfg=_base_config()["llm"],
        force=True,  # salta "Paso 1: script previo"
    )
    kwargs.update(overrides)
    return aipwn_mod._run_aipwn_inner(**kwargs)


def test_reconnects_network_serial_before_checking_install(monkeypatch):
    monkeypatch.setattr(aipwn_mod.shutil, "which", lambda name: "/usr/bin/adb")
    monkeypatch.setattr(aipwn_mod, "check_app_installed", lambda adb_args, pkg: True)

    ensure_calls = []
    monkeypatch.setattr(
        aipwn_mod.adb_transport, "ensure_available",
        lambda serial, adb_bin=None: ensure_calls.append(serial) or True,
    )

    class _StubAgent:
        def __init__(self, **kw):
            pass

        def run(self):
            return AgentResult(success=True, script_path=None, explanation="stub",
                                failure_reason="", frida_runs=0, iterations=0,
                                last_frida_result=None)

    monkeypatch.setattr(aipwn_mod, "FridaAgent", _StubAgent)

    result = _run_inner(serial="192.0.2.10:5555")

    assert ensure_calls == ["192.0.2.10:5555"]
    assert result.success is True


def test_does_not_call_ensure_available_for_usb_serial(monkeypatch):
    monkeypatch.setattr(aipwn_mod.shutil, "which", lambda name: "/usr/bin/adb")
    monkeypatch.setattr(aipwn_mod, "check_app_installed", lambda adb_args, pkg: True)

    ensure_calls = []
    monkeypatch.setattr(
        aipwn_mod.adb_transport, "ensure_available",
        lambda serial, adb_bin=None: ensure_calls.append(serial) or True,
    )

    class _StubAgent:
        def __init__(self, **kw):
            pass

        def run(self):
            return AgentResult(success=True, script_path=None, explanation="stub",
                                failure_reason="", frida_runs=0, iterations=0,
                                last_frida_result=None)

    monkeypatch.setattr(aipwn_mod, "FridaAgent", _StubAgent)

    _run_inner(serial="TESTDEVICE01")

    assert ensure_calls == []


def test_does_not_call_ensure_available_without_adb(monkeypatch):
    monkeypatch.setattr(aipwn_mod.shutil, "which", lambda name: None)

    ensure_calls = []
    monkeypatch.setattr(
        aipwn_mod.adb_transport, "ensure_available",
        lambda serial, adb_bin=None: ensure_calls.append(serial) or True,
    )

    class _StubAgent:
        def __init__(self, **kw):
            pass

        def run(self):
            return AgentResult(success=True, script_path=None, explanation="stub",
                                failure_reason="", frida_runs=0, iterations=0,
                                last_frida_result=None)

    monkeypatch.setattr(aipwn_mod, "FridaAgent", _StubAgent)

    _run_inner(serial="192.0.2.10:5555")

    assert ensure_calls == []


# ── FridaAgent.run(): guard antes de check_app_installed ────────────────────

def _make_agent(serial: str | None) -> FridaAgent:
    agent = FridaAgent.__new__(FridaAgent)
    agent.package = "com.example.app"
    agent.ctx = SimpleNamespace(serial=serial)
    agent.llm = SimpleNamespace(model="test-model", provider="openai")
    agent.max_frida_runs = 5
    return agent


def test_frida_agent_run_reconnects_network_serial_before_check(monkeypatch):
    monkeypatch.setattr("nutcracker_core.plugins.aipwn.frida_agent.shutil.which",
                         lambda name: "/usr/bin/adb")

    ensure_calls = []
    monkeypatch.setattr(
        "nutcracker_core.plugins.aipwn.frida_agent.adb_transport.ensure_available",
        lambda serial, adb_bin=None: ensure_calls.append(serial) or True,
    )
    # check_app_installed=False -> run() retorna temprano, sin ejecutar el
    # loop ReAct completo (fuera del alcance de este test).
    monkeypatch.setattr(
        "nutcracker_core.plugins.aipwn.frida_agent.check_app_installed",
        lambda adb_args, pkg: False,
    )

    agent = _make_agent(serial="192.0.2.10:5555")
    result = agent.run()

    assert ensure_calls == ["192.0.2.10:5555"]
    assert result.success is False


def test_frida_agent_run_skips_reconnect_for_usb_serial(monkeypatch):
    monkeypatch.setattr("nutcracker_core.plugins.aipwn.frida_agent.shutil.which",
                         lambda name: "/usr/bin/adb")

    ensure_calls = []
    monkeypatch.setattr(
        "nutcracker_core.plugins.aipwn.frida_agent.adb_transport.ensure_available",
        lambda serial, adb_bin=None: ensure_calls.append(serial) or True,
    )
    monkeypatch.setattr(
        "nutcracker_core.plugins.aipwn.frida_agent.check_app_installed",
        lambda adb_args, pkg: False,
    )

    agent = _make_agent(serial="TESTDEVICE01")
    agent.run()

    assert ensure_calls == []


# ── aipwn_cmd (CLI): fallback a strategies.default_device_id sin --serial ──
# FIX (encontrado en uso real, 2026-07-31): `python3 nutcracker.py aipwn
# com.incode.smile.onboard` sin --serial reportaba "App ... not installed on
# device" con la app instalada -- el teléfono estaba conectado a la vez por
# USB y por wifi (mismo device, dos transportes), y sin -s explícito
# `adb shell ...` da "error: more than one device/emulator", que
# check_app_installed() confunde con "no instalada". El resto del pipeline
# (pipeline.py/orchestrator.py/serve.py) ya usaba strategies.default_device_id
# como fallback; aipwn_cmd era el único que se quedaba con serial=None.

def _invoke_aipwn_cli(tmp_path, monkeypatch, default_device_id: str, cli_serial: str | None):
    from nutcracker_core.plugins.aipwn import register

    monkeypatch.chdir(tmp_path)  # sin reports/ ni decompiled/ -> loaders devuelven None

    fake_config = {"strategies": {"default_device_id": default_device_id}}
    monkeypatch.setattr("nutcracker_core.config.load_config", lambda *a, **kw: fake_config)

    captured = {}

    def _fake_run_aipwn(**kwargs):
        captured["serial"] = kwargs.get("serial")
        return AgentResult(success=False, script_path=None, explanation="stub",
                            failure_reason="stub", frida_runs=0, iterations=0,
                            last_frida_result=None)

    monkeypatch.setattr("nutcracker_core.plugins.aipwn.aipwn.run_aipwn", _fake_run_aipwn)

    group = click.Group()
    register(group)

    args = ["aipwn", "com.example.app"]
    if cli_serial is not None:
        args += ["--serial", cli_serial]

    result = CliRunner().invoke(group, args)
    assert result.exit_code == 0, result.output
    return captured["serial"]


def test_aipwn_cli_falls_back_to_configured_default_device_id(tmp_path, monkeypatch):
    serial = _invoke_aipwn_cli(tmp_path, monkeypatch,
                                default_device_id="192.0.2.10:5555", cli_serial=None)
    assert serial == "192.0.2.10:5555"


def test_aipwn_cli_explicit_serial_overrides_config_default(tmp_path, monkeypatch):
    serial = _invoke_aipwn_cli(tmp_path, monkeypatch,
                                default_device_id="192.0.2.10:5555", cli_serial="TESTDEVICE01")
    assert serial == "TESTDEVICE01"


def test_aipwn_cli_stays_none_without_serial_or_config_default(tmp_path, monkeypatch):
    serial = _invoke_aipwn_cli(tmp_path, monkeypatch, default_device_id="", cli_serial=None)
    assert serial is None
