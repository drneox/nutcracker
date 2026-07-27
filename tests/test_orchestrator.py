"""Tests de los fixes encontrados en la prueba con dispositivo físico real
(Magisk, 2026-07-24): --launch perdía el análisis estático (os.execvp
reemplazaba el proceso) y los jobs dinámicos de la cola dependían de un REPL
interactivo de Frida en vez de un modo headless."""

from __future__ import annotations

from nutcracker_core import orchestrator as orch


# ── _launch_frida_bypass: subprocess.run en vez de os.execvp ───────────────

def _mock_frida_server_setup(monkeypatch, setup_calls):
    """Mockea la cadena find_sdk_tools/get_frida_version/download_frida_server/
    frida_arch_for_device/setup_frida_server usada por _launch_frida_bypass
    cuando se pasa --serial, para no tocar red/adb de verdad en los tests."""
    monkeypatch.setattr(orch, "find_sdk_tools", lambda: {"adb": "adb"})
    monkeypatch.setattr(orch, "get_frida_version", lambda: "17.16.4")
    monkeypatch.setattr(orch, "frida_arch_for_device", lambda serial, tools: "arm64")
    monkeypatch.setattr(orch, "download_frida_server", lambda ver, arch: f"/tmp/frida-server-{ver}-{arch}")
    monkeypatch.setattr(
        orch, "setup_frida_server",
        lambda serial, tools, server_bin, **kw: setup_calls.append((serial, server_bin, kw)) or True,
    )


def test_launch_frida_bypass_uses_subprocess_run_not_execvp(monkeypatch, tmp_path):
    """os.execvp reemplaza el proceso Python — nunca vuelve, así que todo el
    código posterior (guardar JSON/PDF, post-hooks) nunca se ejecutaba. Debe
    usar subprocess.run, que sí retorna control al llamador."""
    execvp_called = []
    run_called = []
    setup_calls: list = []

    monkeypatch.setattr(orch.os, "execvp", lambda *a: execvp_called.append(a))
    monkeypatch.setattr(orch.subprocess, "run", lambda *a, **kw: run_called.append((a, kw)))
    _mock_frida_server_setup(monkeypatch, setup_calls)

    script = tmp_path / "bypass.js"
    script.write_text("// noop")

    orch._launch_frida_bypass("com.example.app", script, serial="ABC123")

    assert execvp_called == [], "no debe usar os.execvp (reemplaza el proceso y pierde resultados)"
    assert len(run_called) >= 1
    frida_cmd = run_called[-1][0][0]
    assert frida_cmd[0].endswith("frida")
    assert "-D" in frida_cmd and "ABC123" in frida_cmd


def test_launch_frida_bypass_with_serial_uses_setup_frida_server_not_manual_restart(monkeypatch, tmp_path):
    """FIX (prueba con dispositivo físico real, 2026-07-24): el restart manual
    ('nohup .../frida-server &', sin argumentos) nunca escuchaba en red y no
    manejaba Magisk/Zygisk (LD_PRELOAD) ni versión. Con --serial debe reusar
    setup_frida_server, el mismo mecanismo robusto del flujo FART."""
    run_called = []
    setup_calls: list = []

    monkeypatch.setattr(orch.subprocess, "run", lambda *a, **kw: run_called.append((a, kw)))
    _mock_frida_server_setup(monkeypatch, setup_calls)

    script = tmp_path / "bypass.js"
    script.write_text("// noop")

    orch._launch_frida_bypass("com.example.app", script, serial="ABC123", frida_host="192.168.1.4:27042")

    assert len(setup_calls) == 1, "debe llamar a setup_frida_server exactamente una vez"
    serial, server_bin, kwargs = setup_calls[0]
    assert serial == "ABC123"
    assert kwargs["listen_all"] is True, "frida_host configurado → debe escuchar en 0.0.0.0"
    assert kwargs["force_restart"] is True

    # No debe quedar ningún restart manual "nohup .../frida-server &" (el
    # camino viejo, sin -l 0.0.0.0) cuando hay --serial.
    manual_restarts = [c for c in run_called if "nohup" in " ".join(str(x) for x in c[0][0])]
    assert manual_restarts == []


def test_launch_frida_bypass_respects_configured_frida_server_version(monkeypatch, tmp_path):
    setup_calls: list = []
    download_calls: list = []

    monkeypatch.setattr(orch.subprocess, "run", lambda *a, **kw: None)
    monkeypatch.setattr(orch, "find_sdk_tools", lambda: {"adb": "adb"})
    monkeypatch.setattr(orch, "get_frida_version", lambda: "17.16.4")  # versión del entorno Python
    monkeypatch.setattr(orch, "frida_arch_for_device", lambda serial, tools: "arm64")
    monkeypatch.setattr(orch, "download_frida_server", lambda ver, arch: download_calls.append(ver) or "/tmp/bin")
    monkeypatch.setattr(
        orch, "setup_frida_server",
        lambda serial, tools, server_bin, **kw: setup_calls.append(kw) or True,
    )
    orch._CFG = {"strategies": {"frida_server_version": "17.15.4"}}  # pineada por el usuario

    script = tmp_path / "bypass.js"
    script.write_text("// noop")
    orch._launch_frida_bypass("com.example.app", script, serial="ABC123")

    assert download_calls == ["17.15.4"], "debe usar la versión de config.yaml, no la del entorno Python"
    orch._CFG = {}


def test_launch_frida_bypass_without_serial_falls_back_to_manual_restart(monkeypatch, tmp_path):
    """Sin --serial no hay forma fiable de resolver arch/tools para
    setup_frida_server — debe conservar el restart simple de antes en vez de
    no reiniciar frida-server en absoluto."""
    run_called = []
    setup_calls: list = []

    monkeypatch.setattr(orch.subprocess, "run", lambda *a, **kw: run_called.append((a, kw)))
    _mock_frida_server_setup(monkeypatch, setup_calls)

    script = tmp_path / "bypass.js"
    script.write_text("// noop")
    orch._launch_frida_bypass("com.example.app", script, serial=None)

    assert setup_calls == [], "sin serial no debe intentar setup_frida_server"
    manual_restarts = [c for c in run_called if "nohup" in " ".join(str(x) for x in c[0][0])]
    assert len(manual_restarts) == 1


def test_launch_frida_bypass_survives_setup_frida_server_exception(monkeypatch, tmp_path):
    """Un fallo al reiniciar frida-server (red caída, etc.) no debe tumbar la
    función entera — debe seguir e intentar lanzar frida igual."""
    run_called = []

    monkeypatch.setattr(orch.subprocess, "run", lambda *a, **kw: run_called.append((a, kw)))
    monkeypatch.setattr(orch, "find_sdk_tools", lambda: {"adb": "adb"})
    monkeypatch.setattr(orch, "get_frida_version", lambda: "17.16.4")
    monkeypatch.setattr(orch, "frida_arch_for_device", lambda serial, tools: "arm64")

    def _boom(*a, **kw):
        raise RuntimeError("no hay red")

    monkeypatch.setattr(orch, "download_frida_server", _boom)

    script = tmp_path / "bypass.js"
    script.write_text("// noop")
    orch._launch_frida_bypass("com.example.app", script, serial="ABC123")  # no debe lanzar

    frida_cmd = run_called[-1][0][0]
    assert frida_cmd[0].endswith("frida")


# ── build_job_cmd: dynamic_checks en vez de launch ──────────────────────────

def test_build_job_cmd_dynamic_uses_dynamic_checks_flag_not_launch():
    cmd = orch.build_job_cmd(
        "/tmp/app.apk", is_local_apk=True, static_only=False,
        dynamic_checks=True, serial="ABC123",
    )
    assert "--dynamic-checks" in cmd
    assert "--serial" in cmd and "ABC123" in cmd
    assert "--launch" not in cmd, "un job automatizado de la cola nunca debe usar --launch (REPL interactivo)"


def test_build_job_cmd_static_has_neither_flag():
    cmd = orch.build_job_cmd("/tmp/app.apk", is_local_apk=True, static_only=True, dynamic_checks=False)
    assert "--dynamic-checks" not in cmd
    assert "--launch" not in cmd
    assert "--static-only" in cmd


def test_build_job_cmd_aipwn_runs_aipwn_subcommand_with_package():
    cmd = orch.build_job_cmd(
        "com.example.tapjacking", is_local_apk=False, aipwn=True, serial="ZY22GPM27J",
    )
    assert "aipwn" in cmd
    assert "com.example.tapjacking" in cmd
    assert "--serial" in cmd and "ZY22GPM27J" in cmd
    # aipwn no acepta --config; nada de lo que analyze/scan usan debe colarse.
    assert "--config" not in cmd
    assert "--static-only" not in cmd
    assert "analyze" not in cmd and "scan" not in cmd


def test_build_job_cmd_aipwn_without_serial_omits_flag():
    cmd = orch.build_job_cmd("com.example.tapjacking", is_local_apk=False, aipwn=True)
    assert "--serial" not in cmd
    assert cmd[-1] == "com.example.tapjacking"


# ── _run_dynamic_checks_for: headless, nunca cede el proceso ────────────────

class _FakeResult:
    package = "com.example.app"


def test_run_dynamic_checks_for_executes_registered_checks(monkeypatch):
    from nutcracker_core.checks import registry

    registry.reset()
    calls = []

    class _FakeCheck:
        class meta:
            id = "DYN-FAKE"

        def run(self, ctx):
            calls.append((ctx.package, ctx.serial))
            from nutcracker_core.checks.base import CheckFinding
            return [CheckFinding(check_id="DYN-FAKE", title="fake", detected=True, detail="ok")]

    monkeypatch.setattr("nutcracker_core.checks.load_registry", lambda: registry.register_dynamic(_FakeCheck()))

    orch._run_dynamic_checks_for(_FakeResult(), "SERIAL123")

    assert calls == [("com.example.app", "SERIAL123")]
    registry.reset()


def test_run_dynamic_checks_for_survives_a_failing_check(monkeypatch):
    """Un check que lanza una excepción no debe tumbar el análisis completo
    (a diferencia del bug de --launch, que sí perdía todo)."""
    from nutcracker_core.checks import registry

    registry.reset()

    class _BrokenCheck:
        class meta:
            id = "DYN-BROKEN"

        def run(self, ctx):
            raise RuntimeError("dispositivo desconectado a mitad de camino")

    monkeypatch.setattr("nutcracker_core.checks.load_registry", lambda: registry.register_dynamic(_BrokenCheck()))

    orch._run_dynamic_checks_for(_FakeResult(), "SERIAL123")  # no debe lanzar
    registry.reset()
