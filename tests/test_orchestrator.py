"""Tests de los fixes encontrados en la prueba con dispositivo físico real
(Magisk, 2026-07-24): --launch perdía el análisis estático (os.execvp
reemplazaba el proceso) y los jobs dinámicos de la cola dependían de un REPL
interactivo de Frida en vez de un modo headless."""

from __future__ import annotations

import os
import shutil

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


def test_build_job_cmd_aipwn_always_passes_report():
    """FIX (2026-07-27): sin --report, plugins/aipwn/__init__.py nunca vuelca
    el ExploitReport a disco (exploit_report_<pkg>.json/.pdf) -- un job de
    cola/dashboard corría el exploit agent entero y tiraba el resultado, sin
    dejar nada reutilizable ni visible. Debe pasarse siempre, con o sin serial."""
    cmd_with_serial = orch.build_job_cmd(
        "com.example.tapjacking", is_local_apk=False, aipwn=True, serial="ZY22GPM27J",
    )
    cmd_without_serial = orch.build_job_cmd("com.example.tapjacking", is_local_apk=False, aipwn=True)
    assert "--report" in cmd_with_serial
    assert "--report" in cmd_without_serial


# ── build_job_cmd: source="device" (batch estático+aipwn desde archivo) ────

def test_build_job_cmd_scan_with_device_source_adds_source_and_serial_flags():
    cmd = orch.build_job_cmd(
        "com.example.app", is_local_apk=False, static_only=True,
        source="device", serial="ZY22GPM27J",
    )
    assert "scan" in cmd
    assert "--source" in cmd
    assert cmd[cmd.index("--source") + 1] == "device"
    assert "--serial" in cmd
    assert cmd[cmd.index("--serial") + 1] == "ZY22GPM27J"


def test_build_job_cmd_scan_with_device_source_without_serial_omits_serial_flag():
    cmd = orch.build_job_cmd("com.example.app", is_local_apk=False, source="device")
    assert "--source" in cmd and "device" in cmd
    assert "--serial" not in cmd


def test_build_job_cmd_scan_without_source_omits_source_flag():
    cmd = orch.build_job_cmd("com.example.app", is_local_apk=False)
    assert "--source" not in cmd


def test_build_job_cmd_local_apk_ignores_source():
    """source solo aplica al branch `scan` (target=package id); analyze
    (target ya es un .apk local) no lo usa -- no debe colarse en el cmd."""
    cmd = orch.build_job_cmd("/tmp/app.apk", is_local_apk=True, source="device", serial="X")
    assert "--source" not in cmd
    assert "analyze" in cmd and "scan" not in cmd


# ── _run_analysis: NUTCRACKER_APK_SOURCE (fix reportado en vivo, 2026-07-27) ─
# El dashboard asumía que "re-analizar" siempre podía re-descargar la app por
# package id -- fallaba para apps analizadas desde un .apk local nunca
# publicado en ninguna store. _run_analysis debe dejar la ruta real en esta
# env var solo cuando el archivo sobrevive al análisis (keep_apk=True).

class _FakeAnalyzer:
    def __init__(self, progress_callback=None, engine=None):
        pass

    def analyze(self, apk_path):
        result = type("FakeResult", (), {})()
        result.package = "com.example.fake"
        result.protected = False
        result.protection_broken = False
        result.elapsed_seconds = 0.0
        return result


def _mock_run_analysis_deps(monkeypatch):
    monkeypatch.setattr(orch, "APKAnalyzer", _FakeAnalyzer)
    monkeypatch.setattr(orch, "print_report", lambda result: None)
    monkeypatch.setattr(orch, "_post_analysis_flow", lambda result, apk_path: None)
    monkeypatch.setattr(orch, "save_analysis_json", lambda *a, **kw: None)
    monkeypatch.setattr(orch, "print_masvs_summary", lambda *a, **kw: None)
    monkeypatch.setattr(orch, "_print_verdict", lambda *a, **kw: None)
    monkeypatch.setattr(orch, "_print_elapsed", lambda *a, **kw: None)
    monkeypatch.setattr(orch, "_generate_pdf", lambda *a, **kw: None)
    monkeypatch.setattr(orch, "_RUN_DYNAMIC_CHECKS", False)

    seen_hook_calls = []
    monkeypatch.setattr(orch, "fire_post_hooks", lambda event, **kw: seen_hook_calls.append((event, kw)))
    return seen_hook_calls


def test_run_analysis_sets_apk_source_env_when_keep_apk_true(monkeypatch, tmp_path):
    _mock_run_analysis_deps(monkeypatch)
    monkeypatch.delenv("NUTCRACKER_APK_SOURCE", raising=False)

    apk_path = tmp_path / "nutbank.apk"
    apk_path.write_bytes(b"PK\x03\x04")

    orch._run_analysis(apk_path, report_path=None, keep_apk=True, gen_pdf=False)

    assert os.environ.get("NUTCRACKER_APK_SOURCE") == str(apk_path.resolve())
    assert apk_path.exists(), "keep_apk=True no debe borrar el archivo"


def test_run_analysis_clears_apk_source_env_when_keep_apk_false(monkeypatch, tmp_path):
    _mock_run_analysis_deps(monkeypatch)
    monkeypatch.setenv("NUTCRACKER_APK_SOURCE", "/stale/path/from/a/previous/run.apk")

    apk_path = tmp_path / "downloaded.apk"
    apk_path.write_bytes(b"PK\x03\x04")

    orch._run_analysis(apk_path, report_path=None, keep_apk=False, gen_pdf=False)

    assert "NUTCRACKER_APK_SOURCE" not in os.environ
    assert not apk_path.exists(), "keep_apk=False debe borrar el archivo como antes"


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


# ── _inject_manifest_component_findings (COMP004/006/007/008 desde manifest) ──
#
# FIX (2026-07-28): vivía inline al final de _do_vuln_scan, en un tramo que
# solo se alcanzaba con include_vuln_scan=True. Con sast_scan: false en
# config.yaml (el camino "solo leak scan" retorna antes), estos hallazgos
# nunca se generaban -- pese a salir enteramente del manifest, sin relación
# con SAST/semgrep. Se extrajo a función propia llamada desde ambos caminos.

def test_inject_manifest_component_findings_adds_comp_findings(monkeypatch):
    from nutcracker_core.scan_types import ScanResult

    class _FakeManifest:
        exported_components = [
            {"tag": "activity", "name": "com.example.app.AdminActivity"},
            {"tag": "provider", "name": "com.example.app.SecretProvider"},
        ]

    monkeypatch.setattr(orch, "_MANIFEST_ANALYSIS", _FakeManifest())

    scan_result = ScanResult(base_dir=None, findings=[], files_scanned=0, scanner_engine="none")
    orch._inject_manifest_component_findings(scan_result)

    rule_ids = sorted(f.rule_id for f in scan_result.findings)
    assert rule_ids == ["COMP006", "COMP008"]


def test_inject_manifest_component_findings_noop_without_manifest(monkeypatch):
    from nutcracker_core.scan_types import ScanResult

    monkeypatch.setattr(orch, "_MANIFEST_ANALYSIS", None)

    scan_result = ScanResult(base_dir=None, findings=[], files_scanned=0, scanner_engine="none")
    orch._inject_manifest_component_findings(scan_result)

    assert scan_result.findings == []


def test_inject_manifest_component_findings_noop_for_none_scan_result(monkeypatch):
    class _FakeManifest:
        exported_components = [{"tag": "activity", "name": "x"}]

    monkeypatch.setattr(orch, "_MANIFEST_ANALYSIS", _FakeManifest())
    orch._inject_manifest_component_findings(None)  # no debe lanzar


def test_inject_manifest_component_findings_does_not_duplicate_on_rerun(monkeypatch):
    """Llamarla dos veces sobre el mismo scan_result (posible si el llamador
    cambia) no debe duplicar los mismos hallazgos COMP."""
    from nutcracker_core.scan_types import ScanResult

    class _FakeManifest:
        exported_components = [{"tag": "service", "name": "com.example.app.SyncService"}]

    monkeypatch.setattr(orch, "_MANIFEST_ANALYSIS", _FakeManifest())

    scan_result = ScanResult(base_dir=None, findings=[], files_scanned=0, scanner_engine="none")
    orch._inject_manifest_component_findings(scan_result)
    orch._inject_manifest_component_findings(scan_result)

    assert len(scan_result.findings) == 1
    assert scan_result.findings[0].rule_id == "COMP007"


def test_do_vuln_scan_leak_only_path_still_adds_comp_findings(monkeypatch, tmp_path):
    """Regresión directa del bug: con include_vuln_scan=False (sast_scan:
    false en config.yaml), _do_vuln_scan tomaba el camino 'solo leak scan' y
    retornaba ANTES de inyectar los hallazgos COMP del manifest."""
    source_dir = tmp_path / "decompiled_app"
    source_dir.mkdir()

    class _FakeManifest:
        exported_components = [{"tag": "provider", "name": "com.example.app.LeakyProvider"}]
        misconfigurations = []

    monkeypatch.setattr(orch, "_MANIFEST_ANALYSIS", _FakeManifest())
    monkeypatch.setattr(orch, "_CFG", {
        "sast": {"engine": "regex"},
        "leak_scan": {"native": False, "apkleaks": False, "gitleaks": False},
    })

    scan_result = orch._do_vuln_scan(
        source_dir, apk_path=None, package_hint="com.example.app",
        include_vuln_scan=False, include_leak_scan=False,
    )

    assert scan_result is not None
    rule_ids = [f.rule_id for f in scan_result.findings]
    assert "COMP008" in rule_ids, "el hallazgo COMP del manifest se perdía en el camino sin vuln_scan"


# ── toolbox de Docker ignorado en la detección de jadx (bug en vivo, VM real) ──
# Reportado en vivo (2026-08-05): con toolbox.enabled=true en config.yaml y
# SIN jadx instalado localmente en la VM, el job igual fallaba con "No se
# encontró ningún decompilador" -- dos chequeos separados llamaban a
# shutil.which("jadx")/get_available_tool() SIN pasarles el config, así que
# nunca veían el toolbox como alternativa válida.

def test_do_decompile_detects_toolbox_without_local_jadx(monkeypatch, tmp_path):
    # auto.unattended + sast_scan/leak_scan en false: solo interesa que pase
    # el chequeo de disponibilidad del decompilador, no ejercitar el resto del
    # flujo (vuln-scan/manifest/OSINT), que no es lo que este test cubre.
    monkeypatch.setattr(orch, "_CFG", {
        "toolbox": {"enabled": True},
        "auto": {"unattended": True},
        "features": {"manifest_scan": False, "sast_scan": False, "leak_scan": False},
    })
    monkeypatch.setattr(shutil, "which", lambda name: None)  # nada instalado local

    calls = []
    fake_dest = tmp_path / "decompiled" / "pkg"
    fake_dest.mkdir(parents=True)
    monkeypatch.setattr(
        orch, "decompile",
        lambda apk_path, output_dir, dest_name=None, config=None: calls.append(config) or fake_dest,
    )

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    orch._do_decompile(apk, "com.example.app")

    # _do_decompile() devuelve el resultado del vuln-scan (None acá, porque
    # sast_scan/leak_scan están apagados a propósito) -- lo que este test
    # verifica es que SÍ llegó a invocar decompile() con el toolbox habilitado
    # en vez de cortar antes con "no se encontró ningún decompilador".
    assert calls, "decompile() nunca se invocó -- el chequeo de disponibilidad cortó antes de tiempo"
    assert calls[0]["toolbox"] == {"enabled": True}
    monkeypatch.setattr(orch, "_CFG", {})


def test_do_decompile_without_toolbox_and_without_local_jadx_fails_as_before(monkeypatch, tmp_path, capsys):
    """Retrocompatibilidad: sin toolbox y sin binario local, debe seguir
    fallando limpio (no debe "inventar" disponibilidad de la nada)."""
    monkeypatch.setattr(orch, "_CFG", {})
    monkeypatch.setattr(shutil, "which", lambda name: None)

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    result = orch._do_decompile(apk, "com.example.app")

    assert result is None


def test_validate_all_dependencies_accepts_toolbox_for_jadx(monkeypatch):
    monkeypatch.setattr(orch, "_CFG", {
        "toolbox": {"enabled": True},
        "pipelines": {"unprotected": {"decompilation_jadx": True}},
    })
    monkeypatch.setattr(shutil, "which", lambda name: None if name != "adb" else "/usr/bin/adb")

    ok = orch._validate_all_dependencies(protected=False)

    assert ok is True, "con toolbox habilitado, jadx no debería reportarse como dependencia faltante"
    monkeypatch.setattr(orch, "_CFG", {})
