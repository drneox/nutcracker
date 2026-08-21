"""Tests de nutcracker_core/plugins/aipwn/frida_capture.py -- el soporte
nuevo de ``shell_fn``/``logcat_fn`` en ``setup_frida_server``/
``launch_frida_capture`` (2026-08-21).

Contexto del bug real: en modo relay (celular conectado por WebUSB al
navegador del operador, no por USB al host del dashboard) no existe ningún
`adb` LOCAL con ruta al dispositivo -- solo el navegador puede hablarle. El
mecanismo que hace funcionar `adb` sobre relay para los jobs de la cola
(``toolbox/relay_adb_shim/adb``, activado anteponiendo su directorio al PATH
del SUBPROCESO del job) nunca se activa para el co-piloto de consulta
(``query_agent.py::QueryAgent``), porque ese corre IN-PROCESS, no como
subproceso -- nunca hay un PATH nuevo que armar.

Estos tests verifican que, con ``shell_fn``/``logcat_fn`` provistos (lo que
hace ``QueryAgent._execute_frida`` en modo relay, vía ``DeviceIO``), estas
funciones compartidas NUNCA tocan ``subprocess``/``adb`` local -- todo pasa
por los callables inyectados. Sin ellos (``None``, el default), el
comportamiento es exactamente el de siempre (CLI, jobs de la cola)."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from nutcracker_core.plugins.aipwn.frida_capture import launch_frida_capture, setup_frida_server


def test_setup_frida_server_with_shell_fn_never_touches_subprocess():
    calls = []

    def fake_shell(cmd: str) -> str:
        calls.append(cmd)
        return ""

    with patch("subprocess.run") as mock_run:
        result = setup_frida_server(
            adb_args=[], package="com.example.app", frida_host="127.0.0.1:12345",
            shell_fn=fake_shell,
        )

    assert result is True
    mock_run.assert_not_called()
    assert any("killall frida-server" in c for c in calls)
    assert any("frida-server -l 0.0.0.0" in c for c in calls)  # frida_host -> bind 0.0.0.0
    assert any("am force-stop com.example.app" in c for c in calls)


def test_setup_frida_server_without_frida_host_binds_localhost_only():
    calls = []

    def fake_shell(cmd: str) -> str:
        calls.append(cmd)
        return ""

    setup_frida_server(adb_args=[], package="com.example.app", shell_fn=fake_shell)

    server_start_cmd = next(c for c in calls if "nohup" in c)
    assert "-l 0.0.0.0" not in server_start_cmd


class _FakeStdin:
    def write(self, _data):
        pass

    def flush(self):
        pass


class _FakeFridaProc:
    """Simula el proceso `frida -H ... -f pkg -l script.js` -- termina solo
    (EOF en stdout) casi de inmediato, como un run exitoso corto."""

    def __init__(self, lines):
        self.stdin = _FakeStdin()
        self._lines = iter(lines)
        self._exited = False

    @property
    def stdout(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._lines) + "\n"
        except StopIteration:
            self._exited = True
            raise

    def poll(self):
        return 0 if self._exited else None

    def wait(self, timeout=None):
        return 0


def test_launch_frida_capture_with_shell_fn_never_touches_subprocess_for_device(tmp_path, monkeypatch):
    """Test de integración de launch_frida_capture completo (no solo
    setup_frida_server) con shell_fn/logcat_fn -- confirma que NINGÚN
    subprocess.run/Popen apunta a `adb` (solo el proceso de `frida` en sí,
    que siempre corre local vía el túnel TCP crudo del relay)."""
    shell_calls = []
    logcat_calls = []

    def fake_shell(cmd: str) -> str:
        shell_calls.append(cmd)
        return ""

    def fake_logcat(duration: float) -> str:
        logcat_calls.append(duration)
        return "09-01 12:00:00.000 W SSL: some warning\n"

    popen_calls = []

    def fake_popen(cmd, **kwargs):
        popen_calls.append(cmd)
        return _FakeFridaProc(["Spawned `com.example.app`", "[*] hook installed"])

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    with patch("subprocess.run") as mock_run:
        result = launch_frida_capture(
            package="com.example.app",
            script_js="console.log('hi');",
            frida_host="127.0.0.1:27042",
            duration=1,
            shell_fn=fake_shell,
            logcat_fn=fake_logcat,
        )

    # Ni un solo subprocess.run (adb) -- todo pasó por shell_fn/logcat_fn.
    mock_run.assert_not_called()
    # El único Popen real es el del binario `frida` -- ninguno para logcat/adb.
    assert len(popen_calls) == 1
    assert popen_calls[0][0].endswith("frida")
    assert "-H" in popen_calls[0] and "127.0.0.1:27042" in popen_calls[0]

    assert "hook installed" in result.output
    assert logcat_calls == [6.0]  # duration(1) + 5, ver docstring de logcat_fn
    assert "SSL: some warning" in result.logcat
    # pidof final también pasó por shell_fn, no por un adb local
    assert any(c.startswith("pidof ") for c in shell_calls)


def test_setup_frida_server_without_shell_fn_keeps_old_behavior(monkeypatch):
    """Sin shell_fn (default None) -- comportamiento de siempre: shellea a un
    adb real vía subprocess.run. Cero cambios para CLI/jobs existentes."""
    calls = []
    monkeypatch.setattr(
        "subprocess.run",
        lambda cmd, **kw: calls.append(cmd) or type("R", (), {"returncode": 0})(),
    )

    result = setup_frida_server(adb_args=["adb", "-s", "ABC"], package="com.example.app")

    assert result is True
    assert len(calls) == 3  # killall, start server, force-stop
    assert calls[0][:3] == ["adb", "-s", "ABC"]
