"""Tests de nutcracker_core/toolbox/relay_adb_shim/adb -- el shim de `adb`
que intercepta llamadas (vía PATH, ver queue/engine.py::_run_job) para jobs
con relay activo, y las traduce a RPC contra el dashboard (ver plan.md,
"Feature: relay browser-as-bridge").

Se invoca el shim como un subproceso REAL (no se importa como módulo Python,
porque en producción se ejecuta directo vía PATH/shutil.which, con un
shebang) contra un servidor HTTP real de juguete que hace de dashboard.
"""

from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

_SHIM_PATH = str(
    Path(__file__).resolve().parent.parent
    / "nutcracker_core" / "toolbox" / "relay_adb_shim" / "adb"
)


class _FakeDashboardHandler(http.server.BaseHTTPRequestHandler):
    # Poblado por el fixture antes de cada request -- ver `fake_dashboard`.
    response_status: int = 200
    response_body: dict = {}
    seen_requests: list = []

    def do_POST(self):  # noqa: N802 -- nombre requerido por BaseHTTPRequestHandler
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        type(self).seen_requests.append({
            "path": self.path,
            "body": json.loads(raw),
            "headers": dict(self.headers),
        })
        body = json.dumps(type(self).response_body).encode("utf-8")
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 -- silenciar logs del test
        pass


@pytest.fixture
def fake_dashboard():
    _FakeDashboardHandler.response_status = 200
    _FakeDashboardHandler.response_body = {}
    _FakeDashboardHandler.seen_requests = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _FakeDashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _run_shim(argv: list[str], env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, _SHIM_PATH, *argv],
        env=env, capture_output=True, text=True, timeout=10,
    )


def _run_shim_bytes(argv: list[str], env: dict) -> subprocess.CompletedProcess:
    """Como _run_shim, pero sin decodificar stdout como texto -- necesario
    para exec-out screencap, que escribe bytes PNG crudos (decodificarlos
    como UTF-8 los corrompería, el mismo motivo por el que el shim usa
    sys.stdout.buffer.write() en vez de sys.stdout.write())."""
    return subprocess.run(
        [sys.executable, _SHIM_PATH, *argv],
        env=env, capture_output=True, text=False, timeout=10,
    )


def test_shell_round_trip_propagates_stdout_stderr_exit_code(fake_dashboard):
    server, url = fake_dashboard
    _FakeDashboardHandler.response_body = {
        "stdout": "package:com.example.app\n", "stderr": "", "exit_code": 0,
    }

    result = _run_shim(
        ["-s", "device-1", "shell", "pm", "list", "packages", "com.example.app"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    assert result.stdout == "package:com.example.app\n"
    assert len(_FakeDashboardHandler.seen_requests) == 1
    req = _FakeDashboardHandler.seen_requests[0]
    assert req["path"] == "/api/relay/device-1/rpc/shell"
    # adb real junta con espacios los tokens después de "shell" -- se replica
    # el mismo comportamiento.
    assert req["body"]["command"] == "pm list packages com.example.app"


# ── Header de auth (bug real reportado en vivo, 2026-08-05) ────────────────
# Con dashboard.auth.enabled (login), el middleware protege /api/* completo
# -- este shim nunca mandaba ningún header de auth, así que cada RPC le
# devolvía 401 en silencio. check_app_installed() (aipwn.py), que solo mira
# stdout, interpretaba eso como "app no instalada" pese a que la sesión de
# relay estaba perfectamente conectada. Confirmado en vivo contra un servidor
# uvicorn real con auth activado antes de escribir este test: sin el header,
# 401; con el header (NUTCRACKER_DASHBOARD_TOKEN), pasa la auth limpio.

def test_shell_sends_internal_token_header_when_env_var_set(fake_dashboard):
    server, url = fake_dashboard
    _FakeDashboardHandler.response_body = {"stdout": "", "stderr": "", "exit_code": 0}

    _run_shim(
        ["-s", "device-1", "shell", "echo", "hi"],
        env={
            "NUTCRACKER_DASHBOARD_URL": url,
            "NUTCRACKER_RELAY_SESSION_ID": "device-1",
            "NUTCRACKER_DASHBOARD_TOKEN": "test-token-abc123",
        },
    )

    assert len(_FakeDashboardHandler.seen_requests) == 1
    headers = _FakeDashboardHandler.seen_requests[0]["headers"]
    assert headers.get("X-Nutcracker-Token") == "test-token-abc123"


def test_shell_omits_token_header_when_env_var_absent(fake_dashboard):
    """Retrocompatibilidad: sin dashboard.auth (uso local/dev), la env var no
    existe y el shim no debe mandar ningún header inventado."""
    server, url = fake_dashboard
    _FakeDashboardHandler.response_body = {"stdout": "", "stderr": "", "exit_code": 0}

    _run_shim(
        ["-s", "device-1", "shell", "echo", "hi"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    headers = _FakeDashboardHandler.seen_requests[0]["headers"]
    assert "X-Nutcracker-Token" not in headers


def test_shell_propagates_nonzero_exit_code_from_device(fake_dashboard):
    server, url = fake_dashboard
    _FakeDashboardHandler.response_body = {"stdout": "", "stderr": "no such package\n", "exit_code": 1}

    result = _run_shim(
        ["-s", "device-1", "shell", "pm", "path", "com.nope"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 1
    assert result.stderr == "no such package\n"


def test_shell_without_dash_s_prefix_still_works(fake_dashboard):
    """Algunos call sites del proyecto arman argv sin -s cuando serial es
    None -- el shim no debe asumir que -s siempre está presente."""
    server, url = fake_dashboard
    _FakeDashboardHandler.response_body = {"stdout": "ok\n", "stderr": "", "exit_code": 0}

    result = _run_shim(
        ["shell", "echo", "ok"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    assert result.stdout == "ok\n"


def test_single_pre_quoted_command_token_is_not_mangled(fake_dashboard):
    """Patrón real usado en frida_capture.py: un solo token ya armado con
    comillas propias para el shell remoto (`su -c '...'`) -- el join con
    espacios de múltiples tokens no debe alterar un token único."""
    server, url = fake_dashboard
    _FakeDashboardHandler.response_body = {"stdout": "", "stderr": "", "exit_code": 0}

    result = _run_shim(
        ["-s", "device-1", "shell", "su -c 'killall frida-server'"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    req = _FakeDashboardHandler.seen_requests[0]
    assert req["body"]["command"] == "su -c 'killall frida-server'"


def test_unsupported_subcommand_fails_explicitly_not_silently(fake_dashboard):
    """`push`/`logcat` (streaming continuo) siguen sin implementar -- a
    diferencia de shell/install/pull/exec-out screencap (Etapas 1-4)."""
    server, url = fake_dashboard

    result = _run_shim(
        ["-s", "device-1", "push", "/tmp/local.txt", "/data/local/tmp/remote.txt"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 2
    assert "push" in result.stderr
    assert "todavía no soportado" in result.stderr
    # No debe haber llegado a pegarle al dashboard -- falla antes, local.
    assert _FakeDashboardHandler.seen_requests == []


def test_missing_env_vars_fails_with_clear_message():
    result = _run_shim(["-s", "device-1", "shell", "echo", "hi"], env={})

    assert result.returncode == 1
    assert "NUTCRACKER_DASHBOARD_URL" in result.stderr


def test_http_error_from_dashboard_surfaces_detail(fake_dashboard):
    server, url = fake_dashboard
    _FakeDashboardHandler.response_status = 502
    _FakeDashboardHandler.response_body = {"detail": "createSocket falló: device offline"}

    result = _run_shim(
        ["-s", "device-1", "shell", "pm", "list", "packages"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 1
    assert "device offline" in result.stderr


def test_unreachable_dashboard_fails_with_clear_message():
    import socket

    # Puerto libre pero sin nada escuchando -- da ECONNREFUSED casi al
    # instante (a diferencia de un puerto privilegiado como el 1, que en
    # este sandbox se queda colgado sin responder en vez de rechazar rápido).
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()

    result = _run_shim(
        ["-s", "device-1", "shell", "echo", "hi"],
        env={
            "NUTCRACKER_DASHBOARD_URL": f"http://127.0.0.1:{free_port}",
            "NUTCRACKER_RELAY_SESSION_ID": "device-1",
        },
    )

    assert result.returncode == 1
    assert "no se pudo contactar" in result.stderr


# ── install / install-multiple (Etapa 2, 2026-08-04) ────────────────────────

def test_install_single_apk_reads_local_file_and_propagates_result(fake_dashboard, tmp_path):
    server, url = fake_dashboard
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04fake-apk-bytes")
    _FakeDashboardHandler.response_body = {"stdout": "Success\n", "stderr": "", "exit_code": 0}

    result = _run_shim(
        ["-s", "device-1", "install", "-r", "-d", str(apk)],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    assert result.stdout == "Success\n"
    req = _FakeDashboardHandler.seen_requests[0]
    assert req["path"] == "/api/relay/device-1/rpc/install"
    assert req["body"]["flags"] == ["-r", "-d"]
    assert req["body"]["multi"] is False
    assert len(req["body"]["apks"]) == 1
    assert req["body"]["apks"][0]["name"] == "app.apk"
    import base64
    assert base64.b64decode(req["body"]["apks"][0]["data_b64"]) == b"PK\x03\x04fake-apk-bytes"


def test_install_multiple_sends_all_apks_with_multi_flag(fake_dashboard, tmp_path):
    server, url = fake_dashboard
    base_apk = tmp_path / "base.apk"
    split_apk = tmp_path / "split_config.arm64_v8a.apk"
    base_apk.write_bytes(b"base-bytes")
    split_apk.write_bytes(b"split-bytes")
    _FakeDashboardHandler.response_body = {"stdout": "Success\n", "stderr": "", "exit_code": 0}

    result = _run_shim(
        ["-s", "device-1", "install-multiple", "-r", "-t", "-d", str(base_apk), str(split_apk)],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    req = _FakeDashboardHandler.seen_requests[0]
    assert req["body"]["multi"] is True
    assert req["body"]["flags"] == ["-r", "-t", "-d"]
    assert [a["name"] for a in req["body"]["apks"]] == ["base.apk", "split_config.arm64_v8a.apk"]


def test_install_missing_local_apk_fails_before_contacting_dashboard(fake_dashboard):
    server, url = fake_dashboard

    result = _run_shim(
        ["-s", "device-1", "install", "-r", "-d", "/no/existe/app.apk"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 1
    assert "no se pudo leer" in result.stderr
    assert _FakeDashboardHandler.seen_requests == []


def test_install_nonzero_exit_code_propagates(fake_dashboard, tmp_path):
    server, url = fake_dashboard
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"fake")
    _FakeDashboardHandler.response_body = {
        "stdout": "", "stderr": "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]\n", "exit_code": 1,
    }

    result = _run_shim(
        ["-s", "device-1", "install", "-r", "-d", str(apk)],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 1
    assert "INSUFFICIENT_STORAGE" in result.stderr


# ── pull (Etapa 4) ────────────────────────────────────────────────────────

def test_pull_writes_bytes_to_local_path_and_exits_zero(fake_dashboard, tmp_path):
    import base64

    server, url = fake_dashboard
    local_path = tmp_path / "libh5t5cr7.so"
    file_bytes = b"\x7fELF" + b"native-lib-content" * 100
    _FakeDashboardHandler.response_body = {"data_b64": base64.b64encode(file_bytes).decode("ascii")}

    result = _run_shim(
        ["-s", "device-1", "pull", "/data/app/xyz/lib/arm64/libh5t5cr7.so", str(local_path)],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    assert local_path.read_bytes() == file_bytes
    req = _FakeDashboardHandler.seen_requests[0]
    assert req["path"] == "/api/relay/device-1/rpc/pull"
    assert req["body"]["remote_path"] == "/data/app/xyz/lib/arm64/libh5t5cr7.so"


def test_pull_requires_remote_and_local_args(fake_dashboard):
    server, url = fake_dashboard

    result = _run_shim(
        ["-s", "device-1", "pull", "/data/only-one-arg"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 1
    assert "requiere" in result.stderr
    assert _FakeDashboardHandler.seen_requests == []


# ── exec-out screencap -p (Etapa 3) ─────────────────────────────────────────

def test_exec_out_screencap_writes_raw_binary_to_stdout(fake_dashboard):
    import base64

    server, url = fake_dashboard
    png_bytes = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4  # incluye bytes no-UTF8 a proposito
    _FakeDashboardHandler.response_body = {"data_b64": base64.b64encode(png_bytes).decode("ascii")}

    result = _run_shim_bytes(
        ["-s", "device-1", "exec-out", "screencap", "-p"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    assert result.stdout == png_bytes
    req = _FakeDashboardHandler.seen_requests[0]
    assert req["path"] == "/api/relay/device-1/rpc/screencap"


def test_exec_out_unsupported_command_fails_explicitly(fake_dashboard):
    server, url = fake_dashboard

    result = _run_shim(
        ["-s", "device-1", "exec-out", "cat", "/data/local/tmp/secret"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 2
    assert "todavía no soportado" in result.stderr
    assert _FakeDashboardHandler.seen_requests == []


# ── logcat (Etapa 5, 2026-08-04) ─────────────────────────────────────────────
#
# `logcat -c` (limpiar) es un comando de una sola pasada -- se reenvía tal
# cual al RPC de 'shell' que ya existe. `logcat -v time ...` (streaming real
# en el device) es la parte nueva: NO es streaming línea-a-línea de verdad
# (aipwn solo consume el log DESPUÉS de la ventana de captura de todos
# modos) -- el navegador junta todo y lo devuelve en un solo RPC.

def test_logcat_clear_routes_through_shell_rpc(fake_dashboard):
    server, url = fake_dashboard
    _FakeDashboardHandler.response_body = {"stdout": "", "stderr": "", "exit_code": 0}

    result = _run_shim(
        ["-s", "device-1", "logcat", "-c"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    req = _FakeDashboardHandler.seen_requests[0]
    assert req["path"] == "/api/relay/device-1/rpc/shell"
    assert req["body"]["command"] == "logcat -c"


def test_logcat_streaming_mode_uses_dedicated_rpc_and_returns_captured_lines(fake_dashboard):
    server, url = fake_dashboard
    captured_lines = "08-04 15:00:00.000 W OkHttp: SSLPeerUnverifiedException\n"
    _FakeDashboardHandler.response_body = {"stdout": captured_lines}

    result = _run_shim(
        ["-s", "device-1", "logcat", "-v", "time", "*:W", "OkHttp:D", "SSL:E", "CONSCRYPT:E"],
        env={"NUTCRACKER_DASHBOARD_URL": url, "NUTCRACKER_RELAY_SESSION_ID": "device-1"},
    )

    assert result.returncode == 0
    assert result.stdout == captured_lines
    req = _FakeDashboardHandler.seen_requests[0]
    assert req["path"] == "/api/relay/device-1/rpc/logcat"
    assert req["body"]["args"] == ["-v", "time", "*:W", "OkHttp:D", "SSL:E", "CONSCRYPT:E"]
    assert req["body"]["duration_seconds"] == 30.0
