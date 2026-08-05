"""Tests de nutcracker_core/decompiler.py.

Bug encontrado en vivo (2026-07-28): apkeep guarda el APK base de un Android
App Bundle literalmente como "base.apk" para *cualquier* paquete -- con el
directorio de salida nombrado por `apk_path.stem` (el comportamiento previo a
este fix), dos jobs estáticos concurrentes de paquetes distintos (ambos
descargados como "base.apk") decompilaban hacia el mismo "decompiled/base/" y
se pisaban entre sí. Confirmado con datos reales: 3 apps bancarias reales
encoladas en el mismo segundo, todas con `downloads/<pkg>/base.apk`, todas
decompilando hacia "decompiled/base" -- una de ellas terminó con
"files_scanned: 0" pese a que apktool corrido a mano contra su APK generaba
30k+ archivos smali sin problema.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from nutcracker_core import decompiler


def _completed(returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout="", stderr=stderr)


@pytest.fixture
def fake_jadx(monkeypatch):
    """jadx "disponible" que solo registra el comando y crea un .java falso en
    el dest recibido, para verificar en qué directorio termina escribiendo."""
    calls = []

    monkeypatch.setattr(decompiler, "_find_tool", lambda name, config=None: f"/usr/bin/{name}" if name == "jadx" else None)

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        dest = Path(cmd[cmd.index("-d") + 1])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "Main.java").write_text("// noop")
        return _completed()

    monkeypatch.setattr(decompiler.subprocess, "run", fake_run)
    return calls


def test_decompile_uses_dest_name_not_apk_stem(tmp_path, fake_jadx):
    """El caso central del bug: dos paquetes distintos, mismo nombre de
    archivo ("base.apk"), deben terminar en directorios DISTINTOS cuando se
    pasa dest_name."""
    apk_a = tmp_path / "pkg_a" / "base.apk"
    apk_b = tmp_path / "pkg_b" / "base.apk"
    apk_a.parent.mkdir(parents=True)
    apk_b.parent.mkdir(parents=True)
    apk_a.write_bytes(b"PK\x03\x04")
    apk_b.write_bytes(b"PK\x03\x04")

    output_dir = tmp_path / "decompiled"

    dest_a = decompiler.decompile(apk_a, output_dir, dest_name="com.example.a")
    dest_b = decompiler.decompile(apk_b, output_dir, dest_name="com.example.b")

    assert dest_a != dest_b
    assert dest_a.name == "com.example.a"
    assert dest_b.name == "com.example.b"
    assert dest_a.exists() and dest_b.exists()
    # ambos conservan su propio contenido -- ninguno se pisó al otro
    assert (dest_a / "Main.java").exists()
    assert (dest_b / "Main.java").exists()


def test_decompile_without_dest_name_falls_back_to_apk_stem(tmp_path, fake_jadx):
    """Compatibilidad hacia atrás: sin dest_name explícito, se comporta como
    antes (nombrado por el archivo)."""
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")

    dest = decompiler.decompile(apk, tmp_path / "decompiled")

    assert dest.name == "base"


def test_decompile_two_base_apks_without_dest_name_would_collide(tmp_path, fake_jadx):
    """Documenta el bug tal cual se manifestaba antes del fix: sin dest_name,
    dos paquetes distintos con el mismo nombre de archivo terminan en el
    MISMO directorio -- la razón real detrás de "files_scanned: 0" en runs
    concurrentes."""
    apk_a = tmp_path / "pkg_a" / "base.apk"
    apk_b = tmp_path / "pkg_b" / "base.apk"
    apk_a.parent.mkdir(parents=True)
    apk_b.parent.mkdir(parents=True)
    apk_a.write_bytes(b"PK\x03\x04")
    apk_b.write_bytes(b"PK\x03\x04")

    output_dir = tmp_path / "decompiled"
    dest_a = decompiler.decompile(apk_a, output_dir)
    dest_b = decompiler.decompile(apk_b, output_dir)

    assert dest_a == dest_b, "ambos deberían colisionar en decompiled/base sin dest_name"


def test_decompile_apktool_fallback_uses_dest_name(tmp_path, monkeypatch):
    """El fallback a apktool (cuando jadx no está instalado, como en este
    entorno) también debe respetar dest_name."""
    monkeypatch.setattr(decompiler, "_find_tool", lambda name, config=None: "/usr/bin/apktool" if name == "apktool" else None)

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        dest = Path(cmd[cmd.index("-o") + 1])
        dest.mkdir(parents=True, exist_ok=True)
        return _completed()

    monkeypatch.setattr(decompiler.subprocess, "run", fake_run)

    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")

    dest = decompiler.decompile(apk, tmp_path / "decompiled", dest_name="com.example.app")

    assert dest.name == "com.example.app"
    assert "-o" in calls[0] and str(dest) in calls[0]


def test_extract_manifest_uses_name_hint_not_apk_stem(tmp_path, monkeypatch):
    """Mismo bug, mismo fix, para el extractor de manifest usado en el flujo
    de runtime dump (Frida) sin manifest disponible."""
    monkeypatch.setattr(decompiler, "_find_tool", lambda name, config=None: "/usr/bin/apktool" if name == "apktool" else None)

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        dest = Path(cmd[cmd.index("-o") + 1])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "AndroidManifest.xml").write_text("<manifest/>")
        return _completed()

    monkeypatch.setattr(decompiler.subprocess, "run", fake_run)

    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")

    result = decompiler.extract_manifest(apk, tmp_path, name_hint="runtime_dump_com.example.app")

    assert result is not None
    assert "runtime_dump_com.example.app" in str(result)


# ── Toolbox de Docker (opt-in vía config.yaml: toolbox.enabled) ─────────────

def test_get_available_tool_prefers_toolbox_when_enabled(monkeypatch):
    """Con toolbox.enabled=true, jadx "está disponible" sin necesitar el
    binario en el host -- lo garantiza la imagen. Sentinel TOOLBOX, no un
    shutil.which() real."""
    monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)  # nada instalado local

    tool, path = decompiler.get_available_tool({"toolbox": {"enabled": True}})

    assert tool == "jadx"
    assert path is decompiler.TOOLBOX


def test_get_available_tool_ignores_toolbox_when_disabled(monkeypatch):
    monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)

    tool, path = decompiler.get_available_tool({"toolbox": {"enabled": False}})

    assert (tool, path) == (None, None)


def test_decompile_routes_through_toolbox_run_when_enabled(tmp_path, monkeypatch):
    """Con el toolbox habilitado, decompile() no debe tocar subprocess.run
    directo -- todo pasa por toolbox.run()."""
    monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)

    calls = []

    def fake_toolbox_run(tool, args, config=None, timeout=600, build_if_missing=True):  # noqa: ANN001
        calls.append((tool, args))
        dest = Path(args[args.index("-d") + 1])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "Main.java").write_text("// noop")
        return decompiler.subprocess.CompletedProcess([], 0, stdout="", stderr="")

    monkeypatch.setattr(decompiler.toolbox, "run", fake_toolbox_run)

    def boom(*a, **kw):  # noqa: ANN001
        raise AssertionError("no debería llamar a subprocess.run local con el toolbox habilitado")

    monkeypatch.setattr(decompiler.subprocess, "run", boom)

    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")

    dest = decompiler.decompile(
        apk, tmp_path / "decompiled", dest_name="com.example.app",
        config={"toolbox": {"enabled": True}},
    )

    assert dest.name == "com.example.app"
    assert calls and calls[0][0] == "jadx"
    # las rutas que le llegan a toolbox.run() deben ser absolutas -- el
    # contenedor monta Path.cwd() en la misma ruta que el host, así que una
    # ruta relativa no resolvería del mismo lado.
    assert Path(calls[0][1][calls[0][1].index("-d") + 1]).is_absolute()
    assert Path(calls[0][1][-1]).is_absolute()


def test_decompile_falls_back_to_apktool_via_toolbox_on_jadx_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)

    calls = []

    def fake_toolbox_run(tool, args, config=None, timeout=600, build_if_missing=True):  # noqa: ANN001
        calls.append(tool)
        if tool == "jadx":
            return decompiler.subprocess.CompletedProcess([], 1, stdout="", stderr="jadx explotó")
        dest = Path(args[args.index("-o") + 1])
        dest.mkdir(parents=True, exist_ok=True)
        return decompiler.subprocess.CompletedProcess([], 0, stdout="", stderr="")

    monkeypatch.setattr(decompiler.toolbox, "run", fake_toolbox_run)

    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")

    dest = decompiler.decompile(
        apk, tmp_path / "decompiled", dest_name="com.example.app",
        config={"toolbox": {"enabled": True}},
    )

    assert calls == ["jadx", "apktool"]
    assert dest.name == "com.example.app"


def test_decompile_wraps_toolbox_error_as_decompiler_error(tmp_path, monkeypatch):
    monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)

    def boom(*a, **kw):  # noqa: ANN001
        raise decompiler.toolbox.ToolboxError("docker no está instalado")

    monkeypatch.setattr(decompiler.toolbox, "run", boom)

    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")

    with pytest.raises(decompiler.DecompilerError, match="docker no está instalado"):
        decompiler.decompile(apk, tmp_path / "decompiled", config={"toolbox": {"enabled": True}})


def test_decompile_without_toolbox_config_behaves_exactly_as_before(tmp_path, fake_jadx):
    """config=None (default) no debe activar el toolbox bajo ninguna
    circunstancia -- comportamiento 100% preexistente."""
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")

    dest = decompiler.decompile(apk, tmp_path / "decompiled")

    assert dest.name == "base"
    assert fake_jadx  # subprocess.run local sí se usó


# ── install_instructions() ajustado por plataforma ──────────────────────────
# Bug encontrado en vivo (2026-08-05, job real en una VM Ubuntu): el mensaje
# de "no hay decompilador" sugería SIEMPRE "brew install jadx" (Homebrew,
# macOS) sin importar la plataforma real -- inútil en Linux/WSL/un VPS.

def test_install_instructions_macos_suggests_brew(monkeypatch):
    monkeypatch.setattr(decompiler.platform, "system", lambda: "Darwin")
    msg = decompiler.install_instructions()
    assert "brew install jadx" in msg
    assert "brew install apktool" in msg


def test_install_instructions_linux_does_not_suggest_brew(monkeypatch):
    monkeypatch.setattr(decompiler.platform, "system", lambda: "Linux")
    msg = decompiler.install_instructions()
    assert "brew install" not in msg
    assert "github.com/skylot/jadx/releases" in msg


def test_install_instructions_always_mentions_toolbox(monkeypatch):
    """El toolbox de Docker es cross-platform -- debe sugerirse sin importar
    el sistema operativo detectado, siempre como primera opción."""
    for system in ("Darwin", "Linux", "Windows"):
        monkeypatch.setattr(decompiler.platform, "system", lambda s=system: s)
        msg = decompiler.install_instructions()
        assert "toolbox" in msg.lower()
        assert "docker" in msg.lower()


def test_decompile_error_uses_install_instructions(tmp_path, monkeypatch):
    """DecompilerError (sin ningún tool disponible) debe compartir el mismo
    texto que install_instructions() -- no un mensaje hardcodeado aparte que
    pueda quedar desactualizado."""
    monkeypatch.setattr(decompiler.shutil, "which", lambda name: None)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    with pytest.raises(decompiler.DecompilerError) as exc_info:
        decompiler.decompile(apk, tmp_path / "decompiled")

    assert str(exc_info.value) == decompiler.install_instructions()
