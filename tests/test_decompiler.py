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

    monkeypatch.setattr(decompiler, "_find_tool", lambda name: f"/usr/bin/{name}" if name == "jadx" else None)

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
    monkeypatch.setattr(decompiler, "_find_tool", lambda name: "/usr/bin/apktool" if name == "apktool" else None)

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
    monkeypatch.setattr(decompiler, "_find_tool", lambda name: "/usr/bin/apktool" if name == "apktool" else None)

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
