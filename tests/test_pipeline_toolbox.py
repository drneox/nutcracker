"""Test de nutcracker_core/pipeline.py::try_gadget_inject -- mismo bug de
toolbox encontrado en vivo (2026-08-05) que en decompiler.py/analyzer.py/
deobfuscator.py: exigía SIEMPRE el binario local de apktool, incluso con
``toolbox.enabled: true`` en config.yaml. Corrido con mocks pesados en los
puntos externos (adb, descarga del gadget, firma) -- lo que importa acá es
que las DOS invocaciones de apktool (decompilar + reempaquetar) ruteen por
``toolbox.run()`` en vez de exigir el binario local, no la mecánica completa
de inyección del gadget."""

from __future__ import annotations

import lzma
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from nutcracker_core import pipeline, toolbox


@pytest.fixture
def toolbox_calls(monkeypatch):
    """Reemplaza toolbox.run() -- solo entiende "apktool d" (crea una
    estructura smali mínima con una clase Application, para que el parcheo en
    Python de try_gadget_inject encuentre algo que patchear) y "apktool b"
    (crea un .zip válido mínimo, porque el código siguiente lo vuelve a abrir
    con zipfile). Cualquier otra tool no debería invocarse -- lanza si pasa."""
    calls: list[tuple[str, list[str]]] = []

    def fake_run(tool, args, config=None, timeout=600, build_if_missing=True):
        calls.append((tool, list(args)))
        if tool != "apktool":
            raise AssertionError(f"tool inesperada vía toolbox: {tool}")
        if args[0] == "d":
            decompiled_dir = Path(args[3])  # ["d", apk, "-o", decompiled_dir, ...]
            smali_dir = decompiled_dir / "smali"
            smali_dir.mkdir(parents=True, exist_ok=True)
            (smali_dir / "MyApp.smali").write_text(
                ".class public LMyApp;\n"
                ".super Landroid/app/Application;\n"
                ".method public constructor <init>()V\n"
                ".end method\n"
            )
        elif args[0] == "b":
            out_path = Path(args[3])  # ["b", decompiled_dir, "-o", out_path]
            with zipfile.ZipFile(out_path, "w") as z:
                z.writestr("classes.dex", b"fake")
        return subprocess.CompletedProcess([tool, *args], 0, stdout="", stderr="")

    monkeypatch.setattr(toolbox, "run", fake_run)
    monkeypatch.setattr(pipeline.toolbox, "run", fake_run)
    return calls


def _mock_common_externals(monkeypatch, tmp_path):
    """Mockea todo lo que try_gadget_inject necesita que NO sea apktool:
    detección de ABI (adb), descarga+descompresión del gadget de frida
    (urlretrieve real reemplazado, pero con bytes lzma REALES para no tener
    que mockear lzma también), apksigner/keystore/sdk, y hace que el paso de
    firma final falle limpio -- eso corta la función con `return None` justo
    DESPUÉS de las dos invocaciones de apktool que este test verifica,
    sin necesitar mockear reinstalación/dexdump/etc."""
    monkeypatch.setattr("nutcracker_core.device.find_sdk_root", lambda: tmp_path / "sdk")

    fake_apksigner = tmp_path / "apksigner"
    fake_apksigner.write_text("#!/bin/sh\n")
    monkeypatch.setattr("nutcracker_core.apk_tools.find_apksigner", lambda sdk: str(fake_apksigner))

    fake_keystore = tmp_path / "debug.keystore"
    fake_keystore.write_bytes(b"fake")
    monkeypatch.setattr("nutcracker_core.apk_tools.ensure_debug_keystore", lambda: fake_keystore)

    def fake_subprocess_run(cmd, capture_output=True, text=True, timeout=None):
        if "getprop" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="arm64-v8a\n", stderr="")
        if cmd[0] == str(fake_apksigner) and "sign" in cmd:
            # Falla a propósito -- corta la función limpio DESPUÉS de que ya
            # pasaron las dos invocaciones de apktool que interesa verificar.
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="firma simulada falló")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)

    def fake_urlretrieve(url, dest):
        Path(dest).write_bytes(lzma.compress(b"fake-gadget-so-bytes"))

    monkeypatch.setattr("urllib.request.urlretrieve", fake_urlretrieve)


def test_try_gadget_inject_routes_apktool_through_toolbox(monkeypatch, tmp_path, toolbox_calls):
    monkeypatch.chdir(tmp_path)
    _mock_common_externals(monkeypatch, tmp_path)
    # Sin binario local de apktool -- solo el toolbox debe hacer que esto
    # funcione (ver toolbox.is_enabled en el fix).
    monkeypatch.setattr(shutil, "which", lambda name: None)

    apk_path = tmp_path / "app.apk"
    apk_path.write_bytes(b"PK\x03\x04fake")

    pipeline.try_gadget_inject(
        apk_path=apk_path,
        serial="emulator-5554",
        sdk_tools={"adb": "adb"},
        package="com.example.app",
        dump_dir=tmp_path / "dump",
        with_spinner=None,
        cfg={"toolbox": {"enabled": True}},
    )

    apktool_calls = [c for c in toolbox_calls if c[0] == "apktool"]
    assert len(apktool_calls) == 2, f"esperaba 2 invocaciones de apktool vía toolbox, hubo {apktool_calls}"
    assert apktool_calls[0][1][0] == "d"
    assert apktool_calls[1][1][0] == "b"


def test_try_gadget_inject_work_dir_lives_under_scratch_dir_with_toolbox(
    monkeypatch, tmp_path, toolbox_calls,
):
    """work_dir tiene que quedar bajo Path.cwd()/.nutcracker_tmp -- si quedara
    bajo /tmp del sistema (tempfile.mkdtemp() a secas), el contenedor del
    toolbox no podría leer/escribir ahí (solo monta Path.cwd())."""
    monkeypatch.chdir(tmp_path)
    _mock_common_externals(monkeypatch, tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    orig_calls = toolbox_calls

    apk_path = tmp_path / "app.apk"
    apk_path.write_bytes(b"PK\x03\x04fake")

    pipeline.try_gadget_inject(
        apk_path=apk_path,
        serial="emulator-5554",
        sdk_tools={"adb": "adb"},
        package="com.example.app",
        dump_dir=tmp_path / "dump",
        with_spinner=None,
        cfg={"toolbox": {"enabled": True}},
    )

    d_call = next(c for c in orig_calls if c[0] == "apktool" and c[1][0] == "d")
    decompiled_dir = Path(d_call[1][3])
    scratch = toolbox.scratch_dir()
    assert scratch in decompiled_dir.parents, (
        f"{decompiled_dir} no está bajo {scratch} -- invisible para el contenedor del toolbox"
    )
