"""Tests de la integración del toolbox de Docker en leak_scanner.py
(apkleaks/gitleaks) -- ver nutcracker_core/toolbox/.

Opt-in: sin config (o con toolbox.enabled=false), debe comportarse
exactamente como antes (binarios locales vía shutil.which).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from nutcracker_core import leak_scanner as ls


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


# ── scan_with_apkleaks ───────────────────────────────────────────────────────

def test_scan_with_apkleaks_skips_without_local_bin_and_without_toolbox(monkeypatch, tmp_path):
    monkeypatch.setattr(ls.shutil, "which", lambda name: None)

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    assert ls.scan_with_apkleaks(apk) == []


def test_scan_with_apkleaks_uses_local_binary_without_toolbox(monkeypatch, tmp_path):
    monkeypatch.setattr(ls.shutil, "which", lambda name: "/usr/bin/apkleaks" if name == "apkleaks" else None)

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text(json.dumps({
            "results": [{"name": "Google_API_Key", "matches": ["AIzaSyABC123real_key_value_here"]}],
        }))
        return _completed(returncode=0)

    monkeypatch.setattr(ls.subprocess, "run", fake_run)

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    findings = ls.scan_with_apkleaks(apk)

    assert len(findings) == 1
    assert findings[0].rule_id.startswith("AL-")
    assert calls[0][0] == "/usr/bin/apkleaks"


def test_scan_with_apkleaks_routes_through_toolbox_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(ls.shutil, "which", lambda name: None)  # nada local
    monkeypatch.setattr(ls.toolbox, "is_enabled", lambda config: True)

    calls = []

    def fake_toolbox_run(tool, args, config=None, timeout=600, build_if_missing=True):  # noqa: ANN001
        calls.append((tool, args))
        out_path = Path(args[args.index("-o") + 1])
        out_path.write_text(json.dumps({
            "results": [{"name": "Firebase", "matches": ["AAAA:APA91b_real_looking_value"]}],
        }))
        return _completed(returncode=0)

    monkeypatch.setattr(ls.toolbox, "run", fake_toolbox_run)
    # scratch_dir real (no mockeado) -- confirma que el reporte queda bajo el
    # proyecto, no en /tmp del sistema (invisible dentro del contenedor).
    monkeypatch.setattr(ls.toolbox, "scratch_dir", lambda: tmp_path)

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    findings = ls.scan_with_apkleaks(apk, config={"toolbox": {"enabled": True}})

    assert len(findings) == 1
    assert calls[0][0] == "apkleaks"
    # el path de salida (-o) debe estar bajo el directorio que devuelve
    # scratch_dir(), no bajo /tmp del sistema.
    out_arg = Path(calls[0][1][calls[0][1].index("-o") + 1])
    assert out_arg.parent == tmp_path
    # las rutas de entrada (-f) deben ser absolutas
    f_arg = calls[0][1][calls[0][1].index("-f") + 1]
    assert Path(f_arg).is_absolute()


def test_scan_with_apkleaks_handles_nonzero_returncode(monkeypatch, tmp_path):
    monkeypatch.setattr(ls.shutil, "which", lambda name: "/usr/bin/apkleaks")
    monkeypatch.setattr(ls.subprocess, "run", lambda *a, **kw: _completed(returncode=2, stderr="boom"))

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    assert ls.scan_with_apkleaks(apk) == []


# ── scan_with_gitleaks ───────────────────────────────────────────────────────

def test_scan_with_gitleaks_skips_without_local_bin_and_without_toolbox(monkeypatch, tmp_path):
    monkeypatch.setattr(ls.shutil, "which", lambda name: None)
    assert ls.scan_with_gitleaks(tmp_path) == []


def test_scan_with_gitleaks_uses_local_binary_without_toolbox(monkeypatch, tmp_path):
    monkeypatch.setattr(ls.shutil, "which", lambda name: "/usr/bin/gitleaks" if name == "gitleaks" else None)

    calls = []

    def fake_run(cmd, capture_output=True, text=True, timeout=None):  # noqa: ANN001
        calls.append(cmd)
        out_path = Path(cmd[cmd.index("-r") + 1])
        out_path.write_text(json.dumps([
            {"RuleID": "aws-access-token", "Description": "AWS key", "Secret": "AKIA...",
             "File": "Foo.java", "StartLine": 42, "Entropy": 4.2},
        ]))
        return _completed(returncode=1)  # 1 = hallazgos encontrados

    monkeypatch.setattr(ls.subprocess, "run", fake_run)

    findings = ls.scan_with_gitleaks(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert calls[0][0] == "/usr/bin/gitleaks"


def test_scan_with_gitleaks_routes_through_toolbox_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(ls.shutil, "which", lambda name: None)
    monkeypatch.setattr(ls.toolbox, "is_enabled", lambda config: True)

    calls = []

    def fake_toolbox_run(tool, args, config=None, timeout=600, build_if_missing=True):  # noqa: ANN001
        calls.append((tool, args))
        out_path = Path(args[args.index("-r") + 1])
        out_path.write_text(json.dumps([
            {"RuleID": "generic-api-key", "Description": "generic", "Secret": "xyz",
             "File": "Bar.java", "StartLine": 1, "Entropy": 3.1},
        ]))
        return _completed(returncode=1)

    monkeypatch.setattr(ls.toolbox, "run", fake_toolbox_run)
    monkeypatch.setattr(ls.toolbox, "scratch_dir", lambda: tmp_path)

    source_dir = tmp_path / "decompiled_app"
    source_dir.mkdir()

    findings = ls.scan_with_gitleaks(source_dir, config={"toolbox": {"enabled": True}})

    assert len(findings) == 1
    assert calls[0][0] == "gitleaks"
    s_arg = calls[0][1][calls[0][1].index("-s") + 1]
    assert Path(s_arg).is_absolute()


def test_scan_with_gitleaks_treats_high_returncode_as_error(monkeypatch, tmp_path):
    monkeypatch.setattr(ls.shutil, "which", lambda name: "/usr/bin/gitleaks")
    monkeypatch.setattr(ls.subprocess, "run", lambda *a, **kw: _completed(returncode=2, stderr="boom"))

    assert ls.scan_with_gitleaks(tmp_path) == []
