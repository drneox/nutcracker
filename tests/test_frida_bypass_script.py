"""Tests de nutcracker_core/frida_bypass.py::generate_bypass_script -- el
script heurístico base que aipwn usa vía extend_heuristic_base=True.
"""

from __future__ import annotations

import datetime
import shutil
import subprocess
from pathlib import Path

import pytest

from nutcracker_core.analyzer import AnalysisResult
from nutcracker_core.frida_bypass import generate_bypass_script


def _make_result(package: str = "com.example.app") -> AnalysisResult:
    return AnalysisResult(
        package=package, results=[], version_name="1.0", version_code=1,
        min_sdk=21, target_sdk=33, analyzed_at=datetime.datetime.now(),
    )


def _generated_script(tmp_path: Path) -> str:
    out = generate_bypass_script(_make_result(), tmp_path)
    return out.read_text()


# ── Skip de hooks GMS ausentes (2026-08-04) ─────────────────────────────────
#
# Bug encontrado en vivo (job 2823, sh.nutcracker.nutbank en un emulador
# AOSP): los 4 hooks de Google Play Services (GoogleApiAvailability,
# GoogleApiAvailabilityLight, DeferredLifecycleHelper,
# GooglePlayServicesUtilLight) intentaban Java.use() cada uno por separado y
# fallaban los 4 con ClassNotFoundException idéntico, ensuciando
# hooks_fallidos con ruido repetido en cada corrida sin GMS instalado.

def test_gms_hooks_are_gated_behind_a_single_availability_check(tmp_path):
    script = _generated_script(tmp_path)
    assert "_gmsAvailable" in script
    # El chequeo "ancla" tiene que aparecer ANTES de los 4 bloques que gatea.
    anchor_idx = script.index("_gmsAvailable = true")
    for marker in (
        "GmsAvail.isGooglePlayServicesAvailable",
        "GmsAvailLight.isGooglePlayServicesAvailable",
        "DeferredHelper.showGooglePlayUnavailableMessage",
        "UtilLight.isGooglePlayServicesAvailable",
    ):
        assert script.index(marker) > anchor_idx


def test_gms_hook_blocks_are_wrapped_in_availability_conditional(tmp_path):
    script = _generated_script(tmp_path)
    gate_idx = script.index("if (_gmsAvailable) {")
    last_hook_idx = script.index("GooglePlayServicesUtilLight hooked")
    assert gate_idx < last_hook_idx


@pytest.mark.skipif(shutil.which("node") is None, reason="node no disponible en este entorno")
def test_generated_script_is_syntactically_valid_js(tmp_path):
    script_path = generate_bypass_script(_make_result(), tmp_path)
    result = subprocess.run(
        ["node", "--check", str(script_path)], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
