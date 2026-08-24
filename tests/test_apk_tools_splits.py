"""Tests de find_split_apks — sets coherentes por generación de nombres.

Bug (visto en vivo, job 20, 2026-08-23): downloads/com.krealo.tenpo/ tenía
DOS descargas de distinta fecha — apkeep nuevo (com.krealo.tenpo.apk +
com.krealo.tenpo.config.*) y la clásica (base.apk + split_config.*) — y
find_split_apks devolvía la UNION (7 APKs), que install-multiple rechaza con
INSTALL_FAILED_INVALID_APK: "Split null was defined multiple times". Con el
set coherente de su propia generación la instalación funciona.
"""

from __future__ import annotations

from nutcracker_core.apk_tools import find_split_apks


def _touch(dirpath, *names):
    for n in names:
        (dirpath / n).touch()


def test_mixed_generations_pick_the_apks_own_generation(tmp_path):
    """El caso del job 20: dos generaciones conviviendo en el mismo dir."""
    _touch(
        tmp_path,
        "com.foo.app.apk",                      # base generación apkeep nueva
        "com.foo.app.config.arm64_v8a.apk",
        "com.foo.app.config.en.apk",
        "com.foo.app.config.xxhdpi.apk",
        "base.apk",                             # base generación clásica
        "split_config.arm64_v8a.apk",
        "split_config.en.apk",
        "split_config.xxhdpi.apk",
    )

    result = find_split_apks(tmp_path / "com.foo.app.apk")

    names = {p.name for p in result}
    assert names == {
        "com.foo.app.apk",
        "com.foo.app.config.arm64_v8a.apk",
        "com.foo.app.config.en.apk",
        "com.foo.app.config.xxhdpi.apk",
    }


def test_mixed_generations_base_apk_picks_split_config_generation(tmp_path):
    _touch(
        tmp_path,
        "com.foo.app.apk",
        "com.foo.app.config.arm64_v8a.apk",
        "base.apk",
        "split_config.arm64_v8a.apk",
        "split_config.en.apk",
    )

    result = find_split_apks(tmp_path / "base.apk")

    names = {p.name for p in result}
    assert names == {"base.apk", "split_config.arm64_v8a.apk", "split_config.en.apk"}


def test_single_generation_collects_its_splits(tmp_path):
    _touch(tmp_path, "com.foo.app.apk", "com.foo.app.config.arm64_v8a.apk")

    result = find_split_apks(tmp_path / "com.foo.app.apk")

    assert {p.name for p in result} == {"com.foo.app.apk", "com.foo.app.config.arm64_v8a.apk"}


def test_generic_splits_fallback_when_no_same_generation(tmp_path):
    """Un apk suelto junto a splits genéricos (sin prefijo propio) sigue
    encontrándolos por el fallback viejo."""
    _touch(tmp_path, "com.foo.app.apk", "split_config.arm64_v8a.apk", "split_config.en.apk")

    result = find_split_apks(tmp_path / "com.foo.app.apk")

    assert {p.name for p in result} == {
        "com.foo.app.apk", "split_config.arm64_v8a.apk", "split_config.en.apk",
    }


def test_loose_apk_without_splits_returns_just_itself(tmp_path):
    _touch(tmp_path, "com.foo.app.apk")

    assert find_split_apks(tmp_path / "com.foo.app.apk") == [tmp_path / "com.foo.app.apk"]


def test_intermediate_artifacts_are_excluded(tmp_path):
    _touch(
        tmp_path,
        "com.foo.app.apk",
        "com.foo.app.config.en.apk",
        "com.foo.app_unsigned.apk",
        "com.foo.app_patched.apk",
    )

    result = find_split_apks(tmp_path / "com.foo.app.apk")

    assert {p.name for p in result} == {"com.foo.app.apk", "com.foo.app.config.en.apk"}
