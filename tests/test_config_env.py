"""Tests de interpolación ${ENV_VAR} en nutcracker_core.config.load_config."""

import pytest

from nutcracker_core.config import load_config


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "google_play:\n"
        "  aas_token: '${NUTCRACKER_TEST_TOKEN}'\n"
        "llm:\n"
        "  api_key: '${NUTCRACKER_TEST_MISSING}'\n"
        "nested:\n"
        "  list:\n"
        "    - '${NUTCRACKER_TEST_TOKEN}'\n"
        "    - plain_value\n"
        "language: en\n",
        encoding="utf-8",
    )
    return path


def test_resolves_env_var_when_set(config_file, monkeypatch):
    monkeypatch.setenv("NUTCRACKER_TEST_TOKEN", "secret-123")

    cfg = load_config(config_file)

    assert cfg["google_play"]["aas_token"] == "secret-123"
    assert cfg["nested"]["list"][0] == "secret-123"


def test_leaves_placeholder_when_env_var_missing(config_file, monkeypatch):
    monkeypatch.setenv("NUTCRACKER_TEST_TOKEN", "secret-123")
    monkeypatch.delenv("NUTCRACKER_TEST_MISSING", raising=False)

    cfg = load_config(config_file)

    assert cfg["llm"]["api_key"] == "${NUTCRACKER_TEST_MISSING}"


def test_non_string_values_untouched(config_file, monkeypatch):
    monkeypatch.setenv("NUTCRACKER_TEST_TOKEN", "secret-123")

    cfg = load_config(config_file)

    assert cfg["language"] == "en"
    assert cfg["nested"]["list"][1] == "plain_value"


def test_missing_file_returns_empty_dict(tmp_path):
    assert load_config(tmp_path / "does_not_exist.yaml") == {}
