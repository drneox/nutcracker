"""Carga de configuración desde config.yaml."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"

_log = logging.getLogger(__name__)

# Interpola "${VAR_NAME}" con os.environ dentro de valores string del YAML.
# Permite mantener secretos (llm.api_key, google_play.aas_token, tokens OSINT)
# fuera de config.yaml, p.ej.: aas_token: "${GOOGLE_PLAY_AAS_TOKEN}"
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """
    Carga la configuración desde un archivo YAML.

    Args:
        path: Ruta al archivo. Si es None, usa config.yaml en la raíz del proyecto.

    Returns:
        Diccionario con la configuración, con placeholders "${VAR}" resueltos
        contra variables de entorno.
    """
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        return {}

    with config_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return _resolve_env_vars(data or {})


def _resolve_env_vars(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_vars(v) for v in value]
    if isinstance(value, str):
        def _sub(match: re.Match) -> str:
            var_name = match.group(1)
            if var_name not in os.environ:
                _log.warning("Variable de entorno %r no definida (placeholder sin resolver)", var_name)
                return match.group(0)
            return os.environ[var_name]

        return _ENV_VAR_RE.sub(_sub, value)
    return value


def get(config: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Accede a una clave anidada del config con un valor por defecto."""
    current = config
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is default:
            return default
    return current
