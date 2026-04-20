"""Carga de configuración desde config.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """
    Carga la configuración desde un archivo YAML.

    Args:
        path: Ruta al archivo. Si es None, usa config.yaml en la raíz del proyecto.

    Returns:
        Diccionario con la configuración.
    """
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        return {}

    with config_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data or {}


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
