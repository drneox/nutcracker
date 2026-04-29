"""Plugin loader para nutcracker.

Detecta automáticamente cualquier subdirectorio de plugins/ que exponga
una función ``register(cli)`` y la invoca al arrancar el CLI.

Instalación de un plugin:
    git clone <url> nutcracker_core/plugins/<nombre>
    pip install -r nutcracker_core/plugins/<nombre>/requirements.txt  # si existe
"""

from __future__ import annotations

import importlib
import logging
import subprocess
import sys
from pathlib import Path

_log = logging.getLogger(__name__)


def load_plugins(cli) -> None:
    """Descubre y registra todos los plugins instalados en este directorio."""
    plugins_dir = Path(__file__).parent
    for entry in sorted(plugins_dir.iterdir()):
        if not entry.is_dir() or entry.name.startswith(("_", ".")):
            continue
        module_path = f"nutcracker_core.plugins.{entry.name}"
        # Auto-install plugin requirements if present and import fails
        req_file = entry / "requirements.txt"
        try:
            mod = importlib.import_module(module_path)
        except ImportError as exc:
            if req_file.exists():
                _log.debug(
                    "Plugin %s: missing deps, trying to install from %s",
                    entry.name, req_file,
                )
                try:
                    subprocess.check_call(
                        [sys.executable, "-m", "pip", "install", "-q", "-r", str(req_file)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    importlib.invalidate_caches()
                    mod = importlib.import_module(module_path)
                except Exception as install_exc:  # noqa: BLE001
                    _log.debug(
                        "Plugin %s: auto-install failed: %s", entry.name, install_exc
                    )
                    continue
            else:
                _log.debug("Plugin %s not available (import failed): %s", entry.name, exc)
                continue
        if callable(getattr(mod, "register", None)):
            try:
                mod.register(cli)
            except Exception as exc:  # noqa: BLE001
                _log.warning("Error al registrar plugin %s: %s", entry.name, exc)
