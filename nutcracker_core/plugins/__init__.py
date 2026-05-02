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

# ── Post-hook registry ────────────────────────────────────────────────────────
# Plugins call register_post_hook(event, fn) during their register() call.
# nutcracker.py calls fire_post_hooks(event, **kwargs) at the right moment.
#
# Supported events:
#   "after_analysis"  — fired after every scan/analyze run that produces a result.
#                       kwargs: package, result, vuln_scan, config
#   "after_batch"     — fired once after a batch run finishes.
#                       kwargs: packages (list[str]), config

_POST_HOOKS: dict[str, list] = {}


def register_post_hook(event: str, fn) -> None:
    """Register *fn* to be called when *event* fires.  Called from plugin register()."""
    _POST_HOOKS.setdefault(event, []).append(fn)


def fire_post_hooks(event: str, **kwargs) -> None:
    """Call every function registered for *event*, passing **kwargs**.  Never raises."""
    for fn in _POST_HOOKS.get(event, []):
        try:
            fn(**kwargs)
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001
            _log.warning("Post-hook %r from %r failed: %s", event, fn, exc)


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
