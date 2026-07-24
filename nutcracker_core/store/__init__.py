"""Capa de persistencia SQLite de nutcracker (core, no plugin).

    from nutcracker_core.store import db, repository
    from nutcracker_core.store.hooks import install as install_persistence

``install_persistence()`` engancha el post-hook ``after_analysis`` para
que cada análisis quede registrado en ``runs``/``findings``/``artifacts`` sin
tocar el flujo JSON/PDF existente. La config se lee en el momento del hook
(bloque ``store:`` de config.yaml), no al instalar.
"""

from __future__ import annotations

from . import db, repository
from .db import DEFAULT_DB_PATH, connect, migrate
from .hooks import install as install_persistence

__all__ = [
    "db",
    "repository",
    "connect",
    "migrate",
    "DEFAULT_DB_PATH",
    "install_persistence",
]
