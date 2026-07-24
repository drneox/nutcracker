"""Conexión SQLite (WAL) y migraciones simples versionadas para nutcracker.

El esquema completo vive en ``schema.sql``. Las migraciones son statements SQL
adicionales aplicados en orden cuando ``PRAGMA user_version`` está por debajo de
``SCHEMA_VERSION``; hoy solo existe la versión 1 (esquema inicial).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "nutcracker.db"

# Migraciones futuras: {version_destino: [statements]}. La versión 1 se aplica
# directamente desde schema.sql (ver _apply_schema).
_MIGRATIONS: dict[int, list[str]] = {}


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Abre (o crea) la base SQLite en modo WAL y aplica migraciones pendientes."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    """Aplica el esquema inicial y cualquier migración pendiente."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]

    if current == 0:
        _apply_schema(conn)
        current = 1
        conn.execute(f"PRAGMA user_version={current}")

    for version in sorted(v for v in _MIGRATIONS if v > current):
        with conn:
            for stmt in _MIGRATIONS[version]:
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version={version}")
        current = version

    conn.commit()


def _apply_schema(conn: sqlite3.Connection) -> None:
    sql = _SCHEMA_PATH.read_text(encoding="utf-8")
    with conn:
        conn.executescript(sql)
