"""Conexión SQLite (WAL) y migraciones simples versionadas para nutcracker.

El esquema completo vive en ``schema.sql``. Las migraciones son statements SQL
adicionales aplicados en orden cuando ``PRAGMA user_version`` está por debajo de
``SCHEMA_VERSION``; hoy solo existe la versión 1 (esquema inicial).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 3

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "nutcracker.db"

# Migraciones incrementales: {version_destino: [statements]}. La versión 1 se aplica
# directamente desde schema.sql (ver _apply_schema). Todas usan "IF NOT EXISTS" para
# ser idempotentes tanto en bases nuevas (0→1→2 en la misma conexión) como existentes.
_MIGRATIONS: dict[int, list[str]] = {
    # Fase 1 del plan: tabla de jobs de la cola (nutcracker_core/queue/).
    # Desacoplada de `runs`: `runs` registra el resultado real de un análisis
    # (lo escribe store/hooks.py al terminar); `queue_jobs` registra el ciclo de
    # vida de un encolado (queued→running→done/error) y se enlaza al `run_id`
    # real vía NUTCRACKER_QUEUE_JOB_ID (ver store/hooks.py y queue/engine.py).
    2: [
        """
        CREATE TABLE IF NOT EXISTS queue_jobs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            target          TEXT NOT NULL,
            kind            TEXT NOT NULL DEFAULT 'static',   -- static | dynamic
            status          TEXT NOT NULL DEFAULT 'queued',   -- queued | running | done | error
            serial          TEXT,               -- serial ADB (solo jobs dinámicos)
            priority        INTEGER NOT NULL DEFAULT 0,
            package         TEXT,               -- se completa cuando el job termina
            run_id          INTEGER REFERENCES runs(id),
            error           TEXT,
            created_at      TEXT NOT NULL,
            started_at      TEXT,
            finished_at     TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_queue_jobs_status ON queue_jobs(status)",
        "CREATE INDEX IF NOT EXISTS idx_queue_jobs_package ON queue_jobs(package)",
    ],
    # FIX (bug real reportado en vivo, 2026-08-05): relay_session_id/frida_host
    # (relay "browser-as-bridge", ver Job en queue/job.py) vivían SOLO en
    # memoria -- cualquier reconstrucción de Job desde SQLite (reinicio del
    # dashboard mientras un job relay-backed seguía 'queued', ver
    # engine.py::_load_queued_from_db) los perdía en silencio, degradando el
    # job a un adb normal sin dispositivo detrás -- síntoma final: "app no
    # instalada" pese a estar instalada de verdad, sin ningún error claro que
    # apunte a la causa real. A diferencia de `source`/`aipwn_resume` (que sí
    # se dejan sin persistir a propósito -- su fallback es aceptable, ver
    # comentarios en job.py), acá no hay degradación razonable posible.
    3: [
        "ALTER TABLE queue_jobs ADD COLUMN relay_session_id TEXT",
        "ALTER TABLE queue_jobs ADD COLUMN frida_host TEXT",
    ],
}


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Abre (o crea) la base SQLite en modo WAL y aplica migraciones pendientes."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    # La cola (Fase 1) puede tener varios procesos (engine + subprocesos hijos)
    # escribiendo en la misma base casi a la vez; con WAL esto es seguro pero
    # puede haber contención breve — sqlite3 reintenta en vez de fallar con
    # "database is locked" mientras esté dentro de este margen.
    conn.execute("PRAGMA busy_timeout=10000")
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
