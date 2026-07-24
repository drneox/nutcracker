"""CRUD tipado sobre el esquema SQLite de nutcracker.

Todas las funciones reciben una ``sqlite3.Connection`` ya abierta (ver ``db.connect``)
para que sean triviales de testear con una base ``:memory:``. No hay estado de
módulo ni conexión global: quien orquesta (CLI, daemon, dashboard) decide el
ciclo de vida de la conexión.
"""

from __future__ import annotations

import datetime
import sqlite3
from dataclasses import dataclass, field


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ── apps ──────────────────────────────────────────────────────────────────────

def upsert_app(conn: sqlite3.Connection, package: str, source: str | None = None) -> None:
    """Crea la app si no existe; si existe, no pisa first_seen ni next_due_at."""
    conn.execute(
        """
        INSERT INTO apps (package, source, first_seen)
        VALUES (?, ?, ?)
        ON CONFLICT(package) DO UPDATE SET
            source = COALESCE(excluded.source, apps.source)
        """,
        (package, source, _utcnow()),
    )
    conn.commit()


def touch_app_run(conn: sqlite3.Connection, package: str, ran_at: str | None = None,
                   next_due_at: str | None = None) -> None:
    """Actualiza last_run_at (y opcionalmente next_due_at) tras un run."""
    ran_at = ran_at or _utcnow()
    conn.execute(
        "UPDATE apps SET last_run_at = ?, next_due_at = COALESCE(?, next_due_at) WHERE package = ?",
        (ran_at, next_due_at, package),
    )
    conn.commit()


def get_app(conn: sqlite3.Connection, package: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM apps WHERE package = ?", (package,)).fetchone()


def apps_due(conn: sqlite3.Connection, before: str | None = None) -> list[sqlite3.Row]:
    """Apps cuyo next_due_at <= before (por defecto: ahora), incluyendo las sin next_due_at."""
    before = before or _utcnow()
    return conn.execute(
        "SELECT * FROM apps WHERE next_due_at IS NOT NULL AND next_due_at <= ? ORDER BY next_due_at",
        (before,),
    ).fetchall()


# ── runs ──────────────────────────────────────────────────────────────────────

def insert_run(conn: sqlite3.Connection, package: str, kind: str = "full",
                status: str = "queued", started_at: str | None = None) -> int:
    """Inserta un run nuevo (asegura la app vía upsert_app) y retorna su id."""
    upsert_app(conn, package)
    cur = conn.execute(
        "INSERT INTO runs (package, kind, status, started_at) VALUES (?, ?, ?, ?)",
        (package, kind, status, started_at or (_utcnow() if status == "running" else None)),
    )
    conn.commit()
    return cur.lastrowid


def update_run_status(
    conn: sqlite3.Connection,
    run_id: int,
    status: str,
    verdict: str | None = None,
    masvs_score: int | None = None,
    grade: str | None = None,
    error: str | None = None,
    finished_at: str | None = None,
) -> None:
    """Actualiza el estado de un run. Marca finished_at automáticamente en done/error."""
    if finished_at is None and status in ("done", "error"):
        finished_at = _utcnow()
    conn.execute(
        """
        UPDATE runs SET
            status = ?,
            verdict = COALESCE(?, verdict),
            masvs_score = COALESCE(?, masvs_score),
            grade = COALESCE(?, grade),
            error = COALESCE(?, error),
            finished_at = COALESCE(?, finished_at)
        WHERE id = ?
        """,
        (status, verdict, masvs_score, grade, error, finished_at, run_id),
    )
    conn.commit()


def get_run(conn: sqlite3.Connection, run_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()


def history(conn: sqlite3.Connection, package: str, limit: int = 50) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM runs WHERE package = ? ORDER BY id DESC LIMIT ?",
        (package, limit),
    ).fetchall()


# ── findings ──────────────────────────────────────────────────────────────────

@dataclass
class FindingRecord:
    """Vista mínima de un hallazgo para persistir, desacoplada de VulnFinding."""
    rule_id: str
    title: str = ""
    severity: str = ""
    category: str = ""
    masvs: list[str] = field(default_factory=list)
    maswe: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    file: str = ""
    line: int = 0
    confirmed: bool | None = None


def record_findings(conn: sqlite3.Connection, run_id: int, findings: list[FindingRecord]) -> None:
    conn.executemany(
        """
        INSERT INTO findings (run_id, rule_id, title, severity, category, masvs, maswe, cwe, file, line, confirmed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                run_id, f.rule_id, f.title, f.severity, f.category,
                ",".join(f.masvs), ",".join(f.maswe), ",".join(f.cwe),
                f.file, f.line,
                None if f.confirmed is None else int(f.confirmed),
            )
            for f in findings
        ],
    )
    conn.commit()


def findings_for_run(conn: sqlite3.Connection, run_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,)).fetchall()


# ── artifacts ─────────────────────────────────────────────────────────────────

def record_artifact(conn: sqlite3.Connection, run_id: int, type: str, path: str) -> None:
    conn.execute(
        "INSERT INTO artifacts (run_id, type, path) VALUES (?, ?, ?)",
        (run_id, type, path),
    )
    conn.commit()


def artifacts_for_run(conn: sqlite3.Connection, run_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM artifacts WHERE run_id = ?", (run_id,)).fetchall()


# ── schedule ──────────────────────────────────────────────────────────────────

def set_schedule(conn: sqlite3.Connection, package: str, interval_days: int = 30,
                  cron: str | None = None, enabled: bool = True) -> None:
    upsert_app(conn, package)
    conn.execute(
        """
        INSERT INTO schedule (package, interval_days, cron, enabled, last_scheduled_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(package) DO UPDATE SET
            interval_days = excluded.interval_days,
            cron = excluded.cron,
            enabled = excluded.enabled,
            last_scheduled_at = excluded.last_scheduled_at
        """,
        (package, interval_days, cron, int(enabled), _utcnow()),
    )
    next_due = _utcnow()
    if interval_days:
        next_due = (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=interval_days)
        ).isoformat(timespec="seconds")
    conn.execute("UPDATE apps SET next_due_at = ? WHERE package = ?", (next_due, package))
    conn.commit()


def get_schedule(conn: sqlite3.Connection, package: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM schedule WHERE package = ?", (package,)).fetchone()


def list_schedules(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM schedule ORDER BY package").fetchall()
