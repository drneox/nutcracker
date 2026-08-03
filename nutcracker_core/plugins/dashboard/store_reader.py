"""Queries de lectura con forma de dashboard sobre el store de Fase 0.

Respeta la frontera core/plugin: **solo lee** (SELECT), nunca escribe. Reusa
las tablas de ``nutcracker_core.store`` (apps/runs/findings/queue_jobs) tal
cual, sin duplicar el modelo de datos — este módulo solo shapea filas crudas
en la forma que necesita la API del dashboard (api.py).
"""

from __future__ import annotations

import sqlite3

from nutcracker_core.store import repository


def summary_counts(conn: sqlite3.Connection) -> dict:
    apps = conn.execute("SELECT COUNT(*) FROM apps").fetchone()[0]
    runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    active_jobs = conn.execute(
        "SELECT COUNT(*) FROM queue_jobs WHERE status IN ('queued', 'running')"
    ).fetchone()[0]
    return {"apps": apps, "runs": runs, "findings": findings, "active_jobs": active_jobs}


def list_apps(conn: sqlite3.Connection) -> list[dict]:
    """Una fila por app, con el resultado de su run más reciente (si tiene alguno)."""
    rows = conn.execute(
        """
        SELECT
            a.package, a.source, a.first_seen, a.last_run_at, a.next_due_at,
            r.id           AS last_run_id,
            r.verdict      AS last_verdict,
            r.masvs_score  AS masvs_score,
            r.grade        AS grade,
            r.finished_at  AS last_run_finished_at
        FROM apps a
        LEFT JOIN runs r ON r.id = (
            SELECT id FROM runs WHERE package = a.package ORDER BY id DESC LIMIT 1
        )
        ORDER BY a.package
        """
    ).fetchall()
    return [dict(r) for r in rows]


def list_runs(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def run_detail(conn: sqlite3.Connection, run_id: int) -> dict | None:
    run = repository.get_run(conn, run_id)
    if run is None:
        return None
    findings = repository.findings_for_run(conn, run_id)
    data = dict(run)
    data["findings"] = [dict(f) for f in findings]
    return data


def masvs_trend(conn: sqlite3.Connection, package: str) -> list[dict]:
    """Score MASVS por run a lo largo del tiempo (ascendente), para el gráfico
    de tendencia del modal de detalle de app."""
    rows = conn.execute(
        """
        SELECT id, masvs_score, grade, finished_at
        FROM runs
        WHERE package = ? AND masvs_score IS NOT NULL
        ORDER BY id ASC
        """,
        (package,),
    ).fetchall()
    return [dict(r) for r in rows]
