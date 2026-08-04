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


def list_runs_for_app(conn: sqlite3.Connection, package: str, limit: int = 50) -> list[dict]:
    """Historial de runs de un paquete (más reciente primero), con conteo de
    hallazgos y los artefactos descargables (JSON/PDF) de cada uno -- para la
    sección "Historial de análisis" del modal de detalle de app.

    El PDF es un archivo canónico por *paquete* (reporter.py lo sobreescribe
    en cada análisis, ver store/hooks.py::_find_artifacts), no por run -- así
    que el mismo path puede aparecer repetido en varios runs viejos, y ya no
    refleja el contenido de ese run específico. El JSON sí es único por run
    (nombre con timestamp). El shapeo de qué mostrar/ocultar en la UI para
    evitar confundir "PDF de este run" con "PDF más reciente" vive en el
    frontend, no acá -- esta función solo expone los datos crudos tal cual
    están en la tabla ``artifacts``.
    """
    rows = repository.history(conn, package, limit=limit)
    result = []
    for row in rows:
        d = dict(row)
        artifacts = repository.artifacts_for_run(conn, d["id"])
        d["artifacts"] = {a["type"]: a["path"] for a in artifacts}
        d["findings_count"] = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE run_id = ?", (d["id"],)
        ).fetchone()[0]
        result.append(d)
    return result


def consolidated_findings_for_app(conn: sqlite3.Connection, package: str) -> list[dict]:
    """Hallazgos distintos vistos alguna vez en CUALQUIER run de esta app,
    deduplicados por (rule_id, file, line) -- sin esto, dos runs del mismo
    build muestran los mismos hallazgos dos veces (confirmado con datos
    reales: com.bcp.bo.wallet runs #10/#11, idénticos byte a byte).

    Cada hallazgo distinto trae ``status``:
      - "present":  sigue apareciendo en el run más reciente.
      - "resolved": apareció en algún run viejo, pero ya no en el más reciente
                    (se corrigió, o el código que lo generaba cambió/desapareció).

    ``repository.history()`` devuelve los runs más reciente primero -- se
    recorren en ese orden, así que la primera vez que aparece una clave es su
    ``last_seen`` (el run más reciente donde está), y se va empujando
    ``first_seen`` hacia atrás a medida que se la encuentra en runs más viejos.
    """
    runs = repository.history(conn, package, limit=1000)
    if not runs:
        return []
    latest_run_id = runs[0]["id"]

    consolidated: dict[tuple, dict] = {}
    for run in runs:
        run_id = run["id"]
        run_time = run["finished_at"] or run["started_at"]
        for f in repository.findings_for_run(conn, run_id):
            key = (f["rule_id"], f["file"], f["line"])
            if key not in consolidated:
                consolidated[key] = {
                    "rule_id": f["rule_id"], "title": f["title"], "severity": f["severity"],
                    "masvs": f["masvs"], "maswe": f["maswe"], "cwe": f["cwe"],
                    "file": f["file"], "line": f["line"],
                    "last_seen_run": run_id, "last_seen_at": run_time,
                    "first_seen_run": run_id, "first_seen_at": run_time,
                    "seen_in_runs": 0,
                }
            consolidated[key]["seen_in_runs"] += 1
            consolidated[key]["first_seen_run"] = run_id
            consolidated[key]["first_seen_at"] = run_time

    result = list(consolidated.values())
    for entry in result:
        entry["status"] = "present" if entry["last_seen_run"] == latest_run_id else "resolved"

    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result.sort(key=lambda e: (e["status"] != "present", _sev_order.get(e["severity"], 5)))
    return result


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
