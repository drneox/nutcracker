"""Post-hook core: persiste cada análisis en SQLite sin tocar el flujo actual.

Doble escritura no destructiva (plan.md Fase 0.1): los JSON/PDF en disco siguen
igual, este hook solo añade una fila en ``runs``/``findings``/``artifacts``.
Se registra una sola vez, en el arranque del CLI (``install``), reusando el
mismo bus de post-hooks que usan los plugins (``after_analysis``).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from ..config import get as cfg_get
from . import db, repository

_log = logging.getLogger(__name__)

_installed = False


def install() -> None:
    """Registra el post-hook after_analysis. Idempotente: llamar más de una vez no duplica."""
    global _installed
    if _installed:
        return
    from ..plugins import register_post_hook

    register_post_hook("after_analysis", _persist_after_analysis)
    _installed = True


def db_path_from_config(config: dict | None) -> str | None:
    if not config:
        return None
    return cfg_get(config, "store", "db_path", default=None)


def _persist_after_analysis(
    package: str,
    result: Any,
    vuln_scan: Any = None,
    config: dict | None = None,
) -> None:
    """Firma estable (package, result, vuln_scan, config): otros post-hooks registrados
    (p.ej. aireview) comparten esta misma firma sin ``**kwargs``, así que este hook no
    puede depender de argumentos extra en ``fire_post_hooks`` — deriva json_path/pdf_path
    de la misma convención de rutas que usa reporter.py/orchestrator.py."""
    if config is not None and not bool(cfg_get(config, "store", "enabled", default=True)):
        return

    conn = db.connect(db_path_from_config(config))
    try:
        run_id = repository.insert_run(conn, package, kind="full", status="running")

        # FIX (reportado en vivo, 2026-07-27): registrar de dónde salió el
        # .apk analizado -- sin esto, "re-analizar" en el dashboard siempre
        # asumía que la app se podía volver a *descargar* por package id,
        # fallando para apps analizadas desde un .apk local que nunca estuvo
        # publicado en ninguna store. orchestrator._run_analysis deja la ruta
        # en NUTCRACKER_APK_SOURCE (solo si el archivo sobrevive al análisis,
        # ver ahí) -- misma técnica de env var que NUTCRACKER_QUEUE_JOB_ID,
        # necesaria porque esta función comparte firma con otros post-hooks
        # (aireview) que no aceptan kwargs extra en fire_post_hooks.
        apk_source = os.environ.get("NUTCRACKER_APK_SOURCE")
        if apk_source:
            repository.upsert_app(conn, package, source=f"local:{apk_source}")

        masvs_report = None
        try:
            from ..masvs import build_masvs_report

            masvs_report = build_masvs_report(result, vuln_scan, None)
        except Exception as exc:  # noqa: BLE001
            _log.debug("build_masvs_report falló para %s: %s", package, exc)

        verdict = _verdict_from_result(result)
        repository.update_run_status(
            conn,
            run_id,
            status="done",
            verdict=verdict,
            masvs_score=masvs_report.score if masvs_report else None,
            grade=masvs_report.grade if masvs_report else None,
        )

        if vuln_scan is not None and getattr(vuln_scan, "findings", None):
            records = [_to_finding_record(f, vuln_scan) for f in vuln_scan.findings]
            repository.record_findings(conn, run_id, records)

        json_path, pdf_path = _find_artifacts(package)
        for artifact_type, path in (("json", json_path), ("pdf", pdf_path)):
            if path:
                repository.record_artifact(conn, run_id, artifact_type, str(path))

        repository.touch_app_run(conn, package)

        # Fase 1 (cola): si este análisis corrió como job de queue/engine.py, el
        # subproceso hijo trae NUTCRACKER_QUEUE_JOB_ID en su entorno — enlazamos
        # el job con el run real para que el motor pueda leer package/verdict de
        # vuelta sin adivinarlos antes de que termine el análisis.
        job_id = os.environ.get("NUTCRACKER_QUEUE_JOB_ID")
        if job_id:
            try:
                repository.link_job_run(conn, int(job_id), run_id, package)
            except Exception as exc:  # noqa: BLE001
                _log.debug("link_job_run falló para job %s: %s", job_id, exc)
    finally:
        conn.close()


def _find_artifacts(package: str) -> tuple[Path | None, Path | None]:
    """Localiza el JSON/PDF que reporter.py acaba de guardar para ``package``.

    orchestrator._run_analysis llama a save_analysis_json()/_generate_pdf() sin pasar
    reports_dir, así que ambos usan siempre su default "./reports" (relativo al cwd),
    sin importar reports.output_dir en config.yaml. Replicamos ese mismo hardcode aquí
    en vez de leer la config, para no desalinearnos si ese default cambia de nuevo.
    """
    pkg_dir = Path("./reports") / package
    if not pkg_dir.is_dir():
        return None, None

    json_candidates = sorted(
        (f for f in pkg_dir.glob("*.json") if f.stem[:1].isdigit()),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )
    json_path = json_candidates[0] if json_candidates else None

    pdf_path = pkg_dir / f"nutcracker_{package}_report.pdf"
    if not pdf_path.exists():
        pdf_path = None

    return json_path, pdf_path


def _verdict_from_result(result: Any) -> str:
    if getattr(result, "protection_broken", False):
        return "protection_broken"
    if getattr(result, "protected", False):
        return "protected"
    return "not_protected"


def _to_finding_record(finding: Any, vuln_scan: Any) -> repository.FindingRecord:
    try:
        from ..masvs import RULE_TO_MASVS, RULE_TO_MASWE, RULE_TO_CWE

        masvs_ids = RULE_TO_MASVS.get(finding.rule_id, [])
        maswe_ids = RULE_TO_MASWE.get(finding.rule_id, [])
        cwe_ids = RULE_TO_CWE.get(finding.rule_id, [])
    except Exception:  # noqa: BLE001
        masvs_ids, maswe_ids, cwe_ids = [], [], []

    file_str = ""
    try:
        file_str = finding.relative_path(vuln_scan.base_dir)
    except Exception:  # noqa: BLE001
        file_str = str(getattr(finding, "file", "") or "")

    return repository.FindingRecord(
        rule_id=finding.rule_id,
        title=getattr(finding, "title", ""),
        severity=getattr(finding, "severity", ""),
        category=getattr(finding, "category", ""),
        masvs=masvs_ids,
        maswe=maswe_ids,
        cwe=cwe_ids,
        file=file_str,
        line=getattr(finding, "line", 0) or 0,
    )
