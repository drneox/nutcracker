"""API REST del dashboard (Fase 3 del plan) — solo lee el store y drive la cola
a través de sus APIs públicas (QueueEngine), nunca reimplementa análisis."""

from __future__ import annotations

import threading

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from nutcracker_core.queue.engine import QueueEngine
from nutcracker_core.store import db, repository

from . import chat_mailbox, store_reader
from .events import bus


def _drain_in_background(engine: QueueEngine) -> None:
    """Dispara engine.drain() en un hilo de fondo -- la respuesta HTTP de
    POST /api/queue no espera a que el job termine (puede tardar minutos); el
    progreso se sigue por /ws/jobs/{id}. `_dashboard_draining` es el guard que
    permite a los tests (y a otro código) esperar a que termine sin adivinar
    un timeout fijo."""
    engine._dashboard_draining = True

    def _run() -> None:
        try:
            engine.drain(
                on_result=lambda o: bus.publish(
                    str(o.job.db_id), "status", {"status": "done" if o.ok else "error"}
                )
            )
        finally:
            engine._dashboard_draining = False

    threading.Thread(target=_run, daemon=True).start()


def _drain_batch_in_background(engine: QueueEngine, then_aipwn: bool, serial: str | None) -> None:
    """Mismo patrón que cli/queue_cmd.py (`--then-aipwn`): drena los jobs
    estáticos recién encolados, acumula los packages cuyo job terminó OK, y
    encola+drena un job aipwn por cada uno -- corriendo en un hilo de fondo en
    vez de bloquear la respuesta HTTP (ver `_drain_in_background`)."""
    engine._dashboard_draining = True

    def _publish(o) -> None:  # noqa: ANN001
        bus.publish(str(o.job.db_id), "status", {"status": "done" if o.ok else "error"})

    def _run() -> None:
        try:
            pending_aipwn: list[str] = []

            def _on_result(o) -> None:  # noqa: ANN001
                _publish(o)
                if then_aipwn and o.job.kind == "static" and o.ok and o.package:
                    pending_aipwn.append(o.package)

            engine.drain(on_result=_on_result)

            if pending_aipwn:
                for pkg in pending_aipwn:
                    engine.submit(pkg, kind="aipwn", serial=serial)
                engine.drain(on_result=_publish)
        finally:
            engine._dashboard_draining = False

    threading.Thread(target=_run, daemon=True).start()


class ScheduleSetPayload(BaseModel):
    interval_days: int = 30
    enabled: bool = True


class QueuePayload(BaseModel):
    target: str
    kind: str = "static"
    serial: str | None = None
    source: str | None = None
    run_now: bool = False


class QueueBatchPayload(BaseModel):
    targets: list[str]
    source: str | None = None
    serial: str | None = None
    then_aipwn: bool = True


def create_router(db_path: str, engine: QueueEngine, default_serial: str | None = None) -> APIRouter:
    """No toca ``engine.on_line`` a propósito: ese wiring (streaming de logs en
    vivo al EventBus) lo hace ``plugins/dashboard/__init__.py::dashboard()``
    sobre la ÚNICA instancia real de producción, antes de llamar a
    ``create_app``. Si este router lo asignara aquí, cualquier test que
    construya su propio ``QueueEngine`` + ``create_app`` (ver tests/dashboard/
    test_api.py) perdería el camino clásico ``subprocess.run`` (Fase 1) sin
    darse cuenta -- pasaría a ``_run_streaming``/``subprocess.Popen`` siempre,
    rompiendo cualquier test que parchea ``subprocess.run`` esperando que se
    invoque de verdad."""
    router = APIRouter()

    def _conn():
        return db.connect(db_path)

    @router.get("/api/summary")
    def summary():
        conn = _conn()
        try:
            return store_reader.summary_counts(conn)
        finally:
            conn.close()

    @router.get("/api/config/default-serial")
    def config_default_serial():
        """Serial preconfigurado (``strategies.default_device_id`` en config.yaml)
        para que el frontend precargue los campos de serial de la cola/batch --
        típicamente un serial de red ("ip:5555" tras ``adb tcpip 5555``) para
        que el operador no tenga que escribirlo a mano en cada job, y para
        evitar el conflicto de exclusividad USB con el video WebUSB (ver
        README de nutcracker_core/plugins/dashboard/webusb/)."""
        return {"serial": default_serial}

    @router.get("/api/apps")
    def apps_list():
        conn = _conn()
        try:
            return store_reader.list_apps(conn)
        finally:
            conn.close()

    @router.get("/api/apps/{package}/trend")
    def app_trend(package: str):
        conn = _conn()
        try:
            return store_reader.masvs_trend(conn, package)
        finally:
            conn.close()

    @router.get("/api/runs")
    def runs_list(limit: int = 100):
        conn = _conn()
        try:
            return store_reader.list_runs(conn, limit=limit)
        finally:
            conn.close()

    @router.get("/api/runs/{run_id}")
    def run_get(run_id: int):
        conn = _conn()
        try:
            detail = store_reader.run_detail(conn, run_id)
        finally:
            conn.close()
        if detail is None:
            raise HTTPException(status_code=404, detail="run no encontrado")
        return detail

    @router.get("/api/schedule")
    def schedule_list():
        conn = _conn()
        try:
            return [dict(r) for r in repository.list_schedules(conn)]
        finally:
            conn.close()

    @router.post("/api/schedule/{package}")
    def schedule_set(package: str, payload: ScheduleSetPayload):
        conn = _conn()
        try:
            repository.set_schedule(
                conn, package, interval_days=payload.interval_days, enabled=payload.enabled,
            )
            row = repository.get_schedule(conn, package)
        finally:
            conn.close()
        return dict(row)

    @router.get("/api/queue")
    def queue_list(status: str | None = None, limit: int = 100):
        conn = _conn()
        try:
            return [dict(r) for r in repository.list_jobs(conn, status=status, limit=limit)]
        finally:
            conn.close()

    @router.post("/api/queue")
    def queue_add(payload: QueuePayload):
        try:
            job = engine.submit(
                payload.target, kind=payload.kind, serial=payload.serial, source=payload.source,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if payload.run_now:
            _drain_in_background(engine)
        return {"job_id": job.db_id}

    @router.delete("/api/queue/{job_id}")
    def queue_delete(job_id: int):
        """Borra un job pendiente (status='queued') de la cola. No afecta jobs
        'running' (ya despachados a un worker en algún proceso -- no hay forma
        de "des-despacharlos" borrando la fila) ni 'done'/'error' (historial)."""
        conn = _conn()
        try:
            deleted = repository.delete_job(conn, job_id)
        finally:
            conn.close()
        if not deleted:
            raise HTTPException(
                status_code=404,
                detail="job no encontrado o ya no está en estado 'queued'",
            )
        return {"deleted": True}

    @router.post("/api/queue/batch")
    def queue_batch(payload: QueueBatchPayload):
        targets = [
            t.strip() for t in payload.targets
            if t.strip() and not t.strip().startswith("#")
        ]
        if not targets:
            raise HTTPException(status_code=400, detail="no hay targets válidos en el batch")
        for target in targets:
            engine.submit(target, kind="static", serial=payload.serial, source=payload.source)
        _drain_batch_in_background(engine, then_aipwn=payload.then_aipwn, serial=payload.serial)
        return {"queued": len(targets)}

    @router.get("/api/chat/{package}/pending")
    def chat_pending(package: str):
        return {"messages": chat_mailbox.drain(package)}

    @router.get("/api/agent/prompt")
    def agent_prompt():
        try:
            from nutcracker_core.plugins.aipwn.frida_agent import _SYSTEM_PROMPT
        except Exception:  # noqa: BLE001
            return {"available": False}
        return {"available": True, "prompt": _SYSTEM_PROMPT}

    return router
