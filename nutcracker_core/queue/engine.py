"""Motor de la cola de nutcracker (Fase 1 del plan).

Estrategia de concurrencia:
  - Jobs **estáticos** (decompilación jadx, semgrep/regex, OSINT): corren en un
    pool de ``static_workers`` hilos en paralelo. Cada hilo solo lanza un
    subproceso y espera — el trabajo real (jadx, semgrep, androguard) ocurre en
    ese proceso hijo, así que no hay contención de GIL relevante.
  - Jobs **dinámicos** (Frida/ADB sobre un teléfono físico): nunca pueden
    compartir el mismo dispositivo. Se ejecutan en su propio pool de
    ``dynamic_workers`` hilos, pero cada ejecución adquiere un
    ``threading.Lock`` propio de su ``serial`` antes de lanzar el subproceso —
    dos jobs con el mismo serial jamás corren a la vez, aunque el pool tenga
    más de un hilo (permite paralelismo *entre* dispositivos distintos).

Cada job se ejecuta como un **subproceso aislado** que invoca el CLI existente
(`nutcracker analyze`/`scan`, ver orchestrator.build_job_cmd) en vez de llamar
funciones del orquestador en el mismo proceso: el orquestador usa estado mutuo
a nivel de módulo (`_CFG`, `_MANIFEST_ANALYSIS`, ...) que no es seguro entre
análisis concurrentes de APKs distintas. El aislamiento por proceso evita ese
riesgo reutilizando 100% del pipeline ya probado, sin reescribirlo.
"""

from __future__ import annotations

import datetime
import logging
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from nutcracker_core import orchestrator as orch
from nutcracker_core.config import get as cfg_get, load_config
from nutcracker_core.store import db, repository

from .job import Job

_log = logging.getLogger(__name__)


@dataclass
class JobOutcome:
    job: Job
    ok: bool
    returncode: int
    error: str = ""
    run_id: int | None = None
    package: str | None = None


def _is_local_apk(target: str) -> bool:
    return Path(target).exists() and target.lower().endswith(".apk")


class QueueEngine:
    """Encola y ejecuta jobs de análisis de APKs."""

    def __init__(
        self,
        config_path: str = "config.yaml",
        db_path: str | None = None,
        static_workers: int = 4,
        dynamic_workers: int = 2,
    ) -> None:
        self.config_path = config_path
        self.db_path = db_path
        self.static_workers = max(1, static_workers)
        self.dynamic_workers = max(1, dynamic_workers)
        self._pending: list[Job] = []
        self._device_locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        # Hook opcional (Fase 3, dashboard): si se asigna, cada línea de stdout
        # del subproceso de un job se publica aquí en vivo, línea a línea,
        # en vez de esperar a que el job termine. None (default) preserva el
        # camino original — subprocess.run() bloqueante, sin cambios de
        # comportamiento para quien no lo use (CLI, scheduler, tests de Fase 1).
        self.on_line: Callable[[int, str], None] | None = None

    # ── Encolado ─────────────────────────────────────────────────────────────

    def submit(self, target: str, kind: str = "static", serial: str | None = None,
               priority: int = 0) -> Job:
        """Encola un job (persistido en SQLite como 'queued' de inmediato)."""
        is_local = _is_local_apk(target)
        if kind == "dynamic" and not is_local:
            raise ValueError(
                f"Job dinámico requiere un .apk local (recibido: {target!r}). "
                "Descárgalo primero (nutcracker scan) o usa el plugin aipwn para "
                "flujos dinámicos con descarga automática."
            )
        job = Job(target=target, kind=kind, is_local_apk=is_local, serial=serial, priority=priority)
        conn = db.connect(self.db_path)
        try:
            job.db_id = repository.enqueue_job(conn, target=target, kind=kind,
                                                 serial=serial, priority=priority)
        finally:
            conn.close()
        self._pending.append(job)
        return job

    def submit_many(self, targets: list[str], kind: str = "static") -> list[Job]:
        return [self.submit(t, kind=kind) for t in targets]

    def _load_queued_from_db(self) -> None:
        """Recupera de SQLite los jobs en estado 'queued' que no estén ya en
        memoria. Necesario porque cada invocación del CLI (`queue add`) es un
        proceso nuevo: su QueueEngine arranca con `_pending` vacío, así que sin
        esto un job encolado por un proceso anterior (o por el scheduler en un
        tick previo) nunca sería recogido por `drain()`."""
        known_ids = {j.db_id for j in self._pending}
        conn = db.connect(self.db_path)
        try:
            rows = repository.list_jobs(conn, status="queued", limit=1000)
        finally:
            conn.close()
        for row in rows:
            if row["id"] in known_ids:
                continue
            self._pending.append(Job(
                target=row["target"],
                kind=row["kind"],
                is_local_apk=_is_local_apk(row["target"]),
                serial=row["serial"],
                priority=row["priority"],
                db_id=row["id"],
            ))

    def enqueue_due_apps(self) -> int:
        """Encola como jobs estáticos las apps cuyo next_due_at ya venció (lo
        llama el scheduler en cada tick). Retorna cuántas se encolaron."""
        conn = db.connect(self.db_path)
        try:
            due = repository.apps_due(conn)
        finally:
            conn.close()
        for row in due:
            self.submit(row["package"], kind="static")
        return len(due)

    # ── Ejecución ────────────────────────────────────────────────────────────

    def _device_lock(self, serial: str) -> threading.Lock:
        with self._locks_guard:
            return self._device_locks.setdefault(serial, threading.Lock())

    def _default_interval_days(self) -> int:
        config = load_config(self.config_path)
        return int(cfg_get(config, "scheduler", "default_interval_days", default=30))

    def _reschedule(self, conn, package: str) -> None:
        """Recalcula next_due_at tras completar un run (Fase 1.2 del plan:
        garantiza ≥1 revisión/mes por defecto para toda app que pasa por la cola)."""
        sched = repository.get_schedule(conn, package)
        if not sched:
            repository.set_schedule(conn, package, interval_days=self._default_interval_days())
            return
        next_due = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=sched["interval_days"])
        ).isoformat(timespec="seconds")
        repository.touch_app_run(conn, package, next_due_at=next_due)

    def _run_job(self, job: Job) -> JobOutcome:
        conn = db.connect(self.db_path)
        try:
            repository.update_job_status(conn, job.db_id, "running")
        finally:
            conn.close()

        cmd = orch.build_job_cmd(
            job.target,
            is_local_apk=job.is_local_apk,
            config_path=self.config_path,
            static_only=(job.kind == "static"),
            launch=(job.kind == "dynamic"),
            serial=job.serial,
        )
        env = dict(os.environ)
        env["NUTCRACKER_QUEUE_JOB_ID"] = str(job.db_id)

        _log.info("job #%s: %s", job.db_id, " ".join(cmd))
        if self.on_line is not None:
            proc = self._run_streaming(job.db_id, cmd, env)
        else:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        ok = proc.returncode == 0
        tail = (proc.stderr or proc.stdout or "").strip()[-2000:]
        error = "" if ok else tail

        conn = db.connect(self.db_path)
        try:
            repository.update_job_status(
                conn, job.db_id, "done" if ok else "error", error=error or None,
            )
            row = repository.get_job(conn, job.db_id)
            package = row["package"] if row else None
            run_id = row["run_id"] if row else None
            if package:
                self._reschedule(conn, package)
        finally:
            conn.close()

        return JobOutcome(job=job, ok=ok, returncode=proc.returncode, error=error,
                           run_id=run_id, package=package)

    def _run_streaming(self, job_id: int, cmd: list[str], env: dict) -> subprocess.CompletedProcess:
        """Como subprocess.run(), pero publica cada línea de salida a
        self.on_line(job_id, line) en cuanto se produce (stdout+stderr
        combinados, orden real de aparición) en vez de solo al terminar."""
        proc = subprocess.Popen(
            cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        lines: list[str] = []
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line)
            self.on_line(job_id, line.rstrip("\n"))  # type: ignore[misc]
        proc.wait()
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout="".join(lines), stderr="")

    def _run_dynamic(self, job: Job) -> JobOutcome:
        serial = job.serial or "default"
        with self._device_lock(serial):
            return self._run_job(job)

    def drain(self, on_result: Callable[[JobOutcome], None] | None = None) -> list[JobOutcome]:
        """Ejecuta todos los jobs pendientes (en memoria + persistidos en SQLite
        por otros procesos/ticks anteriores) hasta vaciar la cola y retorna sus
        resultados. Bloqueante: vuelve cuando no queda ningún job por correr."""
        self._load_queued_from_db()
        static_jobs = [j for j in self._pending if j.kind == "static"]
        dynamic_jobs = [j for j in self._pending if j.kind == "dynamic"]
        self._pending = []

        outcomes: list[JobOutcome] = []

        if static_jobs:
            with ThreadPoolExecutor(max_workers=self.static_workers) as pool:
                futures = [pool.submit(self._run_job, j) for j in static_jobs]
                for fut in as_completed(futures):
                    outcome = fut.result()
                    outcomes.append(outcome)
                    if on_result:
                        on_result(outcome)

        if dynamic_jobs:
            with ThreadPoolExecutor(max_workers=self.dynamic_workers) as pool:
                futures = [pool.submit(self._run_dynamic, j) for j in dynamic_jobs]
                for fut in as_completed(futures):
                    outcome = fut.result()
                    outcomes.append(outcome)
                    if on_result:
                        on_result(outcome)

        return outcomes
