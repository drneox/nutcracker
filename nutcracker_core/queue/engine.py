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
import re
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


def _resolve_local_apk(target: str) -> str | None:
    """Si ``target`` es un package ID con un APK ya descargado en
    ``downloads/<package>/``, devuelve la ruta al APK base (reutilizando la
    misma heurística que ``downloader._find_downloaded_apk``).

    Esto permite que un job encolado desde el dashboard con un package ID
    (no una ruta de archivo) reutilice un APK descargado previamente en vez
    de forzar una nueva descarga que puede fallar (credenciales, región,
    app retirada de Google Play, etc.).

    Retorna ``None`` si no hay APK local reusable.
    """
    # Caso 1: target ya es una ruta a un .apk existente → ya es local
    if _is_local_apk(target):
        return target

    # Caso 2: target no parece un package ID → no hay nada que resolver
    if "/" in target or "\\" in target or target.lower().endswith(".apk"):
        return None
    # Debe verse como un package ID (ej. com.example.app)
    if not target or "." not in target:
        return None

    downloads_dir = Path("downloads") / target
    if not downloads_dir.is_dir():
        return None

    # APK con nombre del paquete (formato apkeep >= 0.18)
    pkg_apk = downloads_dir / f"{target}.apk"
    if pkg_apk.exists():
        return str(pkg_apk)

    # base.apk (formato App Bundle clásico)
    base_apk = downloads_dir / "base.apk"
    if base_apk.exists():
        return str(base_apk)

    # Cualquier .apk que NO sea split/config (heurística)
    for apk in sorted(downloads_dir.glob("*.apk"), key=os.path.getmtime, reverse=True):
        name_lower = apk.name.lower()
        if "config." not in name_lower and "split_" not in name_lower:
            return str(apk)

    return None


# Marcadores usados por _extract_error_summary para reconocer líneas que
# probablemente son la causa raíz real de un fallo.
_ERROR_MARKERS = ("error", "failed", "traceback", "exception", "no route to host",
                   "permission denied", "timed out", "timeout", "refused")

# Defensa en profundidad: aunque _run_job fuerza NO_COLOR=1 en el subproceso,
# una herramienta de terceros (semgrep, androguard, ...) podría ignorar esa
# convención y forzar color igual (p.ej. flags propios tipo --color=always).
# Sin esto, esos códigos ANSI crudos terminan como texto literal en el panel
# de logs en vivo del dashboard (visto en vivo: el banner ASCII-art coloreado
# de nutcracker se volcaba como un bloque de texto ilegible en el navegador).
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _extract_error_summary(output: str, max_len: int = 2000) -> str:
    """Extrae un resumen útil del output de un job fallido.

    FIX (prueba con dispositivo físico real, 2026-07-24): un simple
    output[-max_len:] pierde la causa raíz real cuando el proceso sigue
    imprimiendo (tablas de hallazgos, banners) después del error — se vio en
    vivo con un fallo de conexión Frida ("No route to host") tapado por una
    tabla de vulnerabilidades posterior, dejando en `error` solo un fragmento
    ilegible de esa tabla. Prioriza líneas que parecen errores reales, y
    completa con el tail normal como contexto.
    """
    output = output.strip()
    if not output:
        return ""
    lines = output.splitlines()
    flagged = list(dict.fromkeys(
        line.strip() for line in lines if any(m in line.lower() for m in _ERROR_MARKERS)
    ))
    tail = output[-max_len:]
    if not flagged:
        return tail
    flagged_text = "\n".join(flagged)[: max_len // 2]
    remaining = max_len - len(flagged_text) - len("\n---\n")
    return f"{flagged_text}\n---\n{tail[-remaining:]}"


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
        # Variables de entorno extra (Fase 3, dashboard) fusionadas en el env
        # de cada subproceso de job -- p.ej. NUTCRACKER_DASHBOARD_URL, que el
        # agente aipwn usa para el polling del mailbox de chat (ver
        # plugins/dashboard/__init__.py y plugins/aipwn/frida_agent.py). Vacío
        # (default) preserva el env tal cual para quien no lo use.
        self.extra_env: dict[str, str] = {}

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

        # FIX (2026-07-27): si el target es un package ID (no una ruta .apk),
        # intenta resolverlo a un APK ya descargado en downloads/<package>/
        # antes de construir el comando. Esto evita que el dashboard fuerce
        # una nueva descarga (que falla si no hay credenciales o la app no
        # está disponible) cuando el APK ya existe localmente.
        effective_target = job.target
        effective_is_local = job.is_local_apk
        if not effective_is_local and job.kind != "aipwn":
            resolved = _resolve_local_apk(job.target)
            if resolved:
                _log.info("job #%s: reusing local APK %s for package %s",
                          job.db_id, resolved, job.target)
                effective_target = resolved
                effective_is_local = True

        cmd = orch.build_job_cmd(
            effective_target,
            is_local_apk=effective_is_local,
            config_path=self.config_path,
            static_only=(job.kind == "static"),
            dynamic_checks=(job.kind == "dynamic"),
            serial=job.serial,
            aipwn=(job.kind == "aipwn"),
        )
        env = dict(os.environ)
        env["NUTCRACKER_QUEUE_JOB_ID"] = str(job.db_id)
        # El job corre desapegado de cualquier terminal (stdout va a un pipe que
        # termina en el panel de logs del dashboard). Si el proceso padre heredó
        # FORCE_COLOR/COLORTERM (p.ej. terminal de VS Code), rich igual emite
        # ANSI truecolor real hacia el pipe -- NO_COLOR es lo único que rich
        # respeta por encima de FORCE_COLOR, y evita volcar códigos de color
        # crudos como texto en el navegador.
        env["NO_COLOR"] = "1"
        env.pop("FORCE_COLOR", None)
        env.update(self.extra_env)

        _log.info("job #%s: %s", job.db_id, " ".join(cmd))
        if self.on_line is not None:
            proc = self._run_streaming(job.db_id, cmd, env)
        else:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        ok = proc.returncode == 0
        error = "" if ok else _extract_error_summary(_strip_ansi(proc.stderr or proc.stdout or ""))

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
        for raw_line in proc.stdout:
            lines.append(raw_line)
            self.on_line(job_id, _strip_ansi(raw_line.rstrip("\n")))  # type: ignore[misc]
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
        # "aipwn" corre exclusivo sobre el mismo dispositivo físico que los
        # checks dinámicos (Frida) -- comparte el lock por serial con "dynamic".
        dynamic_jobs = [j for j in self._pending if j.kind in ("dynamic", "aipwn")]
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