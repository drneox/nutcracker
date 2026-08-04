"""API REST del dashboard (Fase 3 del plan) — solo lee el store y drive la cola
a través de sus APIs públicas (QueueEngine), nunca reimplementa análisis."""

from __future__ import annotations

import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from nutcracker_core import adb_transport
from nutcracker_core.queue.engine import QueueEngine
from nutcracker_core.store import db, repository

# aipwn es un plugin opcional (repo git separado, puede no estar presente en
# el checkout) -- import perezoso/tolerante para no romper el resto del
# dashboard si falta.
try:
    from nutcracker_core.plugins.aipwn import agent_memory
except ImportError:
    agent_memory = None

from . import chat_mailbox, store_reader
from .events import bus
from .relay import RelayError, RpcError, RpcTimeoutError, relay_manager


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


class RelayShellPayload(BaseModel):
    command: str
    timeout: float = 30.0


class RelayApkPayload(BaseModel):
    name: str
    data_b64: str


class RelayInstallPayload(BaseModel):
    apks: list[RelayApkPayload]
    flags: list[str] = []
    multi: bool = False
    timeout: float = 120.0


class RelayPullPayload(BaseModel):
    remote_path: str
    timeout: float = 180.0


class RelayScreencapPayload(BaseModel):
    timeout: float = 30.0


class RelayLogcatPayload(BaseModel):
    args: list[str] = []
    duration_seconds: float = 30.0
    timeout: float = 40.0


class QueuePayload(BaseModel):
    target: str
    kind: str = "static"
    serial: str | None = None
    source: str | None = None
    run_now: bool = False
    # Relay "browser-as-bridge" (plan.md): si True, ``serial`` no es un serial
    # adb directo sino el session_id de una sesión de relay ya conectada
    # (ver /ws/relay/{session_id}) -- queue_add la resuelve a los puertos
    # locales del túnel antes de encolar (ver más abajo).
    relay: bool = False


class QueueBatchPayload(BaseModel):
    targets: list[str]
    source: str | None = None
    serial: str | None = None
    then_aipwn: bool = True


def _require_attached_relay_session(session_id: str):
    """Sesión de relay con navegador conectado, o 404 -- chequeo repetido por
    los 4 endpoints RPC (shell/install/pull/screencap), factorizado acá."""
    session = relay_manager.get(session_id)
    if session is None or not session.attached:
        raise HTTPException(
            status_code=404,
            detail=f"no hay un navegador con el relay conectado para '{session_id}'.",
        )
    return session


async def _run_relay_rpc(session, op: str, **fields):
    """``session.rpc(op, **fields)`` con el mismo mapeo de errores a HTTP en
    los 4 endpoints RPC -- factorizado para no repetirlo cuatro veces."""
    try:
        return await session.rpc(op, **fields)
    except RpcTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except RpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except RelayError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


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

    @router.post("/api/adb/kill-server")
    def adb_kill_server():
        """Mata el daemon adb por las dos vías (WSL + Windows, ver
        adb_transport.kill_server()) -- botón "🔪 adb kill-server" de la
        pestaña Dispositivo, para soltar el cable USB antes de conectar
        WebUSB sin que el operador tenga que abrir una terminal aparte."""
        return adb_transport.kill_server()

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

    @router.get("/api/apps/{package}/findings")
    def app_consolidated_findings(package: str):
        """Hallazgos deduplicados de TODAS las corridas de un paquete, con
        estado present/resolved (ver store_reader.consolidated_findings_for_app)."""
        conn = _conn()
        try:
            return store_reader.consolidated_findings_for_app(conn, package)
        finally:
            conn.close()

    @router.get("/api/apps/{package}/runs")
    def app_runs(package: str, limit: int = 50):
        """Historial de análisis de un paquete -- sección "Historial" del
        modal de detalle de app (ver store_reader.list_runs_for_app)."""
        conn = _conn()
        try:
            return store_reader.list_runs_for_app(conn, package, limit=limit)
        finally:
            conn.close()

    @router.get("/api/runs/{run_id}/download/{artifact_type}")
    def run_download(run_id: int, artifact_type: str):
        """Descarga el JSON o PDF de un run puntual.

        El PDF es un archivo canónico por *paquete* (se sobreescribe en cada
        análisis, ver store_reader.list_runs_for_app) -- si el run pedido no
        es el más reciente, esto sirve igual el PDF más reciente que exista
        en disco para ese run_id, porque es lo único que hay: no existe un
        PDF histórico por run. El frontend decide cuándo tiene sentido
        mostrar ese botón (solo en el run más reciente) para no confundir."""
        if artifact_type not in ("json", "pdf"):
            raise HTTPException(404, f"Tipo de artefacto inválido: {artifact_type!r}")
        conn = _conn()
        try:
            artifacts = repository.artifacts_for_run(conn, run_id)
        finally:
            conn.close()
        match = next((a for a in artifacts if a["type"] == artifact_type), None)
        if match is None:
            raise HTTPException(404, f"No hay artefacto '{artifact_type}' para el run #{run_id}")
        path = Path(match["path"])
        if not path.exists():
            raise HTTPException(404, f"El archivo ya no existe en disco: {path}")
        return FileResponse(path, filename=path.name)

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
            jobs = [dict(r) for r in repository.list_jobs(conn, status=status, limit=limit)]
        finally:
            conn.close()
        # "resumable": el job aipwn de este target terminó sin conclusión
        # (límite de iteraciones, LLM cortado) y hay una sesión guardada para
        # continuar -- ver agent_memory.save_resume_state(). Solo tiene
        # sentido para el job MÁS RECIENTE de cada target: si alguien ya lo
        # reanudó y volvió a terminar sin conclusión, el estado guardado ahora
        # es el de esa corrida nueva, no la vieja -- no marcar ambas.
        _latest_aipwn_id_by_target: dict[str, int] = {}
        for j in jobs:
            if j["kind"] == "aipwn":
                _latest_aipwn_id_by_target.setdefault(j["target"], j["id"])
        for j in jobs:
            j["resumable"] = bool(
                agent_memory is not None
                and j["kind"] == "aipwn"
                and _latest_aipwn_id_by_target.get(j["target"]) == j["id"]
                and agent_memory.has_resume_state(j["target"])
            )
        return jobs

    @router.get("/api/relay/{session_id}")
    def relay_status(session_id: str):
        """Estado de una sesión de relay (ver relay.py) -- el navegador debe
        estar conectado a ``/ws/relay/{session_id}`` para que exista. Usado
        por el frontend antes de ofrecer "encolar con relay", y por
        ``queue_add`` para resolver ``payload.relay=True``."""
        session = relay_manager.get(session_id)
        if session is None:
            raise HTTPException(
                status_code=404,
                detail=f"no hay sesión de relay para '{session_id}' -- conectá el "
                       "navegador a /ws/relay/{session_id} primero (WebUSB).",
            )
        return {"session_id": session_id, "attached": session.attached, "ports": session.ports}

    @router.post("/api/relay/{session_id}/rpc/shell")
    async def relay_rpc_shell(session_id: str, payload: RelayShellPayload):
        """Ejecuta un comando `adb shell` a través del relay -- usado por el
        shim de adb (ver toolbox/relay_adb_shim/adb), nunca directo por un
        operador. Reemplaza el túnel TCP crudo original para adb: Android
        bloquea el reenvío `tcp:` hacia el propio puerto de control de adbd
        (verificado en vivo), así que esto va como RPC estructurado -- el
        navegador lo resuelve con `adb.subprocess.spawnAndWait()` (métodos
        nativos de Tango, el mismo mecanismo que ya usa scrcpy/app.webadb.com,
        no una técnica nueva sin probar)."""
        session = _require_attached_relay_session(session_id)
        result = await _run_relay_rpc(session, "shell", command=payload.command, timeout=payload.timeout)
        return {
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "exit_code": result.get("exit_code", 0),
        }

    @router.post("/api/relay/{session_id}/rpc/install")
    async def relay_rpc_install(session_id: str, payload: RelayInstallPayload):
        """Instala uno (`install`) o varios (`install-multiple`) APKs a través
        del relay -- usado por el shim de adb. El navegador sube cada APK al
        device con `adb.sync().write()` (Etapa 2 del plan) a
        `/data/local/tmp/<nombre>`, corre `pm install[-multiple] <flags>
        <rutas>`, y borra los temporales -- mismos métodos nativos de Tango
        que shell/pull, no un socket crudo."""
        session = _require_attached_relay_session(session_id)
        result = await _run_relay_rpc(
            session, "install",
            apks=[a.model_dump() for a in payload.apks],
            flags=payload.flags, multi=payload.multi, timeout=payload.timeout,
        )
        return {
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "exit_code": result.get("exit_code", 0),
        }

    @router.post("/api/relay/{session_id}/rpc/pull")
    async def relay_rpc_pull(session_id: str, payload: RelayPullPayload):
        """Trae un archivo del device (`adb pull`) a través del relay -- el
        navegador lo lee con `adb.sync().read()` y lo manda en base64 (Etapa
        4 del plan). El shim de adb lo escribe en la ruta local que pidió el
        caller."""
        session = _require_attached_relay_session(session_id)
        result = await _run_relay_rpc(session, "pull", remote_path=payload.remote_path, timeout=payload.timeout)
        return {"data_b64": result.get("data_b64", "")}

    @router.post("/api/relay/{session_id}/rpc/screencap")
    async def relay_rpc_screencap(session_id: str, payload: RelayScreencapPayload):
        """Captura pantalla (`adb exec-out screencap -p`) a través del relay
        -- el navegador corre `screencap -p` y devuelve los bytes PNG crudos
        en base64 (Etapa 3 del plan), sin pasar por decodificación de texto
        (que corrompería el binario)."""
        session = _require_attached_relay_session(session_id)
        result = await _run_relay_rpc(session, "screencap", timeout=payload.timeout)
        return {"data_b64": result.get("data_b64", "")}

    @router.post("/api/relay/{session_id}/rpc/logcat")
    async def relay_rpc_logcat(session_id: str, payload: RelayLogcatPayload):
        """Captura logcat acotada en el tiempo a través del relay -- reemplaza
        `adb logcat` en modo streaming (Etapa 5 del plan). No es streaming
        real línea-a-línea: aipwn solo consume el log DESPUÉS de la ventana
        de captura de todos modos (ver frida_capture.py::stream_logcat), así
        que el navegador junta las líneas durante `duration_seconds` y las
        manda todas juntas en un solo `rpc_response` -- mismo patrón que
        shell/install/pull/screencap, sin protocolo de streaming nuevo."""
        session = _require_attached_relay_session(session_id)
        result = await _run_relay_rpc(
            session, "logcat", args=payload.args,
            duration_seconds=payload.duration_seconds, timeout=payload.timeout,
        )
        return {"stdout": result.get("stdout", "")}

    @router.post("/api/queue")
    def queue_add(payload: QueuePayload):
        serial = payload.serial
        frida_host = None
        relay_session_id = None
        if payload.relay:
            if not serial:
                raise HTTPException(
                    status_code=400,
                    detail="relay=true requiere 'serial' con el session_id de una "
                           "sesión de relay conectada.",
                )
            session = relay_manager.get(serial)
            if session is None or not session.attached:
                raise HTTPException(
                    status_code=400,
                    detail=f"no hay un navegador con el relay conectado para '{serial}' "
                           "-- abrí el dashboard, conectá el device por WebUSB, y "
                           "activá el túnel antes de encolar este job.",
                )
            # `serial` NO se reescribe a una dirección de loopback -- queda
            # como el session_id tal cual (ver Job.relay_session_id: el shim
            # de adb lo ignora igual, y así is_network_serial() no lo confunde
            # con un serial de red real). frida_host sí sigue siendo una
            # dirección real -- el túnel TCP crudo de frida funciona bien
            # (27042 no es el puerto de control de adbd, ver relay.py).
            relay_session_id = serial
            frida_host = f"127.0.0.1:{session.ports['frida']}"
        try:
            job = engine.submit(
                payload.target, kind=payload.kind, serial=serial, source=payload.source,
                frida_host=frida_host, relay_session_id=relay_session_id,
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

    @router.post("/api/queue/{job_id}/resume-aipwn")
    def queue_resume_aipwn(job_id: int, extra_iterations: int = 5):
        """Encola una nueva corrida de aipwn que CONTINÚA la sesión sin
        conclusión de ``job_id`` (mismo target/serial) en vez de arrancar de
        cero -- ver agent_memory.save_resume_state(). Botón "+N iteraciones"
        del dashboard."""
        if agent_memory is None:
            raise HTTPException(status_code=404, detail="plugin aipwn no instalado en este entorno")
        conn = _conn()
        try:
            job = repository.get_job(conn, job_id)
        finally:
            conn.close()
        if job is None:
            raise HTTPException(status_code=404, detail="job no encontrado")
        if job["kind"] != "aipwn":
            raise HTTPException(status_code=400, detail="solo se pueden reanudar jobs 'aipwn'")
        if not agent_memory.has_resume_state(job["target"]):
            raise HTTPException(
                status_code=404,
                detail=f"no hay sesión pendiente para reanudar de '{job['target']}'",
            )
        new_job = engine.submit(
            job["target"], kind="aipwn", serial=job["serial"],
            aipwn_resume=True, aipwn_extra_iterations=extra_iterations,
        )
        _drain_in_background(engine)
        return {"job_id": new_job.db_id}

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
