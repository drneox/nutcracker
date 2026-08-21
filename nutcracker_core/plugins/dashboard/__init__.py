"""dashboard plugin — web local (FastAPI + WebSocket + SPA) sobre el daemon de
Fase 1 (plan.md, Fase 3): lee el store SQLite y drive QueueEngine/
NutcrackerScheduler a través de sus APIs públicas, sin reimplementar nada del
análisis. Respeta la frontera core/plugin igual que aipwn/aireview.

Instalación (ya incluida en este repo, a diferencia de aipwn que es un repo
git separado): las dependencias pesadas (fastapi, uvicorn) NO se importan a
nivel de módulo a propósito -- igual que aipwn/aireview evitan importar sus
dependencias LLM en su __init__.py, para que `load_plugins()` (que intenta
importar cada plugin en CADA invocación del CLI) no dispare un `pip install`
de fastapi/uvicorn solo porque el usuario corrió `nutcracker analyze ...`. El
auto-install (mismo mecanismo que usa load_plugins, ver plugins/__init__.py)
solo se intenta cuando el usuario realmente corre `nutcracker dashboard`.
"""

from __future__ import annotations

import click


def _ensure_dashboard_deps() -> None:
    """Auto-instala fastapi/uvicorn desde requirements.txt si faltan, la
    primera vez que se corre `nutcracker dashboard` (no en cualquier otro
    comando) -- mismo mecanismo de auto-install que ya usa el plugin loader."""
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        import subprocess
        import sys
        from pathlib import Path

        req_file = Path(__file__).parent / "requirements.txt"
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-q", "-r", str(req_file)]
        )
        import importlib
        importlib.invalidate_caches()


def register(cli) -> None:
    @cli.command("dashboard-hash-password")
    @click.option(
        "--username", "-u", default=None,
        help="Usuario a incluir en el bloque YAML de ejemplo (opcional).",
    )
    def dashboard_hash_password(username: str | None) -> None:
        """Genera el hash de una contraseña para dashboard.auth.password_hash.

        Pide la contraseña sin eco por stdin, imprime el hash pbkdf2-sha256 (y
        un bloque YAML listo para pegar en config.yaml). Nunca guardes la
        contraseña en texto plano -- solo este hash va a config.
        """
        import secrets as _secrets

        from .auth import hash_password

        password = click.prompt("Contraseña", hide_input=True, confirmation_prompt=True)
        digest = hash_password(password)
        click.echo("\nHash generado:\n")
        click.echo(f"  {digest}\n")
        click.echo("Bloque para config.yaml (dashboard.auth):\n")
        click.echo("  auth:")
        click.echo("    enabled: true")
        click.echo(f"    username: {username or 'admin'}")
        click.echo(f"    password_hash: '{digest}'")
        click.echo(f"    secret_key: '{_secrets.token_urlsafe(48)}'")
        click.echo("    session_hours: 12")

    @cli.command()
    @click.option(
        "--config", "-c", "config_path",
        default="config.yaml", show_default=True,
        metavar="ARCHIVO",
    )
    @click.option(
        "--host", default=None,
        help="Bind host (default: dashboard.bind en config.yaml, o 127.0.0.1).",
    )
    @click.option(
        "--port", default=None, type=int,
        help="Puerto (default: dashboard.port en config.yaml, u 8765).",
    )
    @click.option(
        "--no-scheduler", is_flag=True, default=False,
        help="No levantar el scheduler periódico propio -- útil si "
             "`nutcracker serve` ya corre en otro proceso sobre el mismo nutcracker.db.",
    )
    def dashboard(config_path: str, host: str | None, port: int | None, no_scheduler: bool) -> None:
        """Arranca el dashboard web: API+WS+SPA sobre la misma cola/scheduler de Fase 1.

        \b
        Ejemplos:
          nutcracker dashboard
          nutcracker dashboard --port 8080 --host 0.0.0.0   # exponer en la LAN
          nutcracker dashboard --no-scheduler                # si `serve` ya corre
        """
        _ensure_dashboard_deps()

        import uvicorn

        from nutcracker_core import adb_transport
        from nutcracker_core.config import load_config, get as cfg_get
        from nutcracker_core.orchestrator import console
        from nutcracker_core.queue.engine import QueueEngine
        from nutcracker_core.scheduler import NutcrackerScheduler
        from nutcracker_core.store.hooks import db_path_from_config

        from .auth import AuthConfig
        from .events import bus
        from .server import create_app

        config = load_config(config_path)
        bind = host or str(cfg_get(config, "dashboard", "bind", default="127.0.0.1"))
        listen_port = port or int(cfg_get(config, "dashboard", "port", default=8765))

        # Auth (login por sesión) -- ver auth.py y deploy/README.md. Se activa
        # solo si `dashboard.auth.enabled` es true; sin eso el dashboard queda
        # abierto (uso local/dev). El `internal_token` es una credencial de
        # máquina generada acá y pasada al subproceso aipwn por env var, para
        # que su polling del mailbox de chat (127.0.0.1) autentique sin cookie
        # -- necesario porque detrás de Caddy toda request llega desde
        # localhost y no se puede eximir al subproceso solo por IP de origen.
        import secrets as _secrets
        internal_token = _secrets.token_urlsafe(32)
        auth_cfg_dict = cfg_get(config, "dashboard", "auth", default={}) or {}
        # secure_cookie=False solo para probar el login en local por HTTP
        # plano (dashboard.auth.secure_cookie: false en config.yaml) -- los
        # navegadores descartan cookies "Secure" fuera de HTTPS, así que con
        # el default (True) el login "funcionaría" pero la cookie nunca
        # quedaría guardada. En el VPS (detrás de HTTPS) dejar el default.
        auth = AuthConfig.from_config(
            auth_cfg_dict,
            internal_token=internal_token,
            secure_cookie=bool(auth_cfg_dict.get("secure_cookie", True)),
        )
        # strategies.default_device_id (config.yaml) llega al frontend vía
        # GET /api/config/default-serial -- así el operador lo configura una
        # sola vez (típicamente un serial de red "ip:5555" tras `adb tcpip
        # 5555`, para evitar el conflicto de exclusividad USB con WebUSB) en
        # vez de tener que escribirlo a mano en cada campo de serial del
        # dashboard (cola, batch).
        default_serial = str(cfg_get(config, "strategies", "default_device_id", default="")).strip() or None

        db_path = db_path_from_config(config)
        engine = QueueEngine(
            config_path=config_path,
            db_path=db_path,
            static_workers=int(cfg_get(config, "queue", "static_workers", default=4)),
            dynamic_workers=int(cfg_get(config, "queue", "dynamic_workers", default=2)),
        )
        # Streaming de logs en vivo (Fase 3): cada línea de stdout de un job
        # corrido por ESTA instancia de engine se publica al EventBus, que
        # /ws/jobs/{id} consume. Se asigna aquí (no en api.py/create_router) a
        # propósito -- así los tests que construyen su propio QueueEngine
        # (tests/dashboard/test_api.py) conservan on_line=None y el camino
        # subprocess.run clásico de Fase 1, en vez de pasar siempre por
        # _run_streaming/subprocess.Popen.
        engine.on_line = lambda job_id, line: bus.publish(str(job_id), "log", line)
        # Wiring del chat (Fase 3, follow-up del plan): el subproceso de un job
        # "aipwn" lee esta env var para saber a dónde hacer polling del mailbox
        # de chat (ver plugins/aipwn/frida_agent.py::_check_operator_chat).
        # Siempre 127.0.0.1: el subproceso corre en la misma máquina que este
        # comando sin importar en qué interfaz --host escuche el server real.
        engine.extra_env["NUTCRACKER_DASHBOARD_URL"] = f"http://127.0.0.1:{listen_port}"
        if auth is not None:
            # El subproceso manda este token en el header X-Nutcracker-Token
            # para autenticar su poll del mailbox (ver frida_agent.py).
            engine.extra_env["NUTCRACKER_DASHBOARD_TOKEN"] = internal_token

        # Keepalive del transporte adb-over-wifi (ver nutcracker_core/adb_transport.py).
        # El dashboard es justo el escenario donde más importa: el video WebUSB
        # se queda el cable USB, así que si el serial de red se cae, los jobs no
        # tienen por dónde hablarle al teléfono. El chequeo por-job del engine no
        # alcanza solo -- entre job y job cualquier `adb` suelto volvería a caer
        # al cable, que es exactamente el conflicto que queremos evitar.
        keepalive = adb_transport.TransportKeepAlive(
            serials=[default_serial] if default_serial else [],
            interval_seconds=int(cfg_get(config, "dashboard", "adb_keepalive_seconds", default=60)),
        )
        engine.transport_keepalive = keepalive
        keepalive.start()

        scheduler = None
        if not no_scheduler:
            scheduler = NutcrackerScheduler(engine, config)
            scheduler.start()

        # Bloque `llm:` de config.yaml -- el mismo que usa aipwn (ver
        # plugins/aipwn/__init__.py) -- reusado tal cual para el co-piloto de
        # consulta (/ws/query, plugins/aipwn/query_agent.py) en vez de pedir
        # una config de LLM aparte. Vacío/faltante = co-piloto no disponible
        # (ver api.py::query_available), sin romper el resto del dashboard.
        llm_config = cfg_get(config, "llm", default={}) or None

        app = create_app(
            db_path=db_path, engine=engine, default_serial=default_serial,
            auth=auth, llm_config=llm_config,
        )

        console.print(
            f"[bold green]✔[/bold green] nutcracker dashboard — "
            f"[bold]http://{bind}:{listen_port}[/bold] "
            f"(scheduler={'off' if no_scheduler else 'on'}, "
            f"auth={'on' if auth is not None else 'off'})"
        )
        if auth is None and bind not in ("127.0.0.1", "localhost", "::1"):
            # Expuesto fuera de localhost sin login -- cualquiera con acceso de
            # red puede operar el dashboard. Ver deploy/README.md.
            console.print(
                f"[bold yellow]⚠[/bold yellow]  Escuchando en {bind} SIN autenticación "
                "— cualquiera con acceso de red puede operar el dashboard. "
                "Configurá dashboard.auth para exigir login (ver deploy/README.md)."
            )
        try:
            uvicorn.run(app, host=bind, port=listen_port, log_level="warning")
        finally:
            keepalive.stop()
            if scheduler is not None:
                scheduler.stop()
