"""Ensambla la app FastAPI del dashboard: REST (api.py) + WebSockets (ws.py) +
el SPA estático (static/index.html) — todo servido local, sin CDN.

Si se pasa ``auth`` (config de login resuelta desde ``dashboard.auth``, ver
auth.py), se monta el middleware que exige sesión en TODA request/WS salvo la
pantalla de login, más los endpoints ``/login`` / ``/api/login`` /
``/api/logout``. Sin ``auth`` el dashboard queda abierto (uso local/dev)."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from nutcracker_core.queue.engine import QueueEngine

from . import ws
from .api import create_router
from .auth import AuthConfig, AuthMiddleware

_STATIC_DIR = Path(__file__).parent / "static"


class _LoginPayload(BaseModel):
    username: str
    password: str


def create_app(
    db_path: str,
    engine: QueueEngine,
    default_serial: str | None = None,
    auth: AuthConfig | None = None,
) -> FastAPI:
    app = FastAPI(title="nutcracker dashboard")

    # ws.py necesita saber la config de auth para chequear el cookie en el
    # handshake WebSocket (defensa en profundidad además del middleware).
    ws.set_auth(auth)

    app.include_router(create_router(db_path=db_path, engine=engine, default_serial=default_serial))
    app.include_router(ws.router)

    if auth is not None:
        _add_auth_routes(app, auth)
        # El middleware se agrega DESPUÉS de las rutas -- en Starlette el
        # último middleware agregado es el más externo, así envuelve todo.
        app.add_middleware(AuthMiddleware, auth=auth)

    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(str(_STATIC_DIR / "index.html"))

    return app


def _add_auth_routes(app: FastAPI, auth: AuthConfig) -> None:
    @app.get("/login")
    def login_page() -> FileResponse:
        return FileResponse(str(_STATIC_DIR / "login.html"))

    @app.post("/api/login")
    def login(payload: _LoginPayload) -> Response:
        if not auth.check_login(payload.username, payload.password):
            return JSONResponse({"detail": "invalid credentials"}, status_code=401)
        resp = JSONResponse({"ok": True})
        name, value = auth.issue_cookie_header(payload.username)
        resp.headers.append(name, value)
        return resp

    @app.post("/api/logout")
    def logout() -> Response:
        resp = JSONResponse({"ok": True})
        name, value = auth.clear_cookie_header()
        resp.headers.append(name, value)
        return resp
