"""Ensambla la app FastAPI del dashboard: REST (api.py) + WebSockets (ws.py) +
el SPA estático (static/index.html) — todo servido local, sin CDN."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from nutcracker_core.queue.engine import QueueEngine

from . import ws
from .api import create_router

_STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: str, engine: QueueEngine, default_serial: str | None = None) -> FastAPI:
    app = FastAPI(title="nutcracker dashboard")

    app.include_router(create_router(db_path=db_path, engine=engine, default_serial=default_serial))
    app.include_router(ws.router)

    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(str(_STATIC_DIR / "index.html"))

    return app
