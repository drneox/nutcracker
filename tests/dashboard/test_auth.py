"""Tests de la autenticación del dashboard (login por sesión, ver
plugins/dashboard/auth.py). Cubre el módulo puro (hashing, tokens, config) y
el flujo end-to-end vía TestClient (login → cookie → acceso; token interno;
rechazo de WS no autenticado; retrocompatibilidad sin auth)."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from nutcracker_core.plugins.dashboard import auth as auth_mod
from nutcracker_core.plugins.dashboard.auth import (
    AuthConfig,
    hash_password,
    make_session_token,
    verify_password,
    verify_session_token,
)
from nutcracker_core.plugins.dashboard.server import create_app
from nutcracker_core.queue.engine import QueueEngine


# ── Hashing de contraseñas ──────────────────────────────────────────────────

def test_hash_password_roundtrip():
    h = hash_password("correct horse battery staple")
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password("correct horse battery staple", h)


def test_hash_password_wrong_password_fails():
    h = hash_password("s3cret")
    assert not verify_password("s3cr3t", h)
    assert not verify_password("", h)


def test_hash_password_unique_salt():
    """Dos hashes de la misma contraseña difieren (sal aleatoria) pero ambos
    verifican."""
    a = hash_password("same")
    b = hash_password("same")
    assert a != b
    assert verify_password("same", a)
    assert verify_password("same", b)


def test_verify_password_malformed_hash_is_false():
    assert not verify_password("x", "garbage")
    assert not verify_password("x", "pbkdf2_sha256$notanint$aa$bb")
    assert not verify_password("x", "md5$1$aa$bb")
    assert not verify_password("x", "")


# ── Tokens de sesión ────────────────────────────────────────────────────────

def test_session_token_roundtrip():
    tok = make_session_token("admin", "secret", 3600)
    assert verify_session_token(tok, "secret") == "admin"


def test_session_token_wrong_secret():
    tok = make_session_token("admin", "secret", 3600)
    assert verify_session_token(tok, "other") is None


def test_session_token_expired():
    tok = make_session_token("admin", "secret", -1)
    assert verify_session_token(tok, "secret") is None


def test_session_token_tampered_signature():
    tok = make_session_token("admin", "secret", 3600)
    payload, sig = tok.split(".")
    tampered = payload + "." + ("A" * len(sig))
    assert verify_session_token(tampered, "secret") is None


def test_session_token_tampered_payload():
    """Cambiar el usuario en el payload invalida la firma."""
    tok = make_session_token("admin", "secret", 3600)
    _, sig = tok.split(".")
    forged = auth_mod._b64e(b"root:" + str(int(time.time()) + 3600).encode()) + "." + sig
    assert verify_session_token(forged, "secret") is None


def test_session_token_malformed():
    assert verify_session_token("no-dot", "secret") is None
    assert verify_session_token("", "secret") is None


# ── AuthConfig ──────────────────────────────────────────────────────────────

def test_authconfig_disabled_returns_none():
    assert AuthConfig.from_config({"enabled": False}, internal_token="x") is None
    assert AuthConfig.from_config({}, internal_token="x") is None
    assert AuthConfig.from_config(None, internal_token="x") is None


def test_authconfig_enabled_without_credentials_raises():
    with pytest.raises(ValueError):
        AuthConfig.from_config({"enabled": True, "username": "admin"}, internal_token="x")
    with pytest.raises(ValueError):
        AuthConfig.from_config(
            {"enabled": True, "password_hash": hash_password("p")}, internal_token="x"
        )


def test_authconfig_check_login():
    h = hash_password("pw")
    cfg = AuthConfig.from_config(
        {"enabled": True, "username": "admin", "password_hash": h, "secret_key": "k"},
        internal_token="itok",
    )
    assert cfg.check_login("admin", "pw")
    assert not cfg.check_login("admin", "bad")
    assert not cfg.check_login("root", "pw")


def test_authconfig_authenticate_request_internal_token():
    cfg = _cfg()
    assert cfg.authenticate_request({"x-nutcracker-token": "itok"})
    assert not cfg.authenticate_request({"x-nutcracker-token": "wrong"})
    assert not cfg.authenticate_request({})


def test_authconfig_authenticate_request_cookie():
    cfg = _cfg()
    _, cookie = cfg.issue_cookie_header("admin")
    session_value = cookie.split(";")[0].split("=", 1)[1]
    assert cfg.authenticate_request({"cookie": f"nutcracker_session={session_value}"})
    assert not cfg.authenticate_request({"cookie": "nutcracker_session=forged"})
    assert not cfg.authenticate_request({"cookie": "other=1"})


def _cfg() -> AuthConfig:
    return AuthConfig.from_config(
        {
            "enabled": True,
            "username": "admin",
            "password_hash": hash_password("pw"),
            "secret_key": "fixedkey",
        },
        internal_token="itok",
        secure_cookie=False,
    )


# ── Flujo end-to-end vía TestClient ─────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "auth_test.db")


@pytest.fixture
def engine(db_path):
    return QueueEngine(config_path="config.yaml", db_path=db_path, static_workers=1)


@pytest.fixture
def auth_app(db_path, engine):
    return create_app(db_path=db_path, engine=engine, auth=_cfg())


def test_unauthenticated_api_returns_401(auth_app):
    c = TestClient(auth_app)
    assert c.get("/api/summary").status_code == 401


def test_unauthenticated_spa_redirects_to_login(auth_app):
    c = TestClient(auth_app)
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_login_page_reachable_without_auth(auth_app):
    c = TestClient(auth_app)
    r = c.get("/login")
    assert r.status_code == 200
    assert "login-form" in r.text


def test_login_wrong_credentials_401(auth_app):
    c = TestClient(auth_app)
    r = c.post("/api/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401


def test_login_then_access_and_logout(auth_app):
    c = TestClient(auth_app)
    r = c.post("/api/login", json={"username": "admin", "password": "pw"})
    assert r.status_code == 200
    # La cookie quedó en el jar del cliente -> ahora la API responde.
    assert c.get("/api/summary").status_code == 200
    # Logout borra la cookie -> vuelve a 401.
    assert c.post("/api/logout").status_code == 200
    assert c.get("/api/summary").status_code == 401


def test_internal_token_bypass(auth_app):
    c = TestClient(auth_app)
    assert c.get("/api/summary", headers={"X-Nutcracker-Token": "itok"}).status_code == 200
    assert c.get("/api/summary", headers={"X-Nutcracker-Token": "bad"}).status_code == 401


def test_websocket_rejected_without_auth(auth_app):
    from starlette.websockets import WebSocketDisconnect

    c = TestClient(auth_app)
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/ws/jobs/1"):
            pass


def test_websocket_accepted_with_session_cookie(auth_app):
    c = TestClient(auth_app)
    c.post("/api/login", json={"username": "admin", "password": "pw"})
    # El TestClient reenvía la cookie del jar en el handshake WS.
    with c.websocket_connect("/ws/jobs/does-not-exist") as ws:
        # Conexión aceptada (job sin historial: no manda nada, pero no cierra
        # con 1008). Cerrar limpio desde el cliente.
        ws.close()


def test_no_auth_config_leaves_dashboard_open(db_path, engine):
    """Retrocompatibilidad: sin `auth`, el dashboard no exige login (uso
    local/dev, y los tests existentes siguen pasando)."""
    app = create_app(db_path=db_path, engine=engine)  # auth=None
    c = TestClient(app)
    assert c.get("/api/summary").status_code == 200
    assert c.get("/login").status_code == 404  # ruta de login no montada
