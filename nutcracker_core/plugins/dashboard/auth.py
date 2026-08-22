"""Autenticación del dashboard — login por sesión, sin dependencias externas.

Diseñado para el despliegue en VPS público (ver deploy/README.md): sin esto,
cualquiera con la URL puede operar el dashboard (encolar jobs, manejar el relay
al dispositivo, leer reportes). itsdangerous NO está instalado en el entorno,
así que todo acá usa solo la stdlib (`hmac`/`hashlib`/`secrets`).

Modelo:
  - Credenciales (usuario + hash de contraseña) en `config.yaml`
    (`dashboard.auth`), nunca en texto plano en el repo — el hash se genera con
    `nutcracker dashboard-hash-password`.
  - Al hacer login se emite un token de sesión firmado con HMAC-SHA256
    (payload = usuario:expiración, firma = HMAC con `secret_key`) guardado en
    una cookie HttpOnly. No hay estado de sesión en el servidor: el token se
    autovalida por la firma, así que reiniciar el server no requiere re-login
    mientras el `secret_key` sea fijo (ver config).
  - Un `internal_token` aparte (machine credential, generado al arrancar) deja
    que el subproceso aipwn local llame a la API sin cookie — NECESARIO porque
    detrás de Caddy todas las requests llegan desde 127.0.0.1, así que no se
    puede distinguir "local" de "proxeado" por IP para eximir al subproceso.

El middleware protege TODO (REST, WS y el SPA) salvo la propia pantalla de
login y sus endpoints. Se activa solo si `dashboard.auth.enabled` es true en
config — sin config de auth el dashboard sigue abierto (uso local/dev, y los
tests existentes no se rompen).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookies
import json
import secrets
import time
from dataclasses import dataclass

# ── Hashing de contraseñas (pbkdf2-sha256, stdlib) ──────────────────────────

_PBKDF2_ITERATIONS = 240_000
_HASH_PREFIX = "pbkdf2_sha256"


def hash_password(password: str, *, iterations: int = _PBKDF2_ITERATIONS) -> str:
    """Devuelve un hash con sal en formato ``pbkdf2_sha256$iters$salt$hash``
    (todo base64 url-safe). Guardá SOLO esto en config.yaml, nunca la
    contraseña en texto plano."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_HASH_PREFIX}${iterations}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Compara ``password`` contra un hash generado por :func:`hash_password`.
    Constante en tiempo (``hmac.compare_digest``). Cualquier hash malformado
    devuelve False en vez de tirar excepción."""
    try:
        prefix, iters_s, salt_b64, hash_b64 = stored.split("$")
        if prefix != _HASH_PREFIX:
            return False
        iterations = int(iters_s)
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
    except (ValueError, TypeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expected)


# ── Tokens de sesión firmados (HMAC-SHA256, stateless) ──────────────────────

def make_session_token(username: str, secret_key: str, ttl_seconds: int) -> str:
    """Emite ``b64(username:expiry).b64(hmac)``. ``expiry`` es epoch absoluto."""
    expiry = int(time.time()) + int(ttl_seconds)
    payload = f"{username}:{expiry}".encode("utf-8")
    sig = _sign(payload, secret_key)
    return f"{_b64e(payload)}.{_b64e(sig)}"


def verify_session_token(token: str, secret_key: str) -> str | None:
    """Valida firma y expiración. Devuelve el ``username`` si el token es
    válido y no expiró, o ``None`` en cualquier otro caso (firma inválida,
    expirado, malformado). Constante en tiempo para la comparación de firma."""
    try:
        payload_b64, sig_b64 = token.split(".")
        payload = _b64d(payload_b64)
        sig = _b64d(sig_b64)
    except (ValueError, TypeError):
        return None
    expected_sig = _sign(payload, secret_key)
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        username, expiry_s = payload.decode("utf-8").rsplit(":", 1)
        expiry = int(expiry_s)
    except (ValueError, UnicodeDecodeError):
        return None
    if time.time() >= expiry:
        return None
    return username


def _sign(payload: bytes, secret_key: str) -> bytes:
    return hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).digest()


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


# ── Config de auth ──────────────────────────────────────────────────────────

COOKIE_NAME = "nutcracker_session"
INTERNAL_HEADER = "x-nutcracker-token"


@dataclass(frozen=True)
class AuthConfig:
    """Configuración de auth resuelta desde ``dashboard.auth`` de config.yaml.

    ``internal_token`` NO viene de config: lo genera el arranque del dashboard
    y se lo inyecta al subproceso aipwn por env var (ver plugins/dashboard/
    __init__.py). ``secure_cookie`` marca la cookie como Secure (solo HTTPS) —
    en el VPS detrás de Caddy va siempre en True."""

    username: str
    password_hash: str
    secret_key: str
    session_ttl_seconds: int
    internal_token: str
    secure_cookie: bool = True

    @classmethod
    def from_config(
        cls,
        auth_cfg: dict,
        *,
        internal_token: str,
        secure_cookie: bool = True,
    ) -> "AuthConfig | None":
        """Construye la config desde el sub-dict ``dashboard.auth``. Devuelve
        None si auth está deshabilitada (o el bloque no existe) — el dashboard
        arranca sin protección en ese caso (uso local/dev)."""
        if not auth_cfg or not auth_cfg.get("enabled"):
            return None
        username = str(auth_cfg.get("username", "")).strip()
        password_hash = str(auth_cfg.get("password_hash", "")).strip()
        if not username or not password_hash:
            raise ValueError(
                "dashboard.auth.enabled=true pero falta username o password_hash "
                "(generá el hash con `nutcracker dashboard-hash-password`)."
            )
        secret_key = str(auth_cfg.get("secret_key", "")).strip()
        if not secret_key:
            # Sin secret_key fijo las sesiones no sobreviven un reinicio (cada
            # arranque firma con una clave nueva) -- aceptable, pero se avisa.
            secret_key = secrets.token_urlsafe(48)
        session_hours = float(auth_cfg.get("session_hours", 12) or 12)
        return cls(
            username=username,
            password_hash=password_hash,
            secret_key=secret_key,
            session_ttl_seconds=int(session_hours * 3600),
            internal_token=internal_token,
            secure_cookie=secure_cookie,
        )

    def check_login(self, username: str, password: str) -> bool:
        """True si las credenciales coinciden. Compara el usuario en tiempo
        constante también, para no filtrar cuál de los dos falló."""
        user_ok = hmac.compare_digest(username.encode("utf-8"), self.username.encode("utf-8"))
        pass_ok = verify_password(password, self.password_hash)
        return user_ok and pass_ok

    def issue_cookie_header(self, username: str) -> tuple[str, str]:
        """Devuelve ``(nombre_header, valor)`` para setear la cookie de sesión
        firmada (HttpOnly, SameSite=Lax, Secure según config)."""
        token = make_session_token(username, self.secret_key, self.session_ttl_seconds)
        return "set-cookie", self._build_cookie(token, self.session_ttl_seconds)

    def clear_cookie_header(self) -> tuple[str, str]:
        return "set-cookie", self._build_cookie("", 0)

    def _build_cookie(self, value: str, max_age: int) -> str:
        parts = [
            f"{COOKIE_NAME}={value}",
            "Path=/",
            f"Max-Age={max_age}",
            "HttpOnly",
            "SameSite=Lax",
        ]
        if self.secure_cookie:
            parts.append("Secure")
        return "; ".join(parts)

    def authenticate_request(self, headers: dict) -> bool:
        """True si la request trae una sesión válida (cookie) o el token
        interno (header). ``headers`` es un dict de nombre-lower → valor."""
        token = headers.get(INTERNAL_HEADER)
        if token and hmac.compare_digest(token, self.internal_token):
            return True
        cookie_header = headers.get("cookie")
        if not cookie_header:
            return False
        session = _read_cookie(cookie_header, COOKIE_NAME)
        if not session:
            return False
        return verify_session_token(session, self.secret_key) is not None


def _read_cookie(cookie_header: str, name: str) -> str | None:
    try:
        jar = http.cookies.SimpleCookie()
        jar.load(cookie_header)
    except http.cookies.CookieError:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel else None


# ── Middleware ASGI (HTTP + WebSocket) ──────────────────────────────────────

# Rutas alcanzables sin sesión: la propia pantalla de login y sus endpoints.
_EXEMPT_PATHS = frozenset({"/login", "/api/login", "/api/logout", "/healthz"})


class AuthMiddleware:
    """Middleware ASGI puro que exige sesión (o token interno) en TODA request
    y handshake WebSocket, salvo las rutas de :data:`_EXEMPT_PATHS`.

    - HTTP no autenticado a ``/api/*`` → 401 JSON.
    - HTTP no autenticado a cualquier otra ruta (el SPA) → 302 a ``/login``.
    - WebSocket no autenticado → se rechaza el handshake (close 1008).
    """

    def __init__(self, app, auth: AuthConfig) -> None:
        self.app = app
        self.auth = auth

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        headers = _scope_headers(scope)

        if path in _EXEMPT_PATHS or self.auth.authenticate_request(headers):
            await self.app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            # Rechazar el handshake sin aceptarlo (ASGI: close antes de accept).
            await send({"type": "websocket.close", "code": 1008})
            return

        if path.startswith("/api/") or path.startswith("/ws/"):
            await _send_json(send, 401, {"detail": "authentication required"})
            return
        await _send_redirect(send, "/login")


def _scope_headers(scope) -> dict:
    """Aplana los headers ASGI (lista de tuplas bytes) a dict nombre-lower→str.
    Si un header se repite (p.ej. varias cookies) toma el último — suficiente
    para cookie/token, que no se repiten en la práctica del navegador."""
    out: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        out[raw_name.decode("latin-1").lower()] = raw_value.decode("latin-1")
    return out


async def _send_json(send, status: int, body: dict) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": payload})


async def _send_redirect(send, location: str) -> None:
    await send({
        "type": "http.response.start",
        "status": 302,
        "headers": [(b"location", location.encode("latin-1"))],
    })
    await send({"type": "http.response.body", "body": b""})


def websocket_authenticated(websocket, auth: "AuthConfig | None") -> bool:
    """Chequeo de auth reutilizable desde un endpoint WebSocket (además del
    middleware, como defensa en profundidad y para tests que montan el
    endpoint suelto). Con ``auth=None`` (sin protección) siempre True."""
    if auth is None:
        return True
    headers = {k.lower(): v for k, v in websocket.headers.items()}
    return auth.authenticate_request(headers)
