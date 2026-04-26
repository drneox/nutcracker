"""
Extractor de strings interesantes del código fuente decompilado.

Busca y categoriza:
  - URLs / endpoints HTTP/HTTPS
  - Direcciones IP no locales
  - Emails
  - Tokens JWT (eyJ...)
  - Strings base64 sospechosas (> 30 chars, alta entropía)
  - Package IDs de SDKs de terceros detectados
  - Números de teléfono
"""

from __future__ import annotations

import base64
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .i18n import t


# ── Patrones ──────────────────────────────────────────────────────────────────

_RE_URL = re.compile(
    r'["\'](?P<url>https?://[^\s"\'\)\(>]{8,})["\']'
)

_RE_IP = re.compile(
    r'["\'](?P<ip>(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))["\']'
)

_RE_EMAIL = re.compile(
    r'["\'](?P<email>[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["\']'
)

_RE_JWT = re.compile(
    r'["\'](?P<jwt>eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})["\']'
)

# Strings alfanuméricas largas que parecen tokens/secretos (≥ 32 chars, no URLs)
_RE_LONG_TOKEN = re.compile(
    r'["\'](?P<tok>[A-Za-z0-9+/=_\-]{32,})["\']'
)

# Package IDs de SDKs de terceros conocidos encontrados en imports/strings
_KNOWN_SDKS = {
    "com.google.firebase": "Firebase",
    "com.google.android.gms": "Google Play Services",
    "com.facebook": "Facebook SDK",
    "com.appsflyer": "AppsFlyer",
    "com.adjust": "Adjust SDK",
    "com.braze": "Braze (Appboy)",
    "com.appboy": "Braze (Appboy)",
    "io.branch": "Branch.io",
    "com.mixpanel": "Mixpanel",
    "com.amplitude": "Amplitude",
    "com.segment": "Segment",
    "com.onesignal": "OneSignal",
    "io.sentry": "Sentry",
    "com.bugsnag": "Bugsnag",
    "com.datadog": "Datadog",
    "com.newrelic": "New Relic",
    "com.squareup.okhttp": "OkHttp",
    "retrofit2": "Retrofit",
    "com.airbnb": "Airbnb SDK",
    "com.stripe": "Stripe",
    "com.paypal": "PayPal SDK",
    "io.intercom": "Intercom",
    "com.zendesk": "Zendesk",
    "com.crashlytics": "Crashlytics (Firebase)",
    "com.urbanairship": "Urban Airship",
    "net.hockeyapp": "HockeyApp (AppCenter)",
    "com.microsoft.appcenter": "App Center",
    "io.embrace": "Embrace",
    "com.guardsquare": "GuardSquare/DexGuard",
    "com.arxan": "Arxan",
}

_RE_IMPORT = re.compile(r'^import\s+([\w.]+);', re.MULTILINE)


# ── Tipos de resultado ─────────────────────────────────────────────────────────

@dataclass
class StringHit:
    value: str
    file: str
    line: int


@dataclass
class ExtractResult:
    urls: list[StringHit] = field(default_factory=list)
    ips: list[StringHit] = field(default_factory=list)
    emails: list[StringHit] = field(default_factory=list)
    jwts: list[StringHit] = field(default_factory=list)
    tokens: list[StringHit] = field(default_factory=list)   # high-entropy strings
    sdks: dict[str, str] = field(default_factory=dict)      # package → nombre SDK


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for c in s:
        counts[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_likely_secret(val: str) -> bool:
    """Heurística: entropía alta + no parece un hash SHA conocido ni una URL."""
    if len(val) < 32:
        return False
    # Excluir strings que parecen hashes hexadecimales simples
    if re.fullmatch(r'[0-9a-fA-F]+', val):
        return False
    # Excluir strings que son solo letras (probablemente texto)
    if re.fullmatch(r'[A-Za-z]+', val):
        return False
    entropy = _shannon_entropy(val)
    return entropy >= 4.0


def extract_strings(
    source_dir: Path,
    progress_callback=None,
) -> ExtractResult:
    """
    Recorre todos los .java del source_dir y extrae strings de interés.

    Args:
        source_dir: Directorio raíz del código fuente decompilado.
        progress_callback: Función(str) para mensajes de progreso.

    Returns:
        ExtractResult con todas las categorías encontradas.
    """
    result = ExtractResult()
    seen_urls: set[str] = set()
    seen_ips: set[str] = set()
    seen_emails: set[str] = set()
    seen_jwts: set[str] = set()
    seen_tokens: set[str] = set()

    java_files = list(source_dir.rglob("*.java"))
    total = len(java_files)

    # IPs locales que ignoramos
    _LOCAL_IP = re.compile(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|255\.)')

    for i, fpath in enumerate(java_files):
        if progress_callback and i % 200 == 0:
            progress_callback(t("se_extracting", current=i, total=total))

        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(fpath.relative_to(source_dir))

        # Detectar SDKs por imports
        for imp in _RE_IMPORT.findall(text):
            for pkg, name in _KNOWN_SDKS.items():
                if imp.startswith(pkg) and pkg not in result.sdks:
                    result.sdks[pkg] = name

        lines = text.splitlines()

        def _hit(val: str, line_no: int) -> StringHit:
            return StringHit(value=val, file=rel, line=line_no)

        # Buscar por línea para tener número de línea correcto
        for lineno, line in enumerate(lines, 1):
            # URLs
            for m in _RE_URL.finditer(line):
                url = m.group("url").rstrip(".,;)")
                if url not in seen_urls:
                    seen_urls.add(url)
                    result.urls.append(_hit(url, lineno))

            # IPs
            for m in _RE_IP.finditer(line):
                ip = m.group("ip")
                if not _LOCAL_IP.match(ip) and ip not in seen_ips:
                    seen_ips.add(ip)
                    result.ips.append(_hit(ip, lineno))

            # Emails
            for m in _RE_EMAIL.finditer(line):
                email = m.group("email")
                if email not in seen_emails:
                    seen_emails.add(email)
                    result.emails.append(_hit(email, lineno))

            # JWTs
            for m in _RE_JWT.finditer(line):
                jwt = m.group("jwt")
                if jwt not in seen_jwts:
                    seen_jwts.add(jwt)
                    result.jwts.append(_hit(jwt, lineno))

            # Tokens de alta entropía (excluyendo lo ya capturado como URL/JWT)
            for m in _RE_LONG_TOKEN.finditer(line):
                tok = m.group("tok")
                # Saltar si ya fue capturado como URL o JWT
                if any(tok in u.value for u in result.urls):
                    continue
                if tok in seen_jwts:
                    continue
                if _is_likely_secret(tok) and tok not in seen_tokens:
                    seen_tokens.add(tok)
                    result.tokens.append(_hit(tok, lineno))

    if progress_callback:
        progress_callback(t("se_extraction_complete"))

    return result
