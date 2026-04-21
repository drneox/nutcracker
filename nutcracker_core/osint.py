"""
Módulo OSINT — nutcracker.

Automatiza la recolección de inteligencia de fuentes abiertas a partir del
código decompilado de una aplicación Android:

  1. Extracción de secretos de BuildConfig (normal y ofuscado)
  2. Enumeración de subdominios vía crt.sh
  3. Búsqueda de leaks en fuentes públicas (GitHub, Postman, Wayback)
  4. Ejecución de búsquedas web (DuckDuckGo) contra dominios propios
"""

from __future__ import annotations

import json
import re
import time
import base64
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote_plus

import requests
from rich.console import Console

console = Console()

# ── Constantes ────────────────────────────────────────────────────────────────

_REQUESTS_TIMEOUT = 15
_USER_AGENT = "nutcracker-osint/0.1"

# Campos de BuildConfig que no son secretos
_BUILDCONFIG_SKIP = frozenset({
    "APPLICATION_ID", "BUILD_TYPE", "DEBUG", "FLAVOR",
    "VERSION_CODE", "VERSION_NAME", "IS_HERMES_ENABLED",
    "IS_NEW_ARCHITECTURE_ENABLED", "LIBRARY_PACKAGE_NAME",
    "FLAVOR_environment",
})

# Regex para detectar declaraciones static final String en BuildConfig
_RE_STATIC_STRING = re.compile(
    r'public\s+static\s+final\s+(?:java\.lang\.)?String\s+'
    r'(?P<name>\w+)\s*=\s*"(?P<value>[^"]+)"',
)

# Regex para detectar encodeToBase64 / Basic Auth hardcodeados
_RE_BASIC_AUTH = re.compile(
    r'["\']Basic\s+[A-Za-z0-9+/=]{10,}["\']'
    r'|encodeToBase64\s*\(\s*"[^"]+:[^"]+"',
)


# ── Tipos de resultado ────────────────────────────────────────────────────────

@dataclass
class Secret:
    """Un secreto encontrado en el código fuente."""
    name: str
    value: str
    file: str
    line: int
    service: str = ""  # servicio inferido (Firebase, Intercom, etc.)


@dataclass
class Subdomain:
    """Un subdominio descubierto via crt.sh."""
    name: str
    first_seen: str = ""
    is_wildcard: bool = False


@dataclass
class PublicLeak:
    """Un leak encontrado en fuentes públicas."""
    source: str        # "github" | "postman"
    query: str
    url: str
    title: str
    snippet: str = ""


@dataclass
class OsintResult:
    """Resultado consolidado del análisis OSINT."""
    package: str
    secrets: list[Secret] = field(default_factory=list)
    subdomains: list[Subdomain] = field(default_factory=list)
    public_leaks: list[PublicLeak] = field(default_factory=list)
    domains_scanned: list[str] = field(default_factory=list)
    auth_flows: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "secrets": [
                {"name": s.name, "value": s.value, "file": s.file,
                 "line": s.line, "service": s.service}
                for s in self.secrets
            ],
            "subdomains": [
                {"name": s.name, "first_seen": s.first_seen,
                 "is_wildcard": s.is_wildcard}
                for s in self.subdomains
            ],
            "public_leaks": [
                {"source": l.source, "query": l.query, "url": l.url,
                 "title": l.title, "snippet": l.snippet}
                for l in self.public_leaks
            ],
            "domains_scanned": self.domains_scanned,
            "auth_flows": self.auth_flows,
        }


# ── Mapeo de nombres de campo a servicios ─────────────────────────────────────

_SERVICE_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"firebase", re.I), "Firebase"),
    (re.compile(r"intercom", re.I), "Intercom"),
    (re.compile(r"salesforce|sfmc", re.I), "Salesforce Marketing Cloud"),
    (re.compile(r"branch", re.I), "Branch.io"),
    (re.compile(r"leanplum", re.I), "Leanplum"),
    (re.compile(r"contentful", re.I), "Contentful"),
    (re.compile(r"dynatrace", re.I), "Dynatrace"),
    (re.compile(r"sentry", re.I), "Sentry"),
    (re.compile(r"onesignal|one_signal", re.I), "OneSignal"),
    (re.compile(r"mapbox", re.I), "Mapbox"),
    (re.compile(r"stripe", re.I), "Stripe"),
    (re.compile(r"incode", re.I), "Incode"),
    (re.compile(r"amplitude", re.I), "Amplitude"),
    (re.compile(r"mixpanel", re.I), "Mixpanel"),
    (re.compile(r"appsflyer", re.I), "AppsFlyer"),
    (re.compile(r"adjust", re.I), "Adjust"),
    (re.compile(r"braze|appboy", re.I), "Braze"),
    (re.compile(r"segment", re.I), "Segment"),
    (re.compile(r"rudder", re.I), "RudderStack"),
    (re.compile(r"datadog", re.I), "Datadog"),
    (re.compile(r"newrelic|new_relic", re.I), "New Relic"),
    (re.compile(r"analytics", re.I), "Analytics"),
    (re.compile(r"api_?url|base_?url|host", re.I), "API Backend"),
    (re.compile(r"secret|token|key|password|credential", re.I), "Credential"),
]


def _infer_service(field_name: str, value: str) -> str:
    """Intenta inferir el servicio asociado a un campo de BuildConfig."""
    combined = f"{field_name} {value}"
    for pattern, service in _SERVICE_HINTS:
        if pattern.search(combined):
            return service
    return ""


# ── 1. Extracción de secretos de BuildConfig ──────────────────────────────────

def extract_buildconfig_secrets(
    source_dir: Path,
    progress_callback=None,
) -> tuple[list[Secret], list[dict]]:
    """
    Busca archivos BuildConfig.java (normales y ofuscados) y extrae
    campos estáticos que parecen secretos.

    También detecta patrones de autenticación hardcodeados (Basic Auth).

    Returns:
        Tupla (secretos, auth_flows)
    """
    secrets: list[Secret] = []
    auth_flows: list[dict] = []
    seen_values: set[str] = set()

    # Buscar todos los BuildConfig.java + candidatos ofuscados
    # Los ofuscados suelen tener nombres cortos y estar en paquetes ofuscados
    buildconfig_files: list[Path] = []

    if progress_callback:
        progress_callback("Buscando archivos BuildConfig...")

    # BuildConfig normales
    for f in source_dir.rglob("BuildConfig.java"):
        buildconfig_files.append(f)

    # Buscar en todos los .java campos que parecen BuildConfig ofuscados
    # (archivos con muchos `public static final String` y valores tipo UUID/key)
    java_files = list(source_dir.rglob("*.java"))
    for f in java_files:
        if f.name == "BuildConfig.java":
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Heurística: archivo con >=5 static final String es candidato
        matches = _RE_STATIC_STRING.findall(text)
        if len(matches) >= 5:
            # Verificar que al menos uno tiene un nombre tipo CI_*, APP_*, o valor UUID/key
            has_config_like = any(
                n.startswith(("CI_", "APP_", "API_", "SDK_", "FIREBASE", "VERSION"))
                or _looks_like_secret_value(v)
                for n, v in matches
            )
            if has_config_like:
                buildconfig_files.append(f)

    if progress_callback:
        progress_callback(f"Analizando {len(buildconfig_files)} archivos BuildConfig...")

    for fpath in buildconfig_files:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            rel = str(fpath.relative_to(source_dir))
        except ValueError:
            rel = str(fpath)

        lines = text.splitlines()
        for lineno, line in enumerate(lines, 1):
            m = _RE_STATIC_STRING.search(line)
            if not m:
                continue
            name = m.group("name")
            value = m.group("value")

            if name in _BUILDCONFIG_SKIP:
                continue
            if value in seen_values:
                continue
            # Saltar valores triviales
            if len(value) < 4 or value in ("true", "false", "null", "release", "debug", "prod"):
                continue

            seen_values.add(value)
            service = _infer_service(name, value)
            secrets.append(Secret(
                name=name, value=value, file=rel,
                line=lineno, service=service,
            ))

        # Detectar Basic Auth hardcodeado
        for lineno, line in enumerate(lines, 1):
            for m in _RE_BASIC_AUTH.finditer(line):
                auth_flows.append({
                    "type": "hardcoded_basic_auth",
                    "file": rel,
                    "line": lineno,
                    "matched": m.group(0)[:120],
                })

    if progress_callback:
        progress_callback(f"BuildConfig: {len(secrets)} secretos, {len(auth_flows)} auth flows")

    return secrets, auth_flows


def _looks_like_secret_value(val: str) -> bool:
    """Heurística para detectar valores que parecen secretos."""
    # UUIDs
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", val, re.I):
        return True
    # API keys largas (hex, alfanuméricas)
    if len(val) >= 20 and re.fullmatch(r"[A-Za-z0-9_\-+/=.]+", val):
        return True
    # URLs de producción
    if val.startswith("https://"):
        return True
    return False


# ── 2. Enumeración de subdominios vía crt.sh ─────────────────────────────────

def enumerate_subdomains(
    domains: list[str],
    progress_callback=None,
) -> list[Subdomain]:
    """
    Consulta crt.sh para cada dominio base y devuelve subdominios únicos.

    Normaliza la entrada a eTLD+1 únicos para evitar consultas redundantes
    (p.ej. "api.lemoncash.io" y "web3.lemoncash.io" → una sola query sobre
    "lemoncash.io"). Omite dominios en infraestructura compartida.
    """
    subdomains: dict[str, Subdomain] = {}

    # Deduplicar a eTLD+1, descartando infra compartida.
    bases: list[str] = sorted({
        _tld1(d) for d in domains
        if _tld1(d) and _tld1(d) not in _SHARED_INFRA_TLD1
    })

    for domain in bases:

        url = f"https://crt.sh/?q=%.{quote_plus(domain)}&output=json"
        try:
            resp = requests.get(
                url,
                timeout=_REQUESTS_TIMEOUT,
                headers={"User-Agent": _USER_AGENT},
            )
            if resp.status_code != 200:
                continue

            entries = resp.json()
            for entry in entries:
                name_value = entry.get("name_value", "")
                # crt.sh puede devolver múltiples nombres separados por \n
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if not name or name == domain:
                        continue
                    # Saltar wildcards literales
                    is_wc = name.startswith("*.")
                    clean = name.lstrip("*.")
                    if clean not in subdomains:
                        first_seen = entry.get("not_before", "")
                        subdomains[clean] = Subdomain(
                            name=clean,
                            first_seen=first_seen,
                            is_wildcard=is_wc,
                        )
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            if progress_callback:
                progress_callback(f"crt.sh: error consultando {domain}")
            continue

        # Rate limiting cortés
        time.sleep(1)

    if progress_callback:
        progress_callback(f"crt.sh: {len(subdomains)} subdominios encontrados")

    return sorted(subdomains.values(), key=lambda s: s.name)


# ── 3. Búsqueda en fuentes públicas ──────────────────────────────────────────


def _query_relevance_tokens(query: str) -> list[str]:
    """
    Extrae los tokens "distintivos" de una query para validar que un resultado
    externo realmente la mencione (y no sea un false positive por fuzzy match).

    - Dominios (`api.lemoncash.io`, `lemoncash.io`): aporta el FQDN completo,
      el eTLD+1 (`lemoncash.io`) y el "brand" (`lemoncash`). El brand debe
      tener ≥ 4 caracteres para evitar tokens genéricos (`api`, `io`).
    - Package IDs (`com.applemoncash`): aporta el package completo y el
      último segmento si es ≥ 4 chars (`applemoncash`).
    - Queries con operadores (`site:foo.com inurl:api`, `"foo.com" filetype:json`):
      extrae dominios y strings entre comillas embebidos y los procesa igual.
    - Otros: el propio string en minúsculas si tiene ≥ 4 chars.
    """
    q = (query or "").strip().lower()
    if not q:
        return []

    tokens: list[str] = []

    def _add_domain_tokens(d: str) -> None:
        d = d.strip().strip('"').strip("'")
        if not d or "." not in d:
            return
        tokens.append(d)
        tld1 = _tld1(d)
        if tld1 and tld1 != d:
            tokens.append(tld1)
        if tld1:
            brand = tld1.split(".", 1)[0]
            if len(brand) >= 4 and brand not in _GENERIC_LABEL_TOKENS:
                tokens.append(brand)
        last = d.rsplit(".", 1)[-1]
        if len(last) >= 4 and last not in _GENERIC_LABEL_TOKENS:
            tokens.append(last)

    # Caso 1: la query entera es un dominio.
    if "." in q and " " not in q and "/" not in q and ":" not in q:
        _add_domain_tokens(q)
    else:
        # Caso 2: query con operadores / texto libre. Extraer dominios y
        # strings entrecomillados embebidos.
        for m in re.finditer(r'"([^"]+)"', q):
            _add_domain_tokens(m.group(1))
            inner = m.group(1)
            if len(inner) >= 4 and "." not in inner:
                tokens.append(inner)
        for m in re.finditer(r"[a-z0-9-]+(?:\.[a-z0-9-]+){1,}", q):
            _add_domain_tokens(m.group(0))

    # Deduplicar preservando orden.
    seen: set[str] = set()
    uniq: list[str] = []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def _result_mentions_query(query: str, *fields: str) -> bool:
    """
    True si alguno de los tokens distintivos de `query` aparece como substring
    en la concatenación (lowercase) de los `fields` proporcionados.
    Si `query` no tiene tokens distintivos (p.ej. dorks operadores), acepta.
    """
    tokens = _query_relevance_tokens(query)
    if not tokens:
        return True
    haystack = " ".join(f for f in fields if f).lower()
    return any(t in haystack for t in tokens)


def search_postman(
    queries: list[str],
    progress_callback=None,
) -> list[PublicLeak]:
    """Busca colecciones públicas en Postman que coincidan con las queries."""
    results: list[PublicLeak] = []

    for query in queries:
        if progress_callback:
            progress_callback(f"Postman: buscando '{query}'...")

        url = "https://www.postman.com/_api/ws/proxy"
        payload = {
            "service": "search",
            "method": "POST",
            "path": "/search-all",
            "body": {
                "queryIndices": [
                    "collaboration.workspace",
                    "runtime.collection",
                    "runtime.request",
                    "adp.api",
                    "flow.flow",
                    "apinetwork.team",
                ],
                "queryText": query,
                "size": 10,
                "from": 0,
                "mergeEntities": True,
                "nonNestedRequests": True,
            },
        }

        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=_REQUESTS_TIMEOUT,
                headers={
                    "User-Agent": _USER_AGENT,
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code != 200:
                continue

            data = resp.json()
            items = data.get("data", [])
            for item in items:
                doc = item.get("document", {})
                name = doc.get("name", "") or doc.get("publisherName", "")
                entity_type = doc.get("entityType", "")
                summary = doc.get("summary", "") or doc.get("description", "")

                if not name:
                    continue

                # Construir link directo a Postman
                doc_id = doc.get("id", "")
                publisher_handle = doc.get("publisherHandle", "")
                slug = doc.get("slug", "")
                public_url = ""
                if entity_type == "collection" and publisher_handle and slug:
                    public_url = f"https://www.postman.com/{publisher_handle}/{slug}"
                elif entity_type == "workspace" and publisher_handle and slug:
                    public_url = f"https://www.postman.com/{publisher_handle}/{slug}"
                elif entity_type == "request" and doc_id:
                    public_url = doc.get("publisherUrl", "") or doc.get("url", "")
                elif doc.get("publisherUrl"):
                    public_url = doc["publisherUrl"]
                # Fallback: link de búsqueda
                if not public_url:
                    public_url = f"https://www.postman.com/search?q={requests.utils.quote(query)}&type={entity_type or 'all'}"

                # Filtro anti-FP: Postman hace fuzzy match por tokens
                # (p.ej. "api.lemoncash.io" devuelve "Qase.io API"). Sólo
                # conservamos resultados que mencionen un token distintivo
                # de la query en nombre / summary / URL / handle.
                if not _result_mentions_query(
                    query, name, summary, public_url,
                    publisher_handle, slug,
                ):
                    continue

                results.append(PublicLeak(
                    source="postman",
                    query=query,
                    url=public_url,
                    title=f"[{entity_type}] {name}",
                    snippet=summary[:200] if summary else "",
                ))
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            continue

        time.sleep(1)

    if progress_callback:
        progress_callback(f"Postman: {len(results)} resultados")

    return results


_GITHUB_API_URL = "https://api.github.com/search/code"
_GITHUB_SEARCH_URL = "https://github.com/search"
_FOFA_API_URL = "https://fofa.info/api/v1/search/all"


def search_github_code(
    queries: list[str],
    *,
    github_token: str | None = None,
    progress_callback=None,
) -> list[PublicLeak]:
    """
    Busca en GitHub Code Search.

    Con `github_token` usa la API REST v3 (/search/code), que devuelve
    resultados concretos (repo, path, fragmento, URL directa).  Sin token
    cae en scraping HTML del contador de resultados (menos información,
    sujeto a cambios en la UI de GitHub).

    Límites API v3 autenticada: 30 req/min para code search.
    """
    results: list[PublicLeak] = []
    use_api = bool(github_token)

    headers: dict[str, str] = {"User-Agent": _USER_AGENT}
    if use_api:
        headers["Authorization"] = f"Bearer {github_token}"
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"

    for query in queries:
        if progress_callback:
            mode = "API" if use_api else "web"
            progress_callback(f"GitHub ({mode}): buscando '{query}'...")

        if use_api:
            try:
                resp = requests.get(
                    _GITHUB_API_URL,
                    params={"q": query, "per_page": 10},
                    headers=headers,
                    timeout=_REQUESTS_TIMEOUT,
                )
                if resp.status_code == 403:
                    # Rate-limit o scope insuficiente — degradar a web.
                    if progress_callback:
                        progress_callback(
                            "GitHub API: rate-limit o sin scope, usando modo web"
                        )
                    use_api = False
                elif resp.status_code == 422:
                    # Query inválida para la API (p.ej. muy corta) — skip.
                    time.sleep(2)
                    continue
                elif resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    items = data.get("items", [])
                    for item in items:
                        repo = item.get("repository", {})
                        repo_name = repo.get("full_name", "")
                        path = item.get("path", "")
                        html_url = item.get("html_url", "")
                        # Fragmento del match (viene como texto plano).
                        text_matches = item.get("text_matches", [])
                        snippet = ""
                        if text_matches:
                            snippet = text_matches[0].get("fragment", "")[:200]

                        if not _result_mentions_query(query, repo_name, path, snippet):
                            continue

                        results.append(PublicLeak(
                            source="github",
                            query=query,
                            url=html_url or f"https://github.com/{repo_name}/blob/HEAD/{path}",
                            title=f"{repo_name}/{path}" if repo_name else path,
                            snippet=snippet,
                        ))
                    if progress_callback and total > 10:
                        progress_callback(
                            f"GitHub: {total} resultados totales para '{query}' (mostrando 10)"
                        )
            except requests.RequestException:
                pass

        if not use_api:
            # Fallback: contador HTML.
            search_url = f"{_GITHUB_SEARCH_URL}?q={quote_plus(query)}&type=code"
            try:
                resp = requests.get(
                    search_url,
                    timeout=_REQUESTS_TIMEOUT,
                    headers={**headers, "Accept": "text/html"},
                )
                if resp.status_code == 200:
                    count_match = re.search(
                        r'(\d[\d,]*)\s+code\s+results?',
                        resp.text,
                    )
                    if count_match:
                        count = int(count_match.group(1).replace(",", ""))
                        if count > 0:
                            results.append(PublicLeak(
                                source="github",
                                query=query,
                                url=search_url,
                                title=f"{count} code result(s) for '{query}'",
                            ))
            except requests.RequestException:
                pass

        time.sleep(2)  # GitHub rate limita agresivamente en ambos modos

    if progress_callback:
        progress_callback(f"GitHub: {len(results)} hallazgos")

    return results


def search_fofa(
    queries: list[str],
    *,
    fofa_key: str,
    progress_callback=None,
) -> list[PublicLeak]:
    """
    Busca activos expuestos en FOFA a partir de dominios propios.

    Usa la API `search/all` con `key` y `qbase64`. Devuelve hasta 10
    resultados por query con los campos `host,ip,port,title`.
    """
    if not fofa_key:
        return []

    results: list[PublicLeak] = []
    fields = "host,ip,port,title"

    for query in queries:
        if progress_callback:
            progress_callback(f"FOFA: buscando '{query}'...")

        fofa_query = f'domain="{query}" || host="{query}"'
        qbase64 = base64.b64encode(fofa_query.encode("utf-8")).decode("ascii")

        try:
            resp = requests.get(
                _FOFA_API_URL,
                params={
                    "key": fofa_key,
                    "qbase64": qbase64,
                    "fields": fields,
                    "size": 10,
                },
                headers={"User-Agent": _USER_AGENT},
                timeout=_REQUESTS_TIMEOUT,
            )
            if resp.status_code != 200:
                continue

            data = resp.json()
            if data.get("error"):
                errmsg = data.get("errmsg") or "error desconocido"
                import sys
                print(f"[FOFA] Error API: {errmsg}", file=sys.stderr)
                if progress_callback:
                    progress_callback(f"FOFA error: {errmsg}")
                continue

            for item in data.get("results", []):
                if not isinstance(item, list) or len(item) < 4:
                    continue

                host, ip_addr, port, title = item[0], item[1], item[2], item[3]
                title = title or ""
                host = host or ""
                ip_addr = ip_addr or ""
                port = str(port or "")
                url = host or (f"{ip_addr}:{port}" if ip_addr else "")

                if not url:
                    continue
                if not _result_mentions_query(query, host, ip_addr, title, url):
                    continue

                results.append(PublicLeak(
                    source="fofa",
                    query=query,
                    url=url,
                    title=title or f"{host or ip_addr}:{port}".strip(":"),
                    snippet=f"ip={ip_addr} port={port}".strip(),
                ))
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            continue

        time.sleep(1)

    if progress_callback:
        progress_callback(f"FOFA: {len(results)} resultados")

    return results


# ── 4. Generación de dorks ────────────────────────────────────────────────────

# DuckDuckGo HTML endpoint (no requiere auth).
_DUCKDUCKGO_URL = "https://html.duckduckgo.com/html/"

# Regex para extraer resultados del HTML de DDG (title + url + snippet).
_RE_DDG_RESULT = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="(?P<url>[^"]+)"[^>]*>(?P<title>.*?)</a>'
    r'.*?<a[^>]+class="result__snippet"[^>]*>(?P<snippet>.*?)</a>',
    re.DOTALL,
)
_RE_HTML_TAG = re.compile(r"<[^>]+>")


def _strip_html(raw: str) -> str:
    """Elimina tags HTML y entidades básicas."""
    text = _RE_HTML_TAG.sub("", raw)
    return (
        text.replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .strip()
    )


def search_duckduckgo(
    query: str,
    *,
    max_results: int = 10,
    timeout: int = _REQUESTS_TIMEOUT,
) -> list[PublicLeak]:
    """
    Ejecuta un dork contra DuckDuckGo (HTML endpoint, sin auth).

    Soporta operadores `site:`, `inurl:`, `filetype:`, comillas y OR.
    Devuelve hasta `max_results` resultados como PublicLeak(source="duckduckgo").
    """
    try:
        resp = requests.post(
            _DUCKDUCKGO_URL,
            data={"q": query, "kl": "us-en"},
            headers={"User-Agent": _USER_AGENT},
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.RequestException:
        return []

    results: list[PublicLeak] = []
    for match in _RE_DDG_RESULT.finditer(resp.text):
        url = match.group("url")
        title = _strip_html(match.group("title"))
        snippet = _strip_html(match.group("snippet"))
        # DDG devuelve URLs redirigidas tipo /l/?kh=-1&uddg=...
        if url.startswith("/") or "duckduckgo.com/l/" in url:
            m = re.search(r"uddg=([^&]+)", url)
            if m:
                from urllib.parse import unquote
                url = unquote(m.group(1))
        if not url or not title:
            continue
        # Filtro anti-FP: exigimos que la URL/título/snippet mencione el token
        # distintivo de la query (dominios → brand/eTLD+1).
        if not _result_mentions_query(query, url, title, snippet):
            continue
        results.append(PublicLeak(
            source="duckduckgo",
            query=query,
            url=url,
            title=title,
            snippet=snippet[:200],
        ))
        if len(results) >= max_results:
            break
    return results


def _build_web_queries(
    domains: list[str],
    secrets: list["Secret"],
    subdomains: list["Subdomain"],
    max_queries: int,
) -> list[str]:
    """
    Construye queries estilo Google/DDG a partir del dominio propio, secretos
    identificables y subdominios de entornos no-prod.
    """
    queries: list[str] = []

    for domain in domains:
        queries.append(f'site:{domain} inurl:api')
        queries.append(f'"{domain}" filetype:json OR filetype:yaml')

    # Agrupar subdominios dev/qa/staging en un solo OR para ahorrar cupo.
    dev_subs = [
        s for s in subdomains
        if any(env in s.name for env in ("dev", "qa", "uat", "test", "staging", "pre."))
    ]
    if dev_subs:
        queries.append(" OR ".join(f'"{s.name}"' for s in dev_subs[:5]))

    # Secretos que no son URLs ni credenciales explícitas.
    for secret in secrets:
        value = secret.value or ""
        if value.startswith("https://"):
            continue
        if not _looks_like_secret_value(value) or len(value) < 20:
            continue
        queries.append(f'"{value}"')
        if len(queries) >= max_queries:
            break

    return queries[:max_queries]


def execute_dorks(
    domains: list[str],
    secrets: list["Secret"],
    subdomains: list["Subdomain"],
    *,
    engines: list[str] | None = None,
    max_per_engine: int = 5,
    max_results_per_dork: int = 5,
    progress_callback=None,
) -> list[PublicLeak]:
    """
    Construye y ejecuta queries OSINT contra motores web soportados.

    Por ahora el único motor soportado es "duckduckgo".
    Las queries se generan a partir de los dominios propios, secretos
    identificables y subdominios de entornos no-prod.
    """
    engines = ["duckduckgo"] if engines is None else engines
    results: list[PublicLeak] = []

    if "duckduckgo" in engines:
        queries = _build_web_queries(domains, secrets, subdomains, max_per_engine)
        for idx, query in enumerate(queries, 1):
            if progress_callback:
                progress_callback(
                    f"DuckDuckGo ({idx}/{len(queries)}): {query[:60]}"
                )
            results.extend(
                search_duckduckgo(query, max_results=max_results_per_dork)
            )
            time.sleep(1)  # cortesía entre requests

    if progress_callback:
        progress_callback(f"Búsquedas web: {len(results)} resultados")

    return results


# ── Wayback Machine (archive.org) ─────────────────────────────────────────────

_WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"

# Patrones de path/querystring considerados "interesantes" para OSINT.
_RE_WAYBACK_INTERESTING = re.compile(
    r"("
    r"/api(?:/|$)|/admin|/debug|/internal|/private|/staging|/dev(?:/|$)|"
    r"/test(?:/|$)|/old(?:/|$)|/backup|/dump|/\.env|/\.git|/\.svn|/\.ds_store|"
    r"/swagger|/openapi|/graphql|/actuator|/phpinfo|/wp-admin|/config\.|"
    r"/v\d+/|\.sql|\.bak|\.log|\.zip|\.tar\.gz|\.pem|\.key|\.pfx|"
    r"[?&](?:api[_-]?key|token|secret|passw|auth|sessionid|jwt)="
    r")",
    re.IGNORECASE,
)


def search_wayback(
    domain: str,
    *,
    limit: int = 200,
    filter_interesting: bool = True,
    timeout: int = _REQUESTS_TIMEOUT,
) -> list[PublicLeak]:
    """
    Consulta la CDX API de Wayback Machine para un dominio.

    Devuelve hasta `limit` URLs archivadas como PublicLeak(source="wayback").
    Si `filter_interesting=True`, aplica un regex de paths/querystrings
    sensibles (endpoints admin, archivos .env/.git, tokens en URL, etc.).
    Sin autenticación.
    """
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "collapse": "urlkey",
        "limit": str(limit),
        "fl": "timestamp,original,mimetype,statuscode",
    }
    try:
        resp = requests.get(
            _WAYBACK_CDX_URL,
            params=params,
            headers={"User-Agent": _USER_AGENT},
            timeout=timeout,
        )
        resp.raise_for_status()
        rows = resp.json()
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return []

    if not rows or len(rows) < 2:
        return []

    # Primera fila son los headers; saltarla.
    results: list[PublicLeak] = []
    for row in rows[1:]:
        if len(row) < 4:
            continue
        timestamp, original, mimetype, statuscode = row[0], row[1], row[2], row[3]
        if filter_interesting and not _RE_WAYBACK_INTERESTING.search(original):
            continue
        # URL reproducible en el viewer de Wayback.
        viewer = f"https://web.archive.org/web/{timestamp}/{original}"
        results.append(PublicLeak(
            source="wayback",
            query=domain,
            url=viewer,
            title=f"[{statuscode} {mimetype or '?'}] {original}",
            snippet=f"archived {timestamp}",
        ))

    return results


def search_wayback_many(
    domains: list[str],
    *,
    limit_per_domain: int = 200,
    filter_interesting: bool = True,
    progress_callback=None,
) -> list[PublicLeak]:
    """Ejecuta search_wayback sobre múltiples dominios con cortesía entre requests."""
    results: list[PublicLeak] = []
    for idx, domain in enumerate(domains, 1):
        if progress_callback:
            progress_callback(f"Wayback ({idx}/{len(domains)}): {domain}")
        results.extend(
            search_wayback(
                domain,
                limit=limit_per_domain,
                filter_interesting=filter_interesting,
            )
        )
        time.sleep(0.5)
    if progress_callback:
        progress_callback(f"Wayback: {len(results)} URLs archivadas")
    return results


# ── Extracción de dominios base desde URLs/secretos ───────────────────────────

_RE_DOMAIN_FROM_URL = re.compile(
    r'https?://(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})',
)

# Tokens demasiado genéricos para usarse como brand-hint desde el label.
_GENERIC_LABEL_TOKENS: frozenset[str] = frozenset({
    "app", "apps", "mobile", "movil", "the", "and", "para",
    "pro", "lite", "beta", "plus", "free", "premium", "web",
    "online", "mi", "my", "banca", "bank", "banking", "pay",
    "wallet", "client", "cliente", "user", "users", "home",
    "empresa", "empresas", "personal", "shop", "store",
})

# SLDs multi-segmento conocidos para calcular eTLD+1 sin dependencias externas.
_KNOWN_MULTI_SLDS: frozenset[str] = frozenset({
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz",
    "com.ar", "com.au", "com.br", "com.mx", "com.pe", "com.co",
    "com.ec", "com.uy", "com.py", "com.bo", "com.ve", "com.cl",
    "com.gt", "com.sv", "com.hn", "com.ni", "com.cu", "com.do",
    "com.pa", "com.cr", "com.tr", "com.cn", "com.hk", "com.sg",
    "com.tw", "com.my", "com.ph", "com.vn", "com.pk", "com.eg",
    "com.sa", "com.ng", "com.ru", "com.ua", "org.uk", "gov.uk",
    "ne.jp", "or.jp", "ac.uk", "ac.jp",
})

# eTLD+1 de infraestructura compartida que NO debe usarse como pivote
# para el bootstrap inverso (CDNs, PaaS, hosters genéricos).
_SHARED_INFRA_TLD1: frozenset[str] = frozenset({
    "amazonaws.com", "cloudfront.net", "appspot.com",
    "firebaseio.com", "firebaseapp.com", "web.app",
    "googleapis.com", "gstatic.com", "google.com",
    "azurewebsites.net", "windows.net", "azure.com",
    "herokuapp.com", "netlify.app", "vercel.app",
    "github.io", "githubusercontent.com",
    "cloudflare.com", "akamaihd.net", "akamaized.net",
    "fastly.net", "jsdelivr.net", "unpkg.com",
    "sentry.io", "intercom.io", "segment.io", "adjust.com",
    "branch.io", "appsflyer.com", "crashlytics.com",
    "facebook.com", "fbcdn.net", "twitter.com", "twimg.com",
})

# Prefijos de rule_id de apkleaks usados para refuerzo.
_APKLEAKS_RULE_PREFIXES: tuple[str, ...] = ("LINK_", "URI_", "IP_", "URL_")

# Número mínimo de apariciones de un mismo eTLD+1 en findings de apkleaks
# para aceptarlo como dominio propio aunque no haya match por hints.
_APKLEAKS_FREQ_THRESHOLD: int = 2


def _normalize_token(value: str) -> str:
    """
    Normaliza un token para comparación por substring.

    - Decompone acentos (NFKD) y elimina marcas de combinación.
    - Pasa a minúsculas.
    - Elimina cualquier carácter no alfanumérico (espacios, guiones,
      puntos, separadores).

    Ejemplo: "Mi Apṕ Pro" -> "miapppro".
    """
    if not value:
        return ""
    decomposed = unicodedata.normalize("NFKD", value)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "", stripped.lower())


def _tld1(domain: str) -> str:
    """
    Devuelve el eTLD+1 del dominio usando una lista heurística de SLDs
    multi-segmento. No requiere dependencias externas.

    Ejemplos:
        api.example.com   -> example.com
        a.b.example.co.uk -> example.co.uk
        example.com.pe    -> example.com.pe
    """
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return domain.lower()
    last_two = ".".join(parts[-2:])
    if last_two in _KNOWN_MULTI_SLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _extract_brand_hints(package: str, app_label: str = "") -> list[str]:
    """
    Extrae palabras clave de marca desde el package ID y, opcionalmente,
    desde el label de la app (nombre comercial).

    Reglas:
      - Del package se descartan TLDs/segmentos comunes (com, org, app, pe, ar,…)
        y segmentos cortos.
      - De cada segmento se generan variantes quitando prefijos como "app",
        "my", "go", "get".
      - Del label se tokeniza por separadores, se normaliza (acentos/case)
        y se descartan tokens demasiado genéricos
        (definidos en _GENERIC_LABEL_TOKENS) o de longitud < 3.

    Devuelve los hints en orden estable y sin duplicados.

    Ejemplo: package="com.example.mybrand", app_label="My Brand Pro"
             -> ["example", "mybrand", "brand", "mybrandpro"]
    """
    parts = (package or "").lower().split(".")
    skip = {"com", "org", "net", "io", "app", "dev", "ar", "pe", "br", "mx",
            "cl", "co", "ec", "uy", "py", "ve", "bo", "cr", "gt", "hn",
            "sv", "pa", "do", "cu", "us", "uk", "de", "fr", "es", "it",
            "pt", "ru", "cn", "jp", "kr", "in", "au", "nz", "za"}

    hints: list[str] = []
    seen: set[str] = set()

    def _add(token: str) -> None:
        if token and token not in seen:
            seen.add(token)
            hints.append(token)

    # Hints desde package
    for segment in parts:
        if segment in skip or len(segment) < 3:
            continue
        _add(segment)
        for prefix in ("app", "my", "go", "get"):
            if segment.startswith(prefix) and len(segment) > len(prefix) + 2:
                _add(segment[len(prefix):])

    # Hints desde app_label
    if app_label:
        # Tokenizar por separadores comunes antes de normalizar.
        raw_tokens = re.split(r"[\s\-_/.,()]+", app_label)
        for raw in raw_tokens:
            norm = _normalize_token(raw)
            if len(norm) < 3 or norm in _GENERIC_LABEL_TOKENS:
                continue
            _add(norm)
        # Y como bonus, el label completo normalizado (sin separadores).
        full_norm = _normalize_token(app_label)
        if len(full_norm) >= 4 and full_norm not in _GENERIC_LABEL_TOKENS:
            _add(full_norm)

    return hints


def _is_brand_domain(domain: str, brand_hints: list[str]) -> bool:
    """Verifica si un dominio parece pertenecer a la marca de la app.

    Compara contra dos representaciones del dominio:
      - el dominio tal cual en minúsculas
      - el dominio normalizado (sin puntos/guiones/acentos)
    para tolerar variantes con separadores.
    """
    if not brand_hints:
        return False
    domain_lower = domain.lower()
    domain_norm = _normalize_token(domain_lower)
    return any(
        hint in domain_lower or hint in domain_norm
        for hint in brand_hints
    )


def extract_target_domains(
    secrets: list[Secret],
    scan_findings: list | None = None,
    source_dir: Path | None = None,
    package: str = "",
    app_label: str = "",
) -> list[str]:
    """
    Extrae dominios "propios" de la app desde las URLs encontradas en
    secretos y hallazgos del scanner.

    Estrategia:
      1. Recolectar todos los dominios candidatos (BuildConfig + findings).
        2. Separar candidatos en:
            - no-infra: eTLD+1 no compartido
            - infra-fqdn: FQDN específico sobre eTLD+1 compartido
              (p.ej. myapp.firebaseio.com). El eTLD+1 compartido puro
              (firebaseio.com) nunca se considera objetivo propio.
        3. Pasada positiva: aceptar dominios que contengan algún brand-hint
            derivado del package y/o del app_label. Para infra compartida,
            sólo se aceptan FQDNs específicos que matcheen marca.
        4. Bootstrap inverso por eTLD+1: si un dominio aceptado pertenece a un
         eTLD+1 X, aceptar también el resto de dominios candidatos cuyo
            eTLD+1 sea X (recupera subdominios que no contienen el hint).
            Esta expansión aplica sólo a no-infra.
        5. Refuerzo por apkleaks: si un mismo eTLD+1 aparece N≥2 veces en
         hallazgos cuya rule_id pertenece a apkleaks (LINK_/URI_/IP_/URL_),
         se acepta aunque no haya match por hints.
        6. Filtrar siempre los eTLD+1 de infraestructura compartida
         (CDNs, PaaS, analytics) para evitar falsos positivos.

    Si no hay package ni app_label, se devuelven todos los dominios
    candidatos (excluyendo igualmente la infraestructura compartida).
    """
    brand_hints = _extract_brand_hints(package, app_label)

    # 1. Recolectar dominios candidatos junto con su rule_id de origen
    #    (necesario para el refuerzo apkleaks).
    all_domains: set[str] = set()
    apkleaks_tld1_counts: Counter[str] = Counter()

    for secret in secrets:
        m = _RE_DOMAIN_FROM_URL.search(secret.value or "")
        if m:
            all_domains.add(m.group(1).lower())

    if scan_findings:
        for f in scan_findings:
            matched = getattr(f, "matched_text", "") or ""
            rule_id = getattr(f, "rule_id", "") or ""
            is_apkleaks = any(
                rule_id.startswith(prefix) for prefix in _APKLEAKS_RULE_PREFIXES
            )
            for url_match in _RE_DOMAIN_FROM_URL.finditer(matched):
                domain = url_match.group(1).lower()
                all_domains.add(domain)
                if is_apkleaks:
                    apkleaks_tld1_counts[_tld1(domain)] += 1

    # Candidatos con eTLD+1 no compartido.
    candidates = {
        d for d in all_domains
        if _tld1(d) not in _SHARED_INFRA_TLD1
    }

    # FQDNs específicos sobre infraestructura compartida.
    shared_fqdn_candidates = {
        d for d in all_domains
        if _tld1(d) in _SHARED_INFRA_TLD1 and d != _tld1(d)
    }

    # 2. Pasada positiva por hints.
    if brand_hints:
        seed = {d for d in candidates if _is_brand_domain(d, brand_hints)}
        shared_seed = {
            d for d in shared_fqdn_candidates
            if _is_brand_domain(d, brand_hints)
        }
    else:
        # Sin señales de marca: devolver todos los candidatos no-infra.
        return sorted(candidates)

    result: set[str] = set(seed)
    result.update(shared_seed)

    # 3. Bootstrap inverso por eTLD+1 (excluyendo infra compartida).
    seed_tld1 = {_tld1(d) for d in seed}
    seed_tld1 -= _SHARED_INFRA_TLD1
    if seed_tld1:
        for d in candidates:
            if _tld1(d) in seed_tld1:
                result.add(d)

    # 4. Refuerzo por apkleaks: eTLD+1 que aparezca ≥ N veces.
    reinforced_tld1 = {
        tld1 for tld1, count in apkleaks_tld1_counts.items()
        if count >= _APKLEAKS_FREQ_THRESHOLD
        and tld1 not in _SHARED_INFRA_TLD1
    }
    if reinforced_tld1:
        for d in candidates:
            if _tld1(d) in reinforced_tld1:
                result.add(d)

    return sorted(result)


# ── Función principal de orquestación ─────────────────────────────────────────

def _secrets_from_scan_findings(findings: list) -> list[Secret]:
    """Convierte hallazgos HC* del scanner de leaks a objetos Secret para OSINT."""
    secrets: list[Secret] = []
    seen: set[str] = set()

    for f in findings:
        rule_id = getattr(f, "rule_id", "")
        if not rule_id.startswith("HC"):
            continue

        matched = getattr(f, "matched_text", "") or ""
        file_str = str(getattr(f, "file", ""))
        line_num = getattr(f, "line", 0)

        # Extraer el nombre y valor de la asignación
        assign = re.search(
            r'(?:String|int|boolean)\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            matched,
        )
        if assign:
            name, value = assign.group(1), assign.group(2)
        else:
            # Fallback: usar el texto completo como valor
            name = rule_id
            value = matched.strip()

        key = f"{name}:{value}"
        if key in seen:
            continue
        seen.add(key)

        # Detectar servicio según el rule_id
        service_map = {
            "HC001": "API Key",
            "HC002": "Credential",
            "HC003": "Private Key",
            "HC004": "Firebase/Google",
            "HC005": "AWS",
            "HC006": "Crypto",
            "HC007": "API Endpoint",
            "HC008": "Third-party Service",
        }
        service = service_map.get(rule_id, "Unknown")

        secrets.append(Secret(
            name=name,
            value=value,
            file=file_str,
            line=line_num,
            service=service,
        ))

    return secrets


def run_osint(
    source_dir: Path,
    package: str,
    *,
    scan_findings: list | None = None,
    crt_sh: bool = True,
    github_search: bool = True,
    github_token: str | None = None,
    fofa_search: bool = False,
    fofa_key: str | None = None,
    postman_search: bool = True,
    execute_dorks_flag: bool = False,
    dork_engines: list[str] | None = None,
    dork_max_per_engine: int = 5,
    dork_max_results_per_dork: int = 5,
    wayback_search: bool = True,
    wayback_limit_per_domain: int = 200,
    wayback_filter_interesting: bool = True,
    app_label: str = "",
    progress_callback=None,
) -> OsintResult:
    """
    Ejecuta el pipeline OSINT completo sobre el código fuente decompilado.

    Args:
        source_dir: Directorio con el código fuente decompilado (.java)
        package: Package ID de la aplicación
        scan_findings: Hallazgos del scanner de vulnerabilidades (VulnFinding).
                       Si se proveen, se extraen secretos y URLs de ahí en lugar
                       de depender solo de la extracción independiente de BuildConfig.
        crt_sh: Consultar crt.sh para subdominios
        github_search: Buscar en GitHub Code Search
        github_token: Token personal de GitHub (opcional). Con token se usa la
                      API REST v3 que devuelve resultados concretos (repo/path/
                      fragmento). Sin token cae en scraping HTML del contador.
                      El scope mínimo necesario es `read:public_repo`.
        fofa_search: Buscar activos expuestos en FOFA.
        fofa_key: API key de FOFA para usar `search/all`.
        postman_search: Buscar en Postman público
        execute_dorks_flag: Si es True, lanza búsquedas web (DuckDuckGo).
        progress_callback: Función para reportar progreso

    Returns:
        OsintResult con todos los hallazgos
    """
    result = OsintResult(package=package)

    # 1. Extraer secretos de BuildConfig (uso interno: alimentan dominios y búsquedas)
    secrets, auth_flows = extract_buildconfig_secrets(
        source_dir, progress_callback=progress_callback,
    )
    result.auth_flows = auth_flows

    # 2. Extraer dominios objetivo (desde BuildConfig + hallazgos del scanner)
    domains = extract_target_domains(
        secrets,
        scan_findings=scan_findings,
        package=package,
        app_label=app_label,
    )
    result.domains_scanned = domains

    if not domains:
        if progress_callback:
            progress_callback("OSINT: no se encontraron dominios propios para analizar")
        return result

    # 3. Enumeración de subdominios
    # enumerate_subdomains normaliza internamente a eTLD+1 para consultar
    # crt.sh con la base correcta (lemoncash.io, no api.lemoncash.io).
    if crt_sh:
        result.subdomains = enumerate_subdomains(
            domains, progress_callback=progress_callback,
        )

    # 4. Búsqueda en fuentes públicas
    # Construir queries relevantes
    search_queries = list(domains)
    search_queries.append(package)

    if postman_search:
        result.public_leaks.extend(
            search_postman(search_queries, progress_callback=progress_callback)
        )

    if github_search:
        github_queries = [package]
        github_queries.extend(domains)
        result.public_leaks.extend(
            search_github_code(
                github_queries,
                github_token=github_token,
                progress_callback=progress_callback,
            )
        )

    if fofa_search and fofa_key:
        result.public_leaks.extend(
            search_fofa(
                domains,
                fofa_key=fofa_key,
                progress_callback=progress_callback,
            )
        )

    # 4.b Wayback Machine (archive.org) — URLs históricas por dominio propio.
    if wayback_search:
        result.public_leaks.extend(
            search_wayback_many(
                domains,
                limit_per_domain=wayback_limit_per_domain,
                filter_interesting=wayback_filter_interesting,
                progress_callback=progress_callback,
            )
        )

    # 5. Ejecutar búsquedas web (DuckDuckGo) — opt-in.
    if execute_dorks_flag:
        result.public_leaks.extend(
            execute_dorks(
                domains=domains,
                secrets=secrets,
                subdomains=result.subdomains,
                engines=dork_engines,
                max_per_engine=dork_max_per_engine,
                max_results_per_dork=dork_max_results_per_dork,
                progress_callback=progress_callback,
            )
        )

    if progress_callback:
        progress_callback(
            f"OSINT completo: "
            f"{len(result.subdomains)} subdominios, "
            f"{len(result.public_leaks)} leaks públicos"
        )

    return result
