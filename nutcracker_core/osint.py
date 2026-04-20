"""
Módulo OSINT — nutcracker.

Automatiza la recolección de inteligencia de fuentes abiertas a partir del
código decompilado de una aplicación Android:

  1. Extracción de secretos de BuildConfig (normal y ofuscado)
  2. Enumeración de subdominios vía crt.sh
  3. Búsqueda de leaks en fuentes públicas (GitHub, Postman)
  4. Generación de dorks (Google, GitHub, Shodan)
"""

from __future__ import annotations

import json
import re
import time
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
    dorks: dict[str, list[str]] = field(default_factory=dict)
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
            "dorks": self.dorks,
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
    """
    subdomains: dict[str, Subdomain] = {}

    for domain in domains:
        if progress_callback:
            progress_callback(f"crt.sh: consultando %.{domain}...")

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


def search_github_code(
    queries: list[str],
    progress_callback=None,
) -> list[PublicLeak]:
    """
    Busca en GitHub Code Search (sin auth, solo repos públicos via web search).
    Usa la interfaz de búsqueda web de GitHub que no requiere token.
    """
    results: list[PublicLeak] = []

    for query in queries:
        if progress_callback:
            progress_callback(f"GitHub: buscando '{query}'...")

        search_url = f"https://github.com/search?q={quote_plus(query)}&type=code"
        try:
            resp = requests.get(
                search_url,
                timeout=_REQUESTS_TIMEOUT,
                headers={
                    "User-Agent": _USER_AGENT,
                    "Accept": "text/html",
                },
            )
            if resp.status_code != 200:
                continue

            # Parseo simple: buscar resultados en el HTML
            # GitHub muestra "X code results" en la página
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
            continue

        time.sleep(2)  # GitHub rate limita agresivamente

    if progress_callback:
        progress_callback(f"GitHub: {len(results)} búsquedas con resultados")

    return results


# ── 4. Generación de dorks ────────────────────────────────────────────────────

def generate_dorks(
    package: str,
    secrets: list[Secret],
    domains: list[str],
    subdomains: list[Subdomain],
) -> dict[str, list[str]]:
    """Genera dorks de búsqueda para Google, GitHub y Shodan."""
    dorks: dict[str, list[str]] = {
        "google": [],
        "github": [],
        "shodan": [],
    }

    # ── Google ────────────────────────────────────────────────────────────
    for domain in domains:
        dorks["google"].append(f'site:{domain} inurl:api')
        dorks["google"].append(f'"{domain}" filetype:json OR filetype:yaml')

    # Buscar entornos expuestos
    dev_subs = [s for s in subdomains if any(
        env in s.name for env in ("dev", "qa", "uat", "test", "staging", "pre.")
    )]
    if dev_subs:
        or_clause = " OR ".join(f'"{s.name}"' for s in dev_subs[:5])
        dorks["google"].append(or_clause)

    # Secretos únicos (solo los más identificables: UUIDs, API keys largas)
    for secret in secrets:
        if _looks_like_secret_value(secret.value) and not secret.value.startswith("https://"):
            if len(secret.value) >= 20:
                dorks["google"].append(f'"{secret.value}"')
                if len(dorks["google"]) >= 15:
                    break

    # ── GitHub ────────────────────────────────────────────────────────────
    for domain in domains:
        dorks["github"].append(f'"{domain}"')

    dorks["github"].append(f'"{package}"')

    # Agregar secretos interesantes
    for secret in secrets:
        if secret.service in ("Credential", "API Backend"):
            continue
        if _looks_like_secret_value(secret.value) and not secret.value.startswith("https://"):
            dorks["github"].append(f'"{secret.value}"')
            if len(dorks["github"]) >= 10:
                break

    # ── Shodan/Censys ─────────────────────────────────────────────────────
    for domain in domains:
        dorks["shodan"].append(f'ssl.cert.subject.cn:"{domain}"')

    return dorks


# ── Extracción de dominios base desde URLs/secretos ───────────────────────────

_RE_DOMAIN_FROM_URL = re.compile(
    r'https?://(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})',
)

def _extract_brand_hints(package: str) -> list[str]:
    """
    Extrae palabras clave de marca desde el package ID.

    com.example.myapp     → ["myapp"]
    pe.example.mybank     → ["mybank", "bank"]
    com.example.service   → ["example", "service"]
    """
    parts = package.lower().split(".")
    # Ignorar prefijos comunes de package (com, org, net, pe, ar, io, etc.)
    skip = {"com", "org", "net", "io", "app", "dev", "ar", "pe", "br", "mx",
            "cl", "co", "ec", "uy", "py", "ve", "bo", "cr", "gt", "hn",
            "sv", "pa", "do", "cu", "us", "uk", "de", "fr", "es", "it",
            "pt", "ru", "cn", "jp", "kr", "in", "au", "nz", "za"}
    hints = [p for p in parts if p not in skip and len(p) >= 3]
    # Variantes sin prefijos comunes de app
    expanded: list[str] = []
    for h in hints:
        expanded.append(h)
        # "appmycompany" → también probar "mycompany" (quitar prefijo "app")
        for prefix in ("app", "my", "go", "get"):
            if h.startswith(prefix) and len(h) > len(prefix) + 2:
                expanded.append(h[len(prefix):])
    return expanded


def _is_brand_domain(domain: str, brand_hints: list[str]) -> bool:
    """Verifica si un dominio parece pertenecer a la marca de la app."""
    domain_lower = domain.lower()
    return any(hint in domain_lower for hint in brand_hints)


def extract_target_domains(
    secrets: list[Secret],
    scan_findings: list | None = None,
    source_dir: Path | None = None,
    package: str = "",
) -> list[str]:
    """
    Extrae dominios "propios" de la app desde las URLs encontradas.

    Usa un filtro positivo: solo acepta dominios que contengan alguna
    palabra clave derivada del package ID (la "marca" de la app).
    Ejemplo: com.example.myapp → acepta api.myapp.io, rechaza adjust.com.
    """
    brand_hints = _extract_brand_hints(package) if package else []
    all_domains: set[str] = set()

    # Desde secretos de BuildConfig
    for secret in secrets:
        m = _RE_DOMAIN_FROM_URL.search(secret.value)
        if m:
            all_domains.add(m.group(1).lower())

    # Desde hallazgos del scanner de leaks
    if scan_findings:
        for f in scan_findings:
            matched = getattr(f, "matched_text", "") or ""
            for url_match in _RE_DOMAIN_FROM_URL.finditer(matched):
                all_domains.add(url_match.group(1).lower())

    # Filtrar: quedarse solo con dominios de la marca
    if brand_hints:
        result = {d for d in all_domains if _is_brand_domain(d, brand_hints)}
    else:
        # Sin package no podemos filtrar — devolver todos
        result = all_domains

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
    postman_search: bool = True,
    gen_dorks: bool = True,
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
        postman_search: Buscar en Postman público
        gen_dorks: Generar dorks de búsqueda
        progress_callback: Función para reportar progreso

    Returns:
        OsintResult con todos los hallazgos
    """
    result = OsintResult(package=package)

    # 1. Extraer secretos de BuildConfig (uso interno: alimentan dominios y dorks)
    secrets, auth_flows = extract_buildconfig_secrets(
        source_dir, progress_callback=progress_callback,
    )
    result.auth_flows = auth_flows

    # 2. Extraer dominios objetivo (desde BuildConfig + hallazgos del scanner)
    domains = extract_target_domains(secrets, scan_findings=scan_findings, package=package)
    result.domains_scanned = domains

    if not domains:
        if progress_callback:
            progress_callback("OSINT: no se encontraron dominios propios para analizar")
        # Aún generamos dorks con lo que tengamos
        if gen_dorks:
            result.dorks = generate_dorks(package, secrets, domains, [])
        return result

    # 3. Enumeración de subdominios
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
            search_github_code(github_queries, progress_callback=progress_callback)
        )

    # 5. Generar dorks
    if gen_dorks:
        result.dorks = generate_dorks(package, secrets, domains, result.subdomains)

    if progress_callback:
        progress_callback(
            f"OSINT completo: "
            f"{len(result.subdomains)} subdominios, "
            f"{len(result.public_leaks)} leaks públicos"
        )

    return result
