"""Scanners de leaks/secretos vía herramientas externas: apkleaks y gitleaks.

Extraído de vuln_scanner.py (Fase 0.3 del plan): vuln_scanner.py conserva las
reglas regex + semgrep (código estático de la app); este módulo cubre los dos
motores externos de detección de secretos que operan sobre el binario APK
(apkleaks) o el árbol de código decompilado (gitleaks).
"""

from __future__ import annotations

import re
from pathlib import Path

from .scan_types import VulnFinding

# ── Integración con apkleaks ──────────────────────────────────────────────────

# Mapeo de categoría apkleaks → severidad
_APKLEAKS_SEVERITY: dict[str, str] = {
    "RSA_Private_Key": "critical",
    "PGP_private_key_block": "critical",
    "SSH_DSA_Private_Key": "critical",
    "SSH_EC_Private_Key": "critical",
    "Amazon_AWS_Access_Key_ID": "high",
    "AWS_API_Key": "high",
    "GitHub_Access_Token": "high",
    "Stripe_API_Key": "high",
    "Stripe_Restricted_API_Key": "high",
    "PayPal_Braintree_Access_Token": "high",
    "Heroku_API_Key": "high",
    "Twilio_API_Key": "high",
    "Firebase": "high",
    "Google_API_Key": "high",
    "Google_Cloud_Platform_Service_Account": "high",
    "Google_OAuth_Access_Token": "high",
    "Slack_Token": "high",
    "Slack_Webhook": "high",
    "MailChimp_API_Key": "high",
    "Mailgun_API_Key": "high",
    "Picatic_API_Key": "high",
    "Square_Access_Token": "high",
    "Square_OAuth_Secret": "high",
    "Facebook_Access_Token": "high",
    "Facebook_Secret_Key": "high",
    "Twitter_Secret_Key": "high",
    "Twitter_Access_Token": "high",
    "Twitter_OAuth": "high",
    "Authorization_Basic": "high",
    "Authorization_Bearer": "high",
    "JSON_Web_Token": "high",
    "Password_in_URL": "high",
    "Basic_Auth_Credentials": "high",
    "Cloudinary_Basic_Auth": "high",
    "Artifactory_API_Token": "medium",
    "Artifactory_Password": "medium",
    "Generic_API_Key": "medium",
    "Generic_Secret": "medium",
    "Amazon_AWS_S3_Bucket": "medium",
    "Google_Cloud_Platform_OAuth": "medium",
    "Facebook_ClientID": "low",
    "Facebook_OAuth": "low",
    "Twitter_ClientID": "low",
    "GitHub": "low",
    "Discord_BOT_Token": "medium",
    "IP_Address": "info",
    "Mac_Address": "info",
    "Mailto": "info",
    "LinkFinder": "info",
    "DEFCON_CTF_Flag": "info",
    "HackerOne_CTF_Flag": "info",
    "HackTheBox_CTF_Flag": "info",
    "TryHackMe_CTF_Flag": "info",
}


def scan_with_apkleaks(
    apk_path: Path,
    progress_callback=None,
) -> list[VulnFinding]:
    """
    Ejecuta apkleaks sobre el APK original y convierte sus hallazgos a VulnFinding.
    Requiere apkleaks instalado (pip install apkleaks).
    Devuelve lista vacía si apkleaks no está disponible o falla.
    """
    import json as _json
    import shutil
    import subprocess
    import tempfile

    def _parse_plain_output(raw_text: str) -> dict[str, list[str]]:
        """Parsea salida estilo texto de apkleaks: [Categoria] y lineas '- valor'."""
        parsed: dict[str, list[str]] = {}
        current: str | None = None
        for line in raw_text.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("[") and s.endswith("]") and len(s) > 2:
                current = s[1:-1].strip()
                if current:
                    parsed.setdefault(current, [])
                continue
            if current and s.startswith("- "):
                value = s[2:].strip()
                if value:
                    parsed[current].append(value)
        return parsed

    apkleaks_bin = shutil.which("apkleaks")
    if not apkleaks_bin:
        if progress_callback:
            progress_callback("apkleaks no encontrado — omitiendo scan de secretos con apkleaks")
        return []

    if progress_callback:
        progress_callback("Escaneando secretos con apkleaks...")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    try:
        proc = subprocess.run(
            [apkleaks_bin, "-f", str(apk_path), "-o", out_path, "--json"],
            capture_output=True,
            text=True,
            timeout=240,
        )
        if proc.returncode not in (0, 1):
            if progress_callback:
                progress_callback(f"apkleaks terminó con rc={proc.returncode}")
            return []

        raw = Path(out_path).read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            return []

        data: dict[str, object]
        try:
            decoded = _json.loads(raw)
            if isinstance(decoded, dict):
                data = decoded
            else:
                data = {"results": []}
        except _json.JSONDecodeError:
            plain = _parse_plain_output(raw)
            data = {
                "results": [
                    {"name": name, "matches": values}
                    for name, values in plain.items()
                ]
            }
    except subprocess.TimeoutExpired:
        if progress_callback:
            progress_callback("apkleaks timeout (>240s), omitiendo")
        return []
    except OSError:
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)

    findings: list[VulnFinding] = []
    for entry in data.get("results", []):
        name: str = entry.get("name", "Unknown")
        matches: list[str] = entry.get("matches", [])
        severity = _APKLEAKS_SEVERITY.get(name, "medium")
        # Omitir categorías de solo info (IP, URLs, etc.) — demasiado ruido
        if severity == "info":
            continue
        if name == "LinkFinder":
            continue
        for match in matches:
            # ── Filtro de falsos positivos conocidos de apkleaks ──────────
            if _is_apkleaks_false_positive(name, match):
                continue
            findings.append(VulnFinding(
                rule_id=f"AL-{name[:20]}",
                title=name.replace("_", " "),
                severity=severity,
                category="M1 - Credenciales",
                file=apk_path,
                line=0,
                matched_text=match[:120],
                description=f"Secreto o credencial detectada por apkleaks: {name}.",
                recommendation="Eliminar credenciales del código. Usar variables de entorno o un gestor de secretos.",
            ))

    if progress_callback:
        pre_count = sum(len(e.get("matches", [])) for e in data.get("results", []))
        if pre_count != len(findings):
            progress_callback(
                f"apkleaks: {len(findings)} secreto(s) tras filtrar "
                f"{pre_count - len(findings)} falso(s) positivo(s)"
            )
        elif findings:
            progress_callback(f"apkleaks: {len(findings)} secreto(s) encontrado(s)")

    return findings


# ── Filtro de falsos positivos de apkleaks ────────────────────────────────────

# Patrones de valores que apkleaks reporta pero NO son secretos reales
_APKLEAKS_FP_PATTERNS: list[re.Pattern] = [
    # "version=X.Y.Z" matcheado como JWT (es metadata de librerías GMS)
    re.compile(r'^(?:version|common_client|googleid_client|image_client|review_client)=[\d.]+'),
    # "basic constraint(s)" matcheado como Authorization Basic (es parte de X.509 certs)
    re.compile(r'^basic\s+constraint'),
    # Números de versión sueltos que no son tokens
    re.compile(r'^[\d.]+$'),
]

# Categorías de apkleaks con alta tasa de FP en APKs Android normales
_APKLEAKS_NOISY_CATEGORIES: dict[str, re.Pattern] = {
    # JSON_Web_Token: apkleaks matchea "key=value" de metadata GMS como JWT
    "JSON_Web_Token": re.compile(
        r'^(?:version|common_client|googleid_client|image_client|review_client)='
        r'|^[\w._]+=[\d.]+$'
    ),
    # Authorization_Basic: matchea "basic constraint" de certificados X.509
    "Authorization_Basic": re.compile(
        r'basic\s+constraint|BasicConstraints'
    ),
    # Facebook_Secret_Key: FACEBOOK_SIGNATURE es la firma pública del SDK, no un secreto
    "Facebook_Secret_Key": re.compile(
        r'FACEBOOK_SIGNATURE\s*='
    ),
}


def _is_apkleaks_false_positive(category: str, match_text: str) -> bool:
    """Devuelve True si el hallazgo de apkleaks es un falso positivo conocido."""
    text = match_text.strip()

    # Filtros genéricos (aplican a cualquier categoría)
    for fp_pattern in _APKLEAKS_FP_PATTERNS:
        if fp_pattern.search(text):
            return True

    # Filtros por categoría
    cat_pattern = _APKLEAKS_NOISY_CATEGORIES.get(category)
    if cat_pattern and cat_pattern.search(text):
        return True

    return False


# ── Gitleaks scanner ──────────────────────────────────────────────────────────

# Reglas de gitleaks cuyo hallazgo se considera critical (claves privadas, AWS, etc.)
_GITLEAKS_CRITICAL_RULES: set[str] = {
    "private-key",
    "aws-access-token",
    "aws-secret-access-key",
    "github-pat",
    "github-fine-grained-pat",
    "gitlab-pat",
    "stripe-access-token",
    "twilio-api-key",
    "generic-api-key",
}


def scan_with_gitleaks(
    source_dir: Path,
    progress_callback=None,
) -> list[VulnFinding]:
    """
    Ejecuta gitleaks sobre un directorio de código decompilado y convierte
    sus hallazgos a VulnFinding.
    Requiere gitleaks instalado (brew install gitleaks).
    Devuelve lista vacía si gitleaks no está disponible o falla.
    """
    import json as _json
    import shutil
    import subprocess
    import tempfile

    gitleaks_bin = shutil.which("gitleaks")
    if not gitleaks_bin:
        if progress_callback:
            progress_callback("gitleaks no encontrado — omitiendo scan")
        return []

    if progress_callback:
        progress_callback("Escaneando secretos con gitleaks...")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    try:
        proc = subprocess.run(
            [
                gitleaks_bin, "detect",
                "--no-git",
                "--no-banner",
                "-s", str(source_dir),
                "-f", "json",
                "-r", out_path,
                "--log-level", "error",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        # rc=0 → sin hallazgos, rc=1 → hallazgos encontrados, ≥2 → error
        if proc.returncode >= 2:
            if progress_callback:
                progress_callback(f"gitleaks terminó con rc={proc.returncode}")
            return []

        raw = Path(out_path).read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            return []

        try:
            items = _json.loads(raw)
        except _json.JSONDecodeError:
            if progress_callback:
                progress_callback("gitleaks: JSON inválido")
            return []

        if not isinstance(items, list):
            return []

    except subprocess.TimeoutExpired:
        if progress_callback:
            progress_callback("gitleaks timeout (>300s), omitiendo")
        return []
    except OSError:
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)

    findings: list[VulnFinding] = []
    for item in items:
        rule_id = item.get("RuleID", "unknown")
        description = item.get("Description", rule_id)
        secret = item.get("Secret", item.get("Match", ""))
        file_path = item.get("File", "")
        start_line = item.get("StartLine", 0)
        entropy = item.get("Entropy", 0.0)

        severity = "critical" if rule_id in _GITLEAKS_CRITICAL_RULES else "high"

        desc_text = f"{description}"
        if entropy:
            desc_text += f" (entropy: {entropy:.2f})"

        findings.append(VulnFinding(
            rule_id=f"GL-{rule_id}",
            title=description,
            severity=severity,
            category="M1 - Credenciales",
            file=Path(file_path),
            line=start_line,
            matched_text=secret[:120] if secret else "",
            description=desc_text,
            recommendation="Eliminar credenciales del código. Usar variables de entorno o un gestor de secretos.",
        ))

    if progress_callback:
        progress_callback(f"gitleaks: {len(findings)} secreto(s) encontrado(s)")

    return findings
