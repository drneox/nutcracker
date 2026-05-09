"""
Scanner de vulnerabilidades en librerías nativas (.so) extraídas de un APK.

Complementa vuln_scanner.py (Java/Kotlin) con análisis de código nativo:
  - Símbolos importados peligrosos (buffer overflow, command injection)
  - Strings hardcodeadas sospechosas en .rodata (secretos, TLS bypass)
  - Patrones anti-debug nativos
  - Cripto débil a nivel de símbolos (MD5, DES, RC4)

Uso:
    from nutcracker_core.native_scanner import scan_native_libs
    findings = scan_native_libs(apk_path=Path("app.apk"), work_dir=Path("/tmp/nat"))
    # devuelve list[VulnFinding] compatible con ScanResult
"""

from __future__ import annotations

import math
import shutil
import subprocess
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .vuln_scanner import VulnFinding
from .i18n import t as _t


# ── Definición de reglas nativas ──────────────────────────────────────────────

@dataclass
class _NativeRule:
    rule_id: str
    title: str
    severity: str          # critical / high / medium / low / info
    category: str
    description: str
    recommendation: str
    # Símbolos importados (nm -D) que activan esta regla
    imported_symbols: list[str] = field(default_factory=list)
    # Strings (strings -n 8) que activan esta regla — comparación case-insensitive
    string_patterns: list[str] = field(default_factory=list)
    # Si True, solo reportar si la cadena tiene entropía Shannon ≥ entropy_threshold
    require_high_entropy: bool = False
    entropy_threshold: float = 3.5

    def i18n_title(self) -> str:
        key = f"rule_{self.rule_id.lower()}_title"
        val = _t(key)
        return val if val != key else self.title

    def i18n_desc(self) -> str:
        key = f"rule_{self.rule_id.lower()}_desc"
        val = _t(key)
        return val if val != key else self.description

    def i18n_rec(self) -> str:
        key = f"rule_{self.rule_id.lower()}_rec"
        val = _t(key)
        return val if val != key else self.recommendation


_NATIVE_RULES: list[_NativeRule] = [
    # ── NAT001: Funciones de manejo de buffer inseguras ───────────────────────
    _NativeRule(
        rule_id="NAT001",
        title="Funciones inseguras de manejo de buffer importadas",
        severity="high",
        category="M7 - Inyección / Buffer overflow",
        imported_symbols=[
            "strcpy", "strcat", "gets", "sprintf", "vsprintf",
            "strncpy",   # no null-termina garantizado
            "strncat",
            "scanf", "sscanf", "fscanf",
            "memcpy",    # solo si no verifica longitud — lo reportamos como aviso
            "memmove",
        ],
        description=(
            "La librería importa funciones C inseguras que no verifican límites de buffer "
            "(strcpy, gets, sprintf, etc.). Si los argumentos provienen de fuentes no confiables, "
            "pueden derivar en buffer overflow, stack smashing o corrupción de memoria."
        ),
        recommendation=(
            "Reemplazar con equivalentes seguros: strncpy→strlcpy, sprintf→snprintf, "
            "gets→fgets. Activar flags de compilación: -D_FORTIFY_SOURCE=2 -fstack-protector-all."
        ),
    ),

    # ── NAT002: Ejecución de comandos del sistema ─────────────────────────────
    _NativeRule(
        rule_id="NAT002",
        title="Ejecución de comandos del sistema en código nativo",
        severity="critical",
        category="M7 - Inyección",
        imported_symbols=["system", "popen", "execve", "execl", "execlp", "execvp", "execvpe"],
        description=(
            "La librería importa funciones de ejecución de comandos del sistema "
            "(system, popen, execve, etc.). Si el input no está sanitizado, permite "
            "inyección de comandos del SO."
        ),
        recommendation=(
            "Evitar system() y popen(). Si es imprescindible, sanitizar y validar "
            "todo argumento externo. Nunca construir comandos por concatenación de strings."
        ),
    ),

    # ── NAT003: Anti-debug nativo ─────────────────────────────────────────────
    _NativeRule(
        rule_id="NAT003",
        title="Strings de anti-debug / detección de análisis",
        severity="info",
        category="M9 - Ingeniería inversa",
        string_patterns=[
            "/proc/self/status",
            "TracerPid",
            "ptrace",
            "/proc/self/maps",
            "frida",
            "xposed",
            "substrate",
            "gadget",
            "/proc/self/mem",
            "android_server",
        ],
        description=(
            "La librería contiene strings relacionados con detección de debuggers, "
            "Frida, Xposed o técnicas anti-análisis. Esto indica que implementa "
            "protecciones RASP a nivel nativo."
        ),
        recommendation=(
            "Documentar para el report. Estos strings son candidatos para patch con "
            "Memory.patchCode() o patch_native_lib durante el análisis dinámico."
        ),
    ),

    # ── NAT004: Secretos hardcodeados con alta entropía ───────────────────────
    _NativeRule(
        rule_id="NAT004",
        title="Posibles secretos hardcodeados en código nativo (alta entropía)",
        severity="high",
        category="M2 - Almacenamiento inseguro",
        string_patterns=[],          # detectado por entropía, no por patrón fijo
        require_high_entropy=True,
        entropy_threshold=4.2,
        description=(
            "Se encontraron strings de alta entropía en la sección .rodata de la "
            "librería. Pueden ser API keys, tokens, claves de cifrado o secretos "
            "hardcodeados incrustados en el binario nativo."
        ),
        recommendation=(
            "Auditar manualmente cada string de alta entropía. Mover secretos a "
            "almacenamiento seguro (Android Keystore, servidor). No incrustar "
            "credenciales en binarios distribuidos."
        ),
    ),

    # ── NAT005: TLS bypass en código nativo ───────────────────────────────────
    _NativeRule(
        rule_id="NAT005",
        title="Strings de bypass TLS / desactivación de verificación SSL",
        severity="high",
        category="M3 - Comunicación insegura",
        string_patterns=[
            "CURLOPT_SSL_VERIFYPEER",
            "CURLOPT_SSL_VERIFYHOST",
            "ssl_verify_none",
            "SSL_VERIFY_NONE",
            "SSL_CTX_set_verify",
            "setHostnameVerifier",
            "ALLOW_ALL_HOSTNAME",
        ],
        description=(
            "La librería contiene strings asociados con la desactivación de "
            "verificación TLS/SSL (CURLOPT_SSL_VERIFYPEER=0, SSL_VERIFY_NONE, etc.). "
            "Indica que las conexiones HTTPS pueden no verificar el certificado del servidor."
        ),
        recommendation=(
            "Verificar el contexto exacto con disassemble_native_lib. "
            "SSL_CTX_set_verify debe llamarse con SSL_VERIFY_PEER, nunca con SSL_VERIFY_NONE."
        ),
    ),

    # ── NAT006: Root / entorno comprometido ───────────────────────────────────
    _NativeRule(
        rule_id="NAT006",
        title="Strings de detección de root en código nativo",
        severity="medium",
        category="M8 - Manipulación de código",
        string_patterns=[
            "/data/local/tmp",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "magisk",
            "supersu",
            "superuser",
            "busybox",
            "/proc/net/unix",
        ],
        description=(
            "La librería contiene strings de rutas y binarios típicos de dispositivos "
            "rooteados. Implementa detección de root a nivel nativo."
        ),
        recommendation=(
            "Documentar. Durante bypass dinámico, estos strings son candidatos a parchear "
            "con Memory.patchCode() para que las comprobaciones devuelvan 'no root'."
        ),
    ),

    # ── NAT007: Carga dinámica de SSL (dlopen + dlsym) ────────────────────────
    _NativeRule(
        rule_id="NAT007",
        title="Carga dinámica de libssl / pinning nativo custom",
        severity="medium",
        category="M3 - Comunicación insegura",
        imported_symbols=["dlopen", "dlsym"],
        string_patterns=["libssl", "libcrypto", "SSL_CTX_new", "SSL_new", "certificate"],
        description=(
            "La librería usa dlopen/dlsym junto con strings de SSL. Indica pinning "
            "implementado nativamente cargando libssl de forma dinámica, lo que evita "
            "los hooks estándar de Interceptor.attach sobre símbolos exportados."
        ),
        recommendation=(
            "Usar Memory.scanSync para encontrar la función SSL en memoria en lugar de "
            "resolver por símbolo exportado. Ver Phase 2 del sistema de bypass."
        ),
    ),

    # ── NAT008: Cripto débil a nivel de símbolo nativo ────────────────────────
    _NativeRule(
        rule_id="NAT008",
        title="Algoritmos criptográficos débiles en código nativo (MD5, DES, RC4)",
        severity="high",
        category="M5 - Criptografía insuficiente",
        imported_symbols=[
            "MD5_Init", "MD5_Update", "MD5_Final",
            "MD2_Init",
            "DES_key_sched", "DES_ecb_encrypt", "DES_cbc_encrypt",
            "RC4_set_key", "RC4",
            "SHA1_Init",    # SHA1 solo para signing es riesgo
        ],
        description=(
            "La librería importa funciones de algoritmos criptográficos débiles o rotos: "
            "MD5, MD2, DES, RC4 y/o SHA1. Estos algoritmos no son seguros para uso "
            "criptográfico (hashing de contraseñas, cifrado de datos sensibles)."
        ),
        recommendation=(
            "Migrar a AES-256-GCM para cifrado, SHA-256/SHA-3 para hashing. "
            "Nunca usar MD5 o SHA1 para verificar integridad de datos sensibles."
        ),
    ),
]


# ── Utilidades ────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Entropía de Shannon de un string (0-8 bits/char para ASCII)."""
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _extract_so_files(apk_path: Path, work_dir: Path) -> list[Path]:
    """Extrae todos los .so del APK en work_dir/native_libs/. Retorna lista de paths."""
    out_dir = work_dir / "native_libs"
    out_dir.mkdir(parents=True, exist_ok=True)

    extracted: list[Path] = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for entry in zf.namelist():
                if entry.endswith(".so") and not entry.endswith("/"):
                    # Aplanar la ruta para evitar colisiones de ABI: lib/arm64-v8a/foo.so → arm64-v8a_foo.so
                    parts = Path(entry).parts
                    flat_name = "_".join(parts[1:]) if len(parts) > 1 else parts[0]
                    dest = out_dir / flat_name
                    if not dest.exists():
                        dest.write_bytes(zf.read(entry))
                    extracted.append(dest)
    except (zipfile.BadZipFile, OSError):
        pass

    return extracted


def _get_imported_symbols(so_path: Path) -> list[str]:
    """
    Devuelve la lista de símbolos importados (undefined) del .so usando nm o objdump.
    Prefiere nm (más universal), fallback a objdump.
    """
    nm = shutil.which("nm") or shutil.which("arm-linux-androideabi-nm")
    if nm:
        try:
            result = subprocess.run(
                [nm, "-D", "--undefined-only", str(so_path)],
                capture_output=True, text=True, timeout=15,
            )
            symbols: list[str] = []
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    symbols.append(parts[-1].lstrip("_"))
            return symbols
        except (subprocess.TimeoutExpired, OSError):
            pass

    objdump = shutil.which("objdump") or shutil.which("llvm-objdump")
    if objdump:
        try:
            result = subprocess.run(
                [objdump, "-T", str(so_path)],
                capture_output=True, text=True, timeout=15,
            )
            symbols = []
            for line in result.stdout.splitlines():
                if "*UND*" in line or "UND" in line:
                    parts = line.strip().split()
                    if parts:
                        symbols.append(parts[-1].lstrip("_"))
            return symbols
        except (subprocess.TimeoutExpired, OSError):
            pass

    return []


def _get_strings(so_path: Path, min_len: int = 8) -> list[str]:
    """Extrae strings imprimibles del .so. Usa el comando `strings` si está disponible."""
    strings_bin = shutil.which("strings")
    if strings_bin:
        try:
            result = subprocess.run(
                [strings_bin, "-n", str(min_len), str(so_path)],
                capture_output=True, text=True, timeout=20,
            )
            return result.stdout.splitlines()
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Fallback Python puro: extraer secuencias ASCII imprimibles
    found: list[str] = []
    try:
        data = so_path.read_bytes()
        current: list[int] = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(byte)
            else:
                if len(current) >= min_len:
                    found.append(bytes(current).decode("ascii", errors="replace"))
                current = []
        if len(current) >= min_len:
            found.append(bytes(current).decode("ascii", errors="replace"))
    except OSError:
        pass
    return found


# ── Scanner principal ─────────────────────────────────────────────────────────

def scan_native_libs(
    apk_path: Path,
    work_dir: Path,
    progress_callback: Callable[[str], None] | None = None,
    abi_filter: str | None = "arm64-v8a",
) -> list[VulnFinding]:
    """
    Extrae los .so del APK y aplica reglas NAT001-NAT008.

    Args:
        apk_path:          Path al APK (o split APK).
        work_dir:          Directorio temporal donde se extraerán los .so.
        progress_callback: Función(str) para mensajes de progreso.
        abi_filter:        Si se especifica, solo escanear .so de esa ABI.
                           None = escanear todas las ABIs.

    Returns:
        Lista de VulnFinding compatible con ScanResult.findings.
    """

    def _cb(msg: str) -> None:
        if progress_callback:
            progress_callback(msg)

    apk_path = Path(apk_path)
    work_dir = Path(work_dir)

    if not apk_path.exists():
        _cb(f"native_scanner: APK no encontrado en {apk_path}")
        return []

    _cb("Extrayendo librerías nativas del APK…")
    all_so = _extract_so_files(apk_path, work_dir)

    if not all_so:
        _cb("native_scanner: no se encontraron .so en el APK")
        return []

    # Filtrar por ABI si se especificó
    if abi_filter:
        filtered = [p for p in all_so if abi_filter in p.name]
        # Si no hay .so para esa ABI usar todos (e.g. APK universal)
        all_so = filtered if filtered else all_so

    _cb(f"Escaneando {len(all_so)} librería(s) nativa(s)…")

    findings: list[VulnFinding] = []

    for so_path in all_so:
        lib_name = so_path.name
        _cb(f"  → {lib_name}")

        imported_syms = _get_imported_symbols(so_path)
        imported_set = {s.lower() for s in imported_syms}

        all_strings = _get_strings(so_path)
        strings_lower = [s.lower() for s in all_strings]

        # Agrupar hallazgos por regla para este .so (evitar duplicados masivos)
        # Solo reportamos el primer match por (rule_id, .so) — suficiente para el report
        matched_rules: set[str] = set()

        for rule in _NATIVE_RULES:
            if rule.rule_id in matched_rules:
                continue

            matched_text = ""
            matched_line = 0  # .so no tiene líneas — usamos 0

            # Comprobar símbolos importados
            for sym in rule.imported_symbols:
                sym_lower = sym.lower()
                # Buscar coincidencia exacta o con prefijo __
                if sym_lower in imported_set or f"__{sym_lower}" in imported_set:
                    matched_text = sym
                    break

            # Comprobar strings (si no hubo match por símbolo)
            if not matched_text:
                for pattern in rule.string_patterns:
                    pat_lower = pattern.lower()
                    for s in strings_lower:
                        if pat_lower in s:
                            matched_text = s[:120]
                            break
                    if matched_text:
                        break

            # Regla NAT004: alta entropía (sin pattern fijo)
            if not matched_text and rule.require_high_entropy:
                for raw_str in all_strings:
                    if len(raw_str) >= 20 and _shannon_entropy(raw_str) >= rule.entropy_threshold:
                        # Filtrar strings que claramente son rutas o nombres de función
                        if not raw_str.startswith("/") and "." not in raw_str[:4]:
                            matched_text = raw_str[:80]
                            break

            if not matched_text:
                continue

            # Regla NAT007: requiere AMBAS condiciones (dlopen/dlsym + strings ssl)
            if rule.rule_id == "NAT007":
                has_dlopen = "dlopen" in imported_set or "dlsym" in imported_set
                has_ssl_str = any(
                    p.lower() in s for p in rule.string_patterns for s in strings_lower
                )
                if not (has_dlopen and has_ssl_str):
                    continue

            matched_rules.add(rule.rule_id)
            findings.append(VulnFinding(
                rule_id=rule.rule_id,
                title=rule.i18n_title(),
                severity=rule.severity,
                category=rule.category,
                file=so_path,
                line=matched_line,
                matched_text=matched_text,
                description=rule.i18n_desc(),
                recommendation=rule.i18n_rec(),
            ))

    _cb(f"native_scanner: {len(findings)} hallazgo(s) en librerías nativas")
    return findings
