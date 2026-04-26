"""
Detector estático de ofuscación DexGuard / Arxan.

Heurísticas aplicadas (en orden de evidencia):
  1. Firmas de vendor conocidas en strings o nombres de clase.
  2. Alto ratio de clases con nombre simple de 1-2 chars (>55 %).
  3. Múltiples archivos .dex dentro del APK (MultiDex típico de DexGuard).
  4. Muchas strings con alta entropía de Shannon (posiblemente cifradas).
  5. Keywords de cifrado en el pool de strings (decrypt, cipher, AES…).

Se considera detectado cuando se acumulan ≥ 2 evidencias.
"""

from __future__ import annotations

import math
import zipfile
from pathlib import Path

from .base import BaseDetector, DetectionResult
from nutcracker_core.i18n import t

# ── Firmas de vendor ──────────────────────────────────────────────────────────

_VENDOR_SIGS = [
    "com/guardsquare/dexguard",
    "com.guardsquare",
    "com/arxan",
    "com.arxan",
    "guardsquare",
    "dexguard",
]

# ── Umbrales ──────────────────────────────────────────────────────────────────

_OBFUSCATED_CLASS_RATIO = 0.55   # >55 % de clases con nombre 1-2 chars
_HIGH_ENTROPY_THRESHOLD = 4.5    # bits de Shannon para string cifrada
_HIGH_ENTROPY_MIN_LEN = 8        # longitud mínima para evaluar entropía
_HIGH_ENTROPY_MIN_COUNT = 80     # umbral de cantidad para ser sospechoso
_DECRYPT_KEYWORDS = ("decrypt", "decipher", "AesCipher", "StringObf", "obfusc",)

# Entropía de Shannon del contenido raw del DEX dentro del APK.
# Un DEX normal tiene entropía ~5-6 bits (mezcla de código + data).
# Un DEX cifrado (DexGuard encrypt-classes) tiene entropía >7.5 bits.
_DEX_ENCRYPTED_ENTROPY = 7.5    # bits — DEX raw casi aleatorio = cifrado
_DEX_ENCRYPTED_MIN_SIZE = 50_000  # ignorar DEX stub muy pequeños


def _pkg_to_path(package: str) -> str:
    """Convierte package Java a path Dalvik: com.foo.bar → com/foo/bar."""
    return package.replace(".", "/")


def _extract_namespace(dalvik_or_java: str, depth: int = 2) -> str:
    """Extrae las primeras N componentes de un nombre de clase.

    Acepta formatos: Lcom/foo/Bar;  o  com/foo/Bar  o  com.foo.Bar
    Devuelve: 'com.foo'
    """
    clean = dalvik_or_java.strip("L;").replace("/", ".")
    parts = clean.split(".")
    return ".".join(parts[:depth]) if len(parts) >= depth else clean


def _is_app_class(cls_name: str, app_package: str) -> bool:
    """Devuelve True si la clase pertenece al namespace de la app."""
    path = cls_name.strip("L;").replace(".", "/").lower()
    app_path = _pkg_to_path(app_package).lower()
    return path.startswith(app_path)


def _find_string_owner_class(dx, target_str: str) -> str | None:
    """Busca en dx qué clase referencia un string. Devuelve el nombre o None."""
    try:
        for s_analysis in dx.get_strings():
            if s_analysis.get_value() == target_str:
                for ref_class, _ in s_analysis.get_xref_from():
                    return ref_class.get_vm_class().get_name()
                break
    except Exception:  # noqa: BLE001
        pass
    return None


def _shannon_entropy(s: str) -> float:
    """Entropía de Shannon normalizada de un string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _simple_class_name(dalvik_name: str) -> str:
    """Extrae el nombre simple de un tipo Dalvik: Lcom/pkg/Foo; → Foo."""
    return dalvik_name.strip("L;").split("/")[-1]


class DexGuardDetector(BaseDetector):
    """Detecta ofuscación DexGuard/Arxan mediante análisis estático."""

    name = "DexGuardDetector"
    strength = "high"

    def detect(
        self,
        apk,
        dx,
        all_strings: set,
        all_classes: set,
    ) -> DetectionResult:
        details: list[str] = []

        # Obtener package de la app para distinguir código propio vs SDK
        app_package = ""
        try:
            app_package = apk.get_package() or ""
        except Exception:  # noqa: BLE001
            pass

        # ── 1. Firmas de vendor ──────────────────────────────────────────────
        vendor_in_app = False   # vendor sig en namespace propio de la app
        vendor_in_sdk = False   # vendor sig en un SDK de terceros
        sdk_names: set[str] = set()
        dex_encrypted = False

        for sig in _VENDOR_SIGS:
            sig_lo = sig.lower()

            # Buscar en clases — podemos saber directamente el namespace
            for cls in all_classes:
                if sig_lo in cls.lower():
                    if app_package and not _is_app_class(cls, app_package):
                        ns = _extract_namespace(cls)
                        details.append(t("ev_dxg_vendor_class_sdk", ns=ns, cls=cls[:80]))
                        vendor_in_sdk = True
                        sdk_names.add(ns)
                    else:
                        details.append(t("ev_dxg_vendor_class", cls=cls[:80]))
                        vendor_in_app = True
                    break

            # Buscar en strings — intentar rastrear la clase dueña via dx
            for s in all_strings:
                if sig_lo in s.lower():
                    owner = _find_string_owner_class(dx, s) if dx else None
                    if owner and app_package and not _is_app_class(owner, app_package):
                        ns = _extract_namespace(owner)
                        details.append(t("ev_dxg_vendor_string_sdk", ns=ns, s=s[:80]))
                        vendor_in_sdk = True
                        sdk_names.add(ns)
                    elif owner and app_package and _is_app_class(owner, app_package):
                        details.append(t("ev_dxg_vendor_string", s=s[:80]))
                        vendor_in_app = True
                    else:
                        # No se pudo resolver el dueño via dx — inferir por
                        # contenido del string: si contiene una firma de vendor
                        # conocida, DexGuard está embebido en algún SDK de
                        # terceros (ej: FaceTec, Unico, etc. embeben DexGuard).
                        _is_sdk_string = any(
                            v in s.lower() for v in ("dexguard", "guardsquare", "arxan")
                        )
                        if _is_sdk_string:
                            details.append(t("ev_dxg_vendor_string_3p_sdk", s=s[:80]))
                            vendor_in_sdk = True
                        else:
                            details.append(t("ev_dxg_vendor_string", s=s[:80]))
                            vendor_in_app = True
                    break

        # ── 2. Ratio de clases con nombre corto ─────────────────────────────
        total_classes = len(all_classes)
        if total_classes > 50:
            short = sum(
                1 for c in all_classes if len(_simple_class_name(c)) <= 2
            )
            ratio = short / total_classes
            if ratio > _OBFUSCATED_CLASS_RATIO:
                details.append(
                    t("ev_dxg_obf_ratio", ratio=f"{ratio:.0%}", short=f"{short:,}", total=f"{total_classes:,}")
                )

        # ── 3. Múltiples DEX en el APK + entropía de DEX raw (cifrado nativo) ──
        try:
            apk_path = getattr(apk, "filename", None)
            if apk_path:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    dex_files = [n for n in zf.namelist() if n.endswith(".dex")]
                    if len(dex_files) > 1:
                        sample = ", ".join(dex_files[:6])
                        suffix = " ..." if len(dex_files) > 6 else ""
                        details.append(
                            t("ev_dxg_multi_dex", count=len(dex_files), sample=sample, suffix=suffix)
                        )

                    # Heurística: DEX cifrado en el APK
                    # DexGuard puede cifrar el bytecode dentro del APK y
                    # descifrarlo en memoria via JNI. El resultado es un DEX
                    # con entropía casi máxima (~8 bits) que androguard no
                    # puede parsear → all_classes y all_strings quedan vacíos.
                    for dex_entry in dex_files:
                        try:
                            raw = zf.read(dex_entry)
                        except Exception:
                            continue
                        if len(raw) < _DEX_ENCRYPTED_MIN_SIZE:
                            continue
                        # Calcular entropía de bytes (256 símbolos)
                        freq: dict[int, int] = {}
                        for b in raw:
                            freq[b] = freq.get(b, 0) + 1
                        n = len(raw)
                        byte_entropy = -sum(
                            (c / n) * math.log2(c / n) for c in freq.values()
                        )
                        if byte_entropy >= _DEX_ENCRYPTED_ENTROPY:
                            details.append(
                                t("ev_dxg_encrypted_dex", entry=dex_entry, entropy=byte_entropy, size_kb=len(raw) // 1024)
                            )
                            dex_encrypted = True
        except Exception:  # noqa: BLE001
            pass

        # ── 4. Strings con alta entropía (posiblemente cifradas) ─────────────
        high_entropy_count = sum(
            1
            for s in all_strings
            if len(s) >= _HIGH_ENTROPY_MIN_LEN
            and _shannon_entropy(s) > _HIGH_ENTROPY_THRESHOLD
        )
        if high_entropy_count > _HIGH_ENTROPY_MIN_COUNT:
            details.append(
                t("ev_dxg_high_entropy", count=f"{high_entropy_count:,}")
            )

        # ── 5. Keywords de cifrado en el pool de strings ─────────────────────
        crypto_hits = [
            s
            for s in all_strings
            if any(kw.lower() in s.lower() for kw in _DECRYPT_KEYWORDS)
        ]
        if crypto_hits:
            sample = ", ".join(f"'{h[:40]}'" for h in crypto_hits[:3])
            details.append(t("ev_dxg_crypto_indicators", sample=sample))

        # DEX cifrado detectado: evidencia independiente de vendor sigs.
        # Si androguard no pudo parsear nada (all_classes vacío) pero el
        # DEX raw tiene entropía ~8 bits, la ausencia de firmas es esperada.

        if vendor_in_app:
            detected = len(details) >= 2
        elif vendor_in_sdk:
            detected = True
            sdk_list = ", ".join(sorted(sdk_names)) if sdk_names else "SDK de terceros"
            details.append(t("ev_dxg_embedded_in", sdk_list=sdk_list))
        elif dex_encrypted:
            # DEX cifrado sin firma de vendor visible: DexGuard o protector
            # nativo similar (Arxan, Naga, etc.). Reportar como detected.
            detected = True
        else:
            detected = False

        strength = self.strength
        if dex_encrypted and not vendor_in_app and not vendor_in_sdk:
            strength = "medium"  # sin firma de vendor, confianza reducida

        return DetectionResult(
            name=self.name,
            detected=detected,
            strength=strength,
            details=details,
        )
