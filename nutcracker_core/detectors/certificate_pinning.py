"""
Detector de certificate pinning (MASVS-NETWORK-2).

Busca evidencia POSITIVA de que la app implementa pinning de certificados:
  - OkHttp CertificatePinner
  - Network Security Config con <pin-set>
  - TrustKit
  - Strings con formato sha256/ (hashes de certificados)

Este detector es "solo positivo": si no encuentra nada no implica fallo,
solo que no hay evidencia de pinning implementado (not_tested).
"""

from .base import BaseDetector, DetectionResult
from nutcracker_core.i18n import t

# Señales de clase que por sí solas ya son evidencia fuerte de pinning real
# -- nombres de librerías/patrones específicos de pinning, no clases
# genéricas de networking que cualquier app podría traer sin usarlas para eso.
STRONG_CLASS_INDICATORS: list[str] = [
    # TrustKit (Datadog / DataTheorem)
    "com/datatheorem/android/trustkit",
    "TrustKit",
    "TrustKitConfiguration",
    # Conscrypt / custom TrustManager con pinning
    "PinningTrustManager",
    "PublicKeyPinning",
    # NO "CertificatePin" a secas -- es prefijo literal de "CertificatePinner"
    # (el indicador AMBIGUO de abajo), así que como substring colisionaría y
    # anularía el gating que este mismo archivo implementa a propósito.
]

# FIX (encontrado en vivo, 2026-08-04, job 2822/sh.nutcracker.nutbank):
# okhttp3.CertificatePinner es una señal AMBIGUA por sí sola -- esa clase
# viene incluida en la librería OkHttp y aparece en el dex de CUALQUIER app
# que la use como dependencia, esté o no configurando pinning real (un
# método dummy `disableCertificatePinning()` que solo loguea disparaba
# detected=True porque la clase está en el classpath, no porque la app la
# use de verdad). Solo cuenta como evidencia si además aparece un hash de
# pin real (sha256/, NSC <pin-set>) -- ver detect() más abajo.
AMBIGUOUS_CLASS_INDICATORS: list[str] = [
    "CertificatePinner",
    "okhttp3/CertificatePinner",
]

# Señales en strings extraídos del APK (resources, assets, código)
PINNING_STRING_INDICATORS: list[str] = [
    # Hash de certificado en formato estándar OkHttp / NSC
    "sha256/",
    "sha1/",
    # Network Security Config con pin-set
    "<pin-set",
    "pin-set>",
    # TrustKit config key
    "trustkit",
    "kTSKPublicKeyHashes",
    "kTSKEnforcePinning",
]


def _matching_classes(indicators: list[str], all_classes: set) -> list[str]:
    found: list[str] = []
    for indicator in indicators:
        for cls in all_classes:
            if indicator.lower() in cls.lower():
                found.append(t("ev_class", item=cls))
                break
    return found


class CertificatePinningDetector(BaseDetector):
    """Detecta implementación de certificate pinning (validación positiva)."""

    name = "Certificate pinning"
    strength = "high"

    def detect(self, apk, dx, all_strings: set, all_classes: set) -> DetectionResult:
        strong_found = _matching_classes(STRONG_CLASS_INDICATORS, all_classes)
        ambiguous_found = _matching_classes(AMBIGUOUS_CLASS_INDICATORS, all_classes)

        string_found: list[str] = []
        for indicator in PINNING_STRING_INDICATORS:
            for s in all_strings:
                if indicator.lower() in s.lower():
                    string_found.append(t("ev_string", item=s))
                    break

        # Buscar en archivos XML del APK (Network Security Config)
        nsc_found: list[str] = []
        try:
            for fname in apk.get_files():
                if fname.endswith(".xml") and ("network_security" in fname or "res/xml" in fname):
                    try:
                        content = apk.get_file(fname).decode("utf-8", errors="ignore")
                        if "<pin-set" in content or "sha256/" in content:
                            nsc_found.append(f"[NSC] {fname}")
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass

        # Los indicadores AMBIGUOS (okhttp3.CertificatePinner) solo cuentan
        # como evidencia si hay un hash de pin real acompañándolos -- si no,
        # es la clase presente por ser dependencia transitiva de OkHttp, no
        # pinning configurado de verdad.
        has_real_pin_evidence = bool(string_found or nsc_found)
        found = strong_found + string_found + nsc_found
        if has_real_pin_evidence:
            found += ambiguous_found

        return DetectionResult(
            name=self.name,
            detected=bool(found),
            strength=self.strength,
            details=found[:8],
        )
