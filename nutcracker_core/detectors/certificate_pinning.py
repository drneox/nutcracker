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

# Señales positivas de pinning en clases / métodos
PINNING_CLASS_INDICATORS: list[str] = [
    # OkHttp CertificatePinner
    "CertificatePinner",
    "okhttp3/CertificatePinner",
    # TrustKit (Datadog / DataTheorem)
    "com/datatheorem/android/trustkit",
    "TrustKit",
    "TrustKitConfiguration",
    # Conscrypt / custom TrustManager con pinning
    "PinningTrustManager",
    "PublicKeyPinning",
    "CertificatePin",
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


class CertificatePinningDetector(BaseDetector):
    """Detecta implementación de certificate pinning (validación positiva)."""

    name = "Certificate pinning"
    strength = "high"

    def detect(self, apk, dx, all_strings: set, all_classes: set) -> DetectionResult:
        found: list[str] = []

        # Buscar en clases
        for indicator in PINNING_CLASS_INDICATORS:
            for cls in all_classes:
                if indicator.lower() in cls.lower():
                    found.append(f"[Clase] {cls!r}")
                    break

        # Buscar en strings (resources, assets, strings.xml, código)
        for indicator in PINNING_STRING_INDICATORS:
            for s in all_strings:
                if indicator.lower() in s.lower():
                    found.append(f"[String] {s!r}")
                    break

        # Buscar en archivos XML del APK (Network Security Config)
        try:
            for fname in apk.get_files():
                if fname.endswith(".xml") and ("network_security" in fname or "res/xml" in fname):
                    try:
                        content = apk.get_file(fname).decode("utf-8", errors="ignore")
                        if "<pin-set" in content or "sha256/" in content:
                            found.append(f"[NSC] {fname}")
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass

        return DetectionResult(
            name=self.name,
            detected=bool(found),
            strength=self.strength,
            details=found[:8],
        )
