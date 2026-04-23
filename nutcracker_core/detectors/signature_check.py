"""
Detector de verificación de integridad de firma del APK (MASVS-RESILIENCE-4).

Busca patrones que indican que la app comprueba su propia firma en runtime:
  - PackageManager.getSignatures() / getPackageInfo con GET_SIGNATURES
  - Google Play Integrity API (ya cubierta por SafetyNetDetector, aquí se añade
    como señal adicional de integridad del APK específicamente)
  - Comparación de hashes SHA / certificados contra valor esperado
  - Librerías de verificación de integridad (Firebase App Check, etc.)
"""

from .base import BaseDetector, DetectionResult

# Clases y métodos que implican verificación activa de la firma del APK
SIGNATURE_CHECK_INDICATORS: list[str] = [
    # PackageManager — forma clásica de obtener firmas del APK instalado
    "GET_SIGNATURES",
    "GET_SIGNING_CERTIFICATES",
    "PackageInfo.signatures",
    "SigningInfo",
    # Comparación explícita de firma del APK (hash del certificado propio)
    "Signature.hashCode",
    "Signature.toCharsString",
    # Firebase App Check — atestigua que el APK no fue modificado
    "com/google/firebase/appcheck",
    "FirebaseAppCheck",
    "AppCheckToken",
    # Nombres de clase propios comunes para verificación de firma
    "SignatureVerif",
    "ApkVerif",
    "TamperDetect",
]

# Cadenas de texto específicas de verificación de firma del APK
SIGNATURE_STRING_INDICATORS: list[str] = [
    "GET_SIGNING_CERTIFICATES",
    "GET_SIGNATURES",
    "firebase.appcheck",
    "AppCheckToken",
    "SigningInfo",
]


class SignatureCheckDetector(BaseDetector):
    """Detecta verificación de integridad de firma del APK en runtime."""

    name = "Verificación de firma del APK"
    strength = "medium"

    def detect(self, apk, dx, all_strings: set, all_classes: set) -> DetectionResult:
        found: list[str] = []

        # Buscar en clases
        for indicator in SIGNATURE_CHECK_INDICATORS:
            for cls in all_classes:
                if indicator.lower() in cls.lower():
                    found.append(f"[Clase] {cls!r}")
                    break

        # Buscar en strings
        for indicator in SIGNATURE_STRING_INDICATORS:
            for s in all_strings:
                if indicator.lower() in s.lower():
                    found.append(f"[String] {s!r}")
                    break

        # Buscar acceso a PackageManager.getPackageInfo con flags de firma via dx
        try:
            for cls_obj in dx.get_classes():
                for method in cls_obj.get_methods():
                    src = str(method.get_method().get_descriptor())
                    # getPackageInfo en cualquier clase del APK (no libs de sistema)
                    class_name = str(cls_obj.name)
                    if (
                        "getPackageInfo" in src
                        and not class_name.startswith("Landroid/")
                        and not class_name.startswith("Ljava/")
                    ):
                        found.append(f"[Método] {class_name}->{src}")
                        break
        except Exception:  # noqa: BLE001
            pass

        return DetectionResult(
            name=self.name,
            detected=bool(found),
            strength=self.strength,
            details=found[:8],
        )
