"""
Detector de uso de SafetyNet Attestation API y Play Integrity API.

Ambas APIs permiten a las apps verificar si el dispositivo está rooteado
o ha sido comprometido, a través de los servidores de Google.
"""

from .base import BaseDetector, DetectionResult

# Clases y strings relacionados con SafetyNet
SAFETYNET_INDICATORS: list[str] = [
    # SafetyNet API (deprecada pero aún en uso)
    "com/google/android/gms/safetynet/SafetyNetApi",
    "com/google/android/gms/safetynet/SafetyNet",
    "com/google/android/gms/safetynet/SafetyNetClient",
    "com/google/android/gms/safetynet/HarmfulAppsData",
    "SafetyNetApi",
    "SafetyNetClient",
    # NOTA: se eliminaron "attest" y "safetynet" por ser demasiado genéricos
    # y producir FP con strings de Google Ads (gads:gma_attestation:*).
]

# Clases y strings relacionados con Play Integrity API (reemplazo de SafetyNet)
PLAY_INTEGRITY_INDICATORS: list[str] = [
    # Solo rutas completas de Google Play Integrity API.
    # NOTA: se eliminaron nombres cortos como "IntegrityManager" que producen
    # FP con com.facebook.appevents.integrity.IntegrityManager (SDK de ads).
    "com/google/android/play/core/integrity/IntegrityManager",
    "com/google/android/play/core/integrity/IntegrityTokenProvider",
    "com/google/android/play/core/integrity/IntegrityTokenRequest",
    "com/google/android/play/core/integrity/model/IntegrityErrorCode",
    "com/google/android/play/core/integrity/StandardIntegrityManager",
    "play.core.integrity",
]


class SafetyNetDetector(BaseDetector):
    """Detecta uso de SafetyNet Attestation API y Play Integrity API."""

    name = "SafetyNet / Play Integrity API"
    strength = "high"

    def detect(self, apk, dx, all_strings: set, all_classes: set) -> DetectionResult:
        found: list[str] = []

        combined = all_classes | all_strings

        # Verificar SafetyNet
        for indicator in SAFETYNET_INDICATORS:
            for item in combined:
                if indicator.lower() in item.lower():
                    found.append(f"[SafetyNet] {item!r}")
                    break

        # Verificar Play Integrity
        for indicator in PLAY_INTEGRITY_INDICATORS:
            for item in combined:
                if indicator.lower() in item.lower():
                    found.append(f"[Play Integrity] {item!r}")
                    break

        # Verificar en el manifest (permisos o dependencias relevantes)
        try:
            declared_permissions = apk.get_declared_permissions()
            for perm in declared_permissions:
                if "integrity" in perm.lower() or "safetynet" in perm.lower():
                    found.append(f"[Permiso] {perm}")
        except Exception:  # noqa: BLE001
            pass

        # Deduplicar manteniendo orden
        seen: set[str] = set()
        unique_found: list[str] = []
        for item in found:
            if item not in seen:
                seen.add(item)
                unique_found.append(item)

        return DetectionResult(
            name=self.name,
            detected=bool(unique_found),
            strength=self.strength,
            details=unique_found,
        )
