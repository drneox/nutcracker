"""
Detector estático de protección AppDome.

AppDome es una plataforma de blindaje de apps (no-code) que envuelve el APK
con sus propias capas de seguridad en tiempo de compilación. Las heurísticas
buscan:
  1. Packages / clases conocidas del SDK de AppDome.
  2. Assets o recursos con nombres propios de AppDome (adfutils, fusedapp, etc.).
  3. Strings características del runtime de AppDome.
  4. Permisos o meta-data específicos.
"""

from __future__ import annotations

from .base import BaseDetector, DetectionResult
from nutcracker_core.i18n import t

# ── Firmas de clases / packages ───────────────────────────────────────────────

CLASS_SIGS: list[str] = [
    # Namespace principal del SDK
    "com/appdome/",
    "com.appdome.",
    # Runtime de fusión (FusedApp)
    "adfutils",
    "fusedapp",
    "FusedApp",
    # Wrapper nativo
    "libappdome",
    "appdome_native",
    # Clases internas conocidas
    "AppdomeSDK",
    "AppdomeService",
    "AppdomePlugin",
    "AppdomeBridge",
    "AppdomeFlutterPlugin",
    "AppdomeReactNative",
]

# ── Strings características ───────────────────────────────────────────────────

STRING_SIGS: list[str] = [
    "appdome",
    "Appdome",
    # Mensajes de error / certificación
    "appdome-cert",
    "appdome.certificate",
    "appdome.attestation",
    # Rutas de assets típicas
    "assets/appdome",
    # Strings del agente de seguridad
    "appdome-version",
    "appdome_build_id",
]

# ── Assets / ficheros en el APK ───────────────────────────────────────────────

ASSET_SIGS: list[str] = [
    "appdome",
    "adfutils",
    "fusedapp",
]


class AppdomeDetector(BaseDetector):
    """Detecta protección AppDome en el APK analizado."""

    name = "AppDome"
    strength = "high"

    def detect(self, apk, dx, all_strings: set, all_classes: set) -> DetectionResult:
        found: list[str] = []

        # 1. Buscar en clases
        for sig in CLASS_SIGS:
            sig_lower = sig.lower()
            matches = [
                cls for cls in all_classes
                if sig_lower in cls.lower() and len(cls) < 300
            ]
            for m in matches[:2]:
                entry = t("ev_class", item=m)
                if entry not in found:
                    found.append(entry)

        # 2. Buscar en strings
        for sig in STRING_SIGS:
            sig_lower = sig.lower()
            for s in all_strings:
                if sig_lower in s.lower() and len(s) < 300:
                    entry = t("ev_string", item=s)
                    if entry not in found:
                        found.append(entry)
                    break

        # 3. Buscar en assets del APK
        try:
            for asset in apk.get_files():
                asset_lower = asset.lower()
                for sig in ASSET_SIGS:
                    if sig.lower() in asset_lower:
                        entry = t("ev_asset", item=asset)
                        if entry not in found:
                            found.append(entry)
                        break
        except Exception:  # noqa: BLE001
            pass

        # 4. Buscar en meta-data del manifest
        try:
            manifest_xml = apk.get_android_manifest_xml()
            if manifest_xml is not None:
                manifest_str = manifest_xml if isinstance(manifest_xml, str) else ""
                if "appdome" in manifest_str.lower():
                    found.append(t("ev_manifest_appdome"))
        except Exception:  # noqa: BLE001
            pass

        return DetectionResult(
            name=self.name,
            detected=bool(found),
            strength=self.strength,
            details=found,
        )
