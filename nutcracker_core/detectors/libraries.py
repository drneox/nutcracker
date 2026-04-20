"""
Detector de librerías anti-root conocidas embebidas en la APK.

Detecta: RootBeer, RootCloak, Xposed, DexGuard, Promon Shield, Appdome, etc.
"""

from .base import BaseDetector, DetectionResult

# Mapa: nombre_legible -> [prefijos de paquete/clase a buscar]
KNOWN_LIBRARIES: dict[str, list[str]] = {
    "RootBeer": [
        "com/scottyab/rootbeer",
        "com.scottyab.rootbeer",
    ],
    "RootCloak": [
        "com/devadvance/rootcloak",
        "com.devadvance.rootcloak",
    ],
    "Xposed Framework": [
        "de/robv/android/xposed",
        "de.robv.android.xposed",
        "XposedBridge",
        "XposedHelpers",
    ],
    "DexGuard": [
        "com/guardsquare/dexguard",
        "com.guardsquare.dexguard",
        "dexguard",
    ],
    "Promon Shield": [
        "com/promon/shield",
        "com.promon.shield",
        "no/promon",
    ],
    "Appdome": [
        "com/appdome",
        "com.appdome",
    ],
    "Free RASP (ThreatCast)": [
        "com/aheaditec/talsec",
        "com.aheaditec.talsec",
    ],
    "AppShielding (Irdeto)": [
        "com/irdeto",
        "com.irdeto",
    ],
    "Arxan / Digital.ai": [
        "com/arxan",
        "com.arxan",
        "com/digitalai",
    ],
    "Verimatrix": [
        "com/verimatrix",
        "com.verimatrix",
    ],
}


class KnownLibrariesDetector(BaseDetector):
    """Detecta librerías anti-root conocidas en el bytecode de la APK."""

    name = "Librerías anti-root conocidas"
    strength = "high"

    def detect(self, apk, dx, all_strings: set, all_classes: set) -> DetectionResult:
        found: list[str] = []

        for lib_name, patterns in KNOWN_LIBRARIES.items():
            for pattern in patterns:
                # Patrones con "/" son rutas de clase → buscar solo en clases
                # Patrones con "." son package names → buscar solo en clases
                # (SDKs de ads referencian estos packages como strings para
                #  anti-fraude; eso NO significa que la librería esté embebida)
                search_set = all_classes
                for item in search_set:
                    if pattern.lower() in item.lower():
                        found.append(f"[{lib_name}] Encontrado: {item!r}")
                        break  # Un match por librería es suficiente
                else:
                    continue
                break  # Si encontramos la librería, pasamos a la siguiente

        return DetectionResult(
            name=self.name,
            detected=bool(found),
            strength=self.strength,
            details=found,
        )
