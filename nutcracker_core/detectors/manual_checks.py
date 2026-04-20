"""
Detector de comprobaciones manuales de root en el código.

Busca rutas de binarios root, llamadas a Runtime.exec("su"),
comprobaciones de propiedades del sistema, y otros indicadores
de detección manual implementados en el código de la app.

NOTA: Muchos SDKs de analytics/ads (AppMetrica, AppsFlyer, Adjust, etc.)
incluyen su propia detección de root para anti-fraude. Para evitar falsos
positivos, este detector requiere evidencia de código anti-root en el namespace
de la app (no solo strings sueltas de SDKs de terceros).
"""

from .base import BaseDetector, DetectionResult

# Rutas de binarios comúnmente asociados con root
ROOT_BINARY_PATHS: list[str] = [
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/su/bin/su",
    "/data/local/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/system/xbin/daemonsu",
]

# Propiedades del sistema que indican root / build inseguro
ROOT_BUILD_PROPS: list[str] = [
    "ro.build.tags=test-keys",
    "test-keys",
    "ro.secure=0",
    "ro.debuggable=1",
    "ro.build.type=userdebug",
    "ro.build.type=eng",
]

# Comandos ejecutados en Runtime.exec que indican detección de root
ROOT_EXEC_COMMANDS: list[str] = [
    "which su",
    # NOTA: se eliminó "id\n" (matcheaba "Android\n") y "mount" (matcheaba
    # "Amount", "dismount", etc.).
    "ls /system/xbin",
    "ls /sbin",
    "cat /proc/mounts",
]

# Indicadores más genéricos (buscar en clases/métodos)
GENERIC_ROOT_INDICATORS: list[str] = [
    "isRooted",
    "isDeviceRooted",
    "checkRoot",
    "detectRoot",
    "hasRootAccess",
    "rootDetect",
    "findBinary",
    "checkRootMethod",
    "RootDetection",
    "RootCheck",
    "daemonsu",
]

# Namespaces de SDKs conocidos que incluyen su propia detección de root
# para anti-fraude. Matches en estas clases NO cuentan como protección de la app.
_SDK_ROOT_CHECK_NAMESPACES: list[str] = [
    "io/appmetrica/",
    "com/yandex/metrica/",
    "com/appsflyer/",
    "com/adjust/sdk/",
    "com/amplitude/",
    "com/mixpanel/",
    "io/branch/",
    "com/singular/",
    "com/kochava/",
    "com/tenjin/",
    "com/google/android/gms/ads/",
    "com/facebook/ads/",
    "com/unity3d/ads/",
    "com/ironsource/",
    "com/applovin/",
    "com/chartboost/",
    "com/mopub/",
    "com/my/tracker/",
    "com/flurry/",
    "com/braze/",
    "com/clevertap/",
    "com/onesignal/",
    "com/segment/",
    "com/newrelic/",
    "com/bugsnag/",
    "com/crashlytics/",
    "io/sentry/",
    "com/datadog/",
    "com/instabug/",
]


def _is_sdk_class(cls_name: str) -> bool:
    """Devuelve True si la clase pertenece a un SDK conocido."""
    cls_lower = cls_name.lower()
    return any(ns.lower() in cls_lower for ns in _SDK_ROOT_CHECK_NAMESPACES)


class ManualChecksDetector(BaseDetector):
    """Detecta comprobaciones manuales de root implementadas en el código."""

    name = "Comprobaciones manuales de root"
    strength = "medium"

    def detect(self, apk, dx, all_strings: set, all_classes: set) -> DetectionResult:
        found: list[str] = []
        has_app_level_evidence = False

        # Buscar rutas de binarios root en strings del DEX
        for path in ROOT_BINARY_PATHS:
            for s in all_strings:
                if path.lower() in s.lower():
                    found.append(f"[Ruta root] {s!r}")
                    break

        # Buscar propiedades de build inseguras
        for prop in ROOT_BUILD_PROPS:
            for s in all_strings:
                if prop.lower() in s.lower():
                    found.append(f"[Build prop] {s!r}")
                    break

        # Buscar comandos ejecutados vía Runtime
        for cmd in ROOT_EXEC_COMMANDS:
            for s in all_strings:
                if cmd.lower() in s.lower():
                    found.append(f"[Runtime.exec] {s!r}")
                    break

        # Buscar indicadores genéricos en nombres de clases y métodos.
        # Solo se cuenta como evidencia de "app-level" si la clase NO
        # pertenece a un SDK de analytics/ads conocido.
        for indicator in GENERIC_ROOT_INDICATORS:
            for cls in all_classes:
                if indicator.lower() in cls.lower():
                    if _is_sdk_class(cls):
                        found.append(f"[SDK] {cls!r}")
                    else:
                        found.append(f"[Clase/método] {cls!r}")
                        has_app_level_evidence = True
                    break

        # Analizar métodos que llaman Runtime.exec con args sospechosos
        try:
            runtime_exec = dx.get_method_analysis_by_name(
                "Ljava/lang/Runtime;", "exec", None
            )
            if runtime_exec:
                xrefs = list(runtime_exec.get_xref_from())
                if xrefs:
                    found.append(
                        f"[Runtime.exec] Encontradas {len(xrefs)} llamadas a Runtime.exec()"
                    )
        except Exception:  # noqa: BLE001
            pass

        # Deduplicar
        seen: set[str] = set()
        unique_found: list[str] = []
        for item in found:
            if item not in seen:
                seen.add(item)
                unique_found.append(item)

        # Detección: requiere evidencia de código anti-root a nivel de la app.
        # Strings sueltas de rutas/props/commands pueden venir de SDKs de
        # analytics (AppMetrica, etc.) y no indican protección intencional.
        # Se requiere al menos una clase con nombre de root-check que NO sea
        # de un SDK conocido.
        return DetectionResult(
            name=self.name,
            detected=has_app_level_evidence,
            strength=self.strength,
            details=unique_found,
        )
