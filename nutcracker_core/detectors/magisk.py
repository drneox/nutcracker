"""
Detector de protecciones basadas en Magisk, SuperSU, Frida y certificados de root.

Detecta referencias explícitas a Magisk, SuperSU, KSU (KernelSU),
y herramientas de bypass de root como Frida.
"""

from .base import BaseDetector, DetectionResult
from nutcracker_core.i18n import t

# Package IDs y strings asociados con frameworks de root.
# NOTA: solo patrones específicos (full package/path). Se eliminaron strings
# genéricos cortos ("magisk", "supersu", "KernelSU") que producían FP con
# strings como "getSuperSubscriberInfo" o nombres de suscripción.
ROOT_FRAMEWORK_PACKAGES: list[str] = [
    # Magisk
    "com.topjohnwu.magisk",
    "io.github.vvb2060.magisk",
    "MagiskHide",
    "MagiskSU",
    "/data/adb/magisk",
    "/sbin/.magisk/",
    "/sbin/.core/db-0/magisk.db",

    # SuperSU
    "eu.chainfire.supersu",
    "eu.chainfire.libsuperuser",

    # KernelSU
    "me.weishu.kernelsu",
    "com.rifsxd.ksunext",

    # APatch (otro framework de root)
    "me.bmax.apatch",

    # SuperUser (AOSP clásico) — solo packages completos
    "com.noshufou.android.su",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
]

# Indicadores de la herramienta de análisis dinámico Frida (bypass de root)
# NOTA: se eliminó "frida" genérico (matcheaba "blackfriday" en regex de URLs).
# "/linjector" en vez de "linjector" para evitar FP con clases de inyección de
# dependencias (Dagger/Hilt) del tipo ActivityInjectorModule_DiscountDetailInjector.
FRIDA_INDICATORS: list[str] = [
    "frida-server",
    "frida-agent",
    "frida-gadget",
    "gum-js-loop",
    "/linjector",
    "/data/local/tmp/frida",
    "re.frida.server",
]

# Permisos que solo tienen sentido con root
ROOT_PERMISSIONS: list[str] = [
    "android.permission.ACCESS_SUPERUSER",
    "android.permission.ROOT",
]


class MagiskDetector(BaseDetector):
    """Detecta protecciones contra Magisk, SuperSU, KernelSU y herramientas similares."""

    name = "Anti Magisk / SuperSU / KernelSU / Frida"
    strength = "high"

    def detect(self, apk, dx, all_strings: set, all_classes: set) -> DetectionResult:
        found: list[str] = []

        # Para root frameworks: buscar SOLO en clases.
        # Muchos SDKs de analytics (AppMetrica, AppsFlyer, etc.) incluyen estos
        # package names como string constants para su propio root check de
        # anti-fraude —  NO indica protección de la app.
        for indicator in ROOT_FRAMEWORK_PACKAGES:
            ind_lower = indicator.lower()
            # Normalizar a ambos formatos (dots y slashes)
            ind_slash = ind_lower.replace(".", "/")
            ind_dot = ind_lower.replace("/", ".")
            matches = [
                item for item in all_classes
                if (ind_lower in item.lower()
                    or ind_slash in item.lower()
                    or ind_dot in item.lower())
                and len(item) < 300
            ]
            for match in matches[:3]:
                entry = t("ev_root_framework", item=match)
                if entry not in found:
                    found.append(entry)

        # Para Frida: buscar en clases + strings (indicadores más específicos)
        combined = all_classes | all_strings
        for indicator in FRIDA_INDICATORS:
            for item in combined:
                if indicator.lower() in item.lower() and len(item) < 300:
                    entry = t("ev_frida_bypass", item=item)
                    if entry not in found:
                        found.append(entry)
                    break

        # Verificar apps instaladas buscando package managers en el código
        # (patrón típico: getInstalledPackages -> buscar Magisk)
        try:
            pkg_manager_calls = dx.get_method_analysis_by_name(
                "Landroid/content/pm/PackageManager;",
                "getInstalledPackages",
                None,
            )
            if pkg_manager_calls:
                xrefs = list(pkg_manager_calls.get_xref_from())
                if xrefs:
                    found.append(t("ev_package_manager", count=len(xrefs)))
        except Exception:  # noqa: BLE001
            pass

        # Verificar permisos root declarados
        try:
            permissions = apk.get_declared_permissions()
            for perm in permissions:
                if any(rp.lower() in perm.lower() for rp in ROOT_PERMISSIONS):
                    found.append(f"[Permiso] {perm}")
        except Exception:  # noqa: BLE001
            pass

        # También verificar permisos requeridos
        try:
            permissions = apk.get_permissions()
            for perm in permissions:
                if any(rp.lower() in perm.lower() for rp in ROOT_PERMISSIONS):
                    found.append(f"[Permiso requerido] {perm}")
        except Exception:  # noqa: BLE001
            pass

        return DetectionResult(
            name=self.name,
            detected=bool(found),
            strength=self.strength,
            details=found,
        )
