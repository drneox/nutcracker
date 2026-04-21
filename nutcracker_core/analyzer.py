"""Orquestador principal del análisis de APKs."""

from __future__ import annotations

import contextlib
import datetime
import json
import logging
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

# Silenciar los logs de debug de androguard completamente
_andro_log = logging.getLogger("androguard")
_andro_log.setLevel(logging.ERROR)
_andro_log.propagate = False   # no subir al root logger

# Androguard usa loguru, no logging estándar — silenciar también loguru
from loguru import logger as _loguru_logger
_loguru_logger.disable("androguard")

from androguard.misc import AnalyzeAPK


class _AndroguardStream:
    """Captura writes a stderr/stdout y los redirige al callback de progreso."""

    def __init__(self, callback, original):
        self._cb = callback
        self._orig = original
        self._buf = ""

    def write(self, text: str) -> int:
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.strip()
            if line and self._cb:
                # Recortar líneas muy largas para que quepan en el spinner
                display = line if len(line) <= 88 else line[:85] + "..."
                self._cb(display)
        return len(text)

    def flush(self) -> None:
        pass

    def fileno(self) -> int:
        """Necesario para algunas bibliotecas que comprueban si es un fd real."""
        return self._orig.fileno()

    def isatty(self) -> bool:
        return False


@contextlib.contextmanager
def _capture_androguard(callback):
    """
    Context manager que:
    1. Silencia los loggers de androguard (propagate=False + nivel ERROR)
    2. Redirige sys.stderr para capturar cualquier print/write directo
    Las líneas capturadas se pasan a `callback(línea)` una a una.
    """
    old_stderr = sys.stderr
    sys.stderr = _AndroguardStream(callback, old_stderr)
    try:
        yield
    finally:
        sys.stderr = old_stderr

from .detectors.base import DetectionResult
from .detectors.appdome import AppdomeDetector
from .detectors.dexguard import DexGuardDetector
from .detectors.libraries import KnownLibrariesDetector
from .detectors.magisk import MagiskDetector
from .detectors.manual_checks import ManualChecksDetector
from .detectors.safetynet import SafetyNetDetector


# Lista de todos los detectores disponibles
ALL_DETECTORS = [
    KnownLibrariesDetector(),
    SafetyNetDetector(),
    ManualChecksDetector(),
    MagiskDetector(),
    DexGuardDetector(),
    AppdomeDetector(),
]


def _resolve_apk_path(apk_path: Path) -> tuple[Path, Path | None]:
    """
    Si el archivo es un XAPK, extrae el APK base a un directorio temporal.

    Returns:
        (ruta_al_apk_real, directorio_temporal_o_None)
    """
    if apk_path.suffix.lower() != ".xapk":
        return apk_path, None

    tmp_dir = Path(tempfile.mkdtemp(prefix="nutcracker_core_"))
    with zipfile.ZipFile(apk_path, "r") as zf:
        # El APK base suele llamarse <package>.apk o base.apk
        apk_entries = [
            name for name in zf.namelist()
            if name.endswith(".apk") and "/" not in name
        ]
        if not apk_entries:
            # Buscar en subdirectorios
            apk_entries = [name for name in zf.namelist() if name.endswith(".apk")]

        if not apk_entries:
            raise FileNotFoundError(
                f"No se encontró ningún .apk dentro del XAPK: {apk_path}"
            )

        # Preferir base.apk o el que tenga el nombre más corto (suele ser el principal)
        best = next((e for e in apk_entries if "base" in e.lower()), apk_entries[0])
        extracted = tmp_dir / Path(best).name
        with zf.open(best) as src, extracted.open("wb") as dst:
            dst.write(src.read())

    return extracted, tmp_dir


class AnalysisResult:
    """Resultado completo del análisis de una APK."""

    def __init__(
        self,
        package: str,
        version_name: str,
        version_code: str,
        min_sdk: str,
        target_sdk: str,
        analyzed_at: str,
        results: list[DetectionResult],
        elapsed_seconds: float | None = None,
    ) -> None:
        self.package = package
        self.version_name = version_name
        self.version_code = version_code
        self.min_sdk = min_sdk
        self.target_sdk = target_sdk
        self.analyzed_at = analyzed_at
        self.results = results
        self.elapsed_seconds = elapsed_seconds
        # Campo opcional: rellena nutcracker.py si se hizo decompilación con frida
        # Formato: {"method": "frida-dexdump" | "FART" | None, "dex_count": int, "source_dir": str}
        self.decompilation_info: "dict | None" = None

    @property
    def protected(self) -> bool:
        """Retorna True si se detectó al menos una protección anti-root."""
        return any(r.detected for r in self.results)

    @property
    def protection_broken(self) -> bool:
        """True cuando se detectó protección pero el bypass runtime la rompió."""
        if not self.protected:
            return False
        dec = self.decompilation_info or {}
        method = str(dec.get("method", "")).lower()
        dex_count = int(dec.get("dex_count", 0) or 0)
        runtime_methods = ("frida", "gadget", "fart", "dexdump")
        return any(m in method for m in runtime_methods) and dex_count > 0

    @property
    def confidence(self) -> str:
        """Nivel de confianza basado en cuántos detectores encontraron algo."""
        detected_count = sum(1 for r in self.results if r.detected)
        if detected_count == 0:
            return "none"
        if detected_count == 1:
            return "low"
        if detected_count == 2:
            return "medium"
        return "high"

    @property
    def high_strength_count(self) -> int:
        return sum(
            1 for r in self.results if r.detected and r.strength == "high"
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "analyzed_at": self.analyzed_at,
            "elapsed_seconds": self.elapsed_seconds,
            "anti_root_protected": self.protected,
            "protection_broken": self.protection_broken,
            "confidence": self.confidence,
            "high_strength_detections": self.high_strength_count,
            "detections": [r.to_dict() for r in self.results],
        }
        if self.decompilation_info:
            data["decompilation_info"] = self.decompilation_info
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisResult":
        results = [
            DetectionResult.from_dict(d) for d in data.get("detections", [])
        ]
        obj = cls(
            package=data["package"],
            version_name=data.get("version_name", "?"),
            version_code=str(data.get("version_code", "?")),
            min_sdk=str(data.get("min_sdk", "?")),
            target_sdk=str(data.get("target_sdk", "?")),
            analyzed_at=data.get("analyzed_at", ""),
            results=results,
            elapsed_seconds=data.get("elapsed_seconds"),
        )
        obj.decompilation_info = data.get("decompilation_info")
        return obj


class APKAnalyzer:
    """Analiza una APK en busca de protecciones anti-root."""

    def __init__(self, progress_callback=None, engine: str = "native") -> None:
        """
        Args:
            progress_callback: Función opcional llamada con (mensaje: str)
                               para reportar progreso.
            engine: Motor de detección anti-root ("native" | "apkid").
        """
        self._progress = progress_callback or (lambda msg: None)
        self._detectors = ALL_DETECTORS
        self._engine = (engine or "native").strip().lower()
        if self._engine == "builtin":
            self._engine = "native"

    def _log(self, msg: str) -> None:
        self._progress(msg)

    def _extract_metadata(self, apk) -> dict[str, str]:
        """Extrae metadatos básicos de la APK."""
        try:
            package = apk.get_package() or "desconocido"
        except Exception:
            package = "desconocido"

        try:
            version_name = apk.get_androidversion_name() or "?"
        except Exception:
            version_name = "?"

        try:
            version_code = str(apk.get_androidversion_code() or "?")
        except Exception:
            version_code = "?"

        try:
            min_sdk = str(apk.get_min_sdk_version() or "?")
        except Exception:
            min_sdk = "?"

        try:
            target_sdk = str(apk.get_target_sdk_version() or "?")
        except Exception:
            target_sdk = "?"

        return {
            "package": package,
            "version_name": version_name,
            "version_code": version_code,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
        }

    def _build_string_set(self, dx) -> set[str]:
        """Construye el conjunto de todas las strings encontradas en el DEX."""
        strings: set[str] = set()
        try:
            for s in dx.get_strings():
                val = s.get_value()
                if val:
                    strings.add(val)
        except Exception:  # noqa: BLE001
            pass
        return strings

    def _build_class_set(self, dx) -> set[str]:
        """Construye el conjunto de nombres de clases del DEX."""
        classes: set[str] = set()
        try:
            for cls in dx.get_classes():
                name = cls.get_vm_class().get_name()
                if name:
                    classes.add(name)
        except Exception:  # noqa: BLE001
            pass
        return classes

    def _run_builtin_detectors(self, apk, dx) -> list[DetectionResult]:
        self._log("Indexando strings del bytecode...")
        all_strings = self._build_string_set(dx)

        self._log("Indexando clases del bytecode...")
        all_classes = self._build_class_set(dx)

        self._log(
            f"Índice listo: {len(all_strings):,} strings, {len(all_classes):,} clases"
        )

        detection_results: list[DetectionResult] = []
        for detector in self._detectors:
            self._log(f"Ejecutando detector: {detector.name}...")
            result = detector.detect(apk, dx, all_strings, all_classes)
            detection_results.append(result)
        return detection_results

    def _run_apkid_detector(self, real_apk: Path) -> list[DetectionResult]:
        """Ejecuta APKiD y traduce su salida a DetectionResult."""
        self._log("Ejecutando APKiD...")

        try:
            proc = subprocess.run(
                ["apkid", "-j", str(real_apk)],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except FileNotFoundError:
            self._log("APKiD no encontrado en PATH; usando detectores native")
            return []
        except subprocess.TimeoutExpired:
            self._log("APKiD excedió el tiempo límite; usando detectores native")
            return []

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[:180]
            self._log(f"APKiD falló (rc={proc.returncode}): {detail}")
            return []

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            self._log("APKiD devolvió salida inválida; usando detectores native")
            return []

        files = data.get("files", [])
        if not isinstance(files, list):
            return []

        by_category: dict[str, list[str]] = {}
        for item in files:
            if not isinstance(item, dict):
                continue
            filename = str(item.get("filename", "?"))
            short_name = filename.split("!")[-1]
            matches = item.get("matches", {})
            if not isinstance(matches, dict):
                continue

            for category, values in matches.items():
                if not values:
                    continue
                by_category.setdefault(str(category), [])
                sample_values = values[:3] if isinstance(values, list) else [values]
                sample = ", ".join(str(v) for v in sample_values)
                by_category[str(category)].append(f"{short_name}: {sample}")

        if not by_category:
            return []

        strength_map = {
            "anti_debug": "high",
            "anti_vm": "high",
            "anti_disassembly": "medium",
            "packer": "high",
            "obfuscator": "medium",
            "dropper": "high",
            "compiler": "low",
        }

        results: list[DetectionResult] = []
        for category, details in sorted(by_category.items()):
            sev = strength_map.get(category, "medium")
            top_details = details[:10]
            results.append(
                DetectionResult(
                    name=f"APKiD:{category}",
                    detected=True,
                    strength=sev,
                    details=top_details,
                )
            )

        dexguard_hits: list[str] = []
        for details in by_category.values():
            for d in details:
                if "dexguard" in d.lower():
                    dexguard_hits.append(d)
        if dexguard_hits:
            results.append(
                DetectionResult(
                    name="DexGuardDetector",
                    detected=True,
                    strength="high",
                    details=dexguard_hits[:10],
                )
            )

        return results

    def analyze(self, apk_path: str | Path) -> AnalysisResult:
        """
        Analiza la APK en la ruta indicada.

        Args:
            apk_path: Ruta al archivo .apk o .xapk.

        Returns:
            AnalysisResult con todos los resultados.
        """
        apk_path = Path(apk_path)
        if not apk_path.exists():
            raise FileNotFoundError(f"APK no encontrada: {apk_path}")

        # Extraer APK base si es un XAPK
        real_apk, tmp_dir = _resolve_apk_path(apk_path)
        if real_apk != apk_path:
            self._log(f"XAPK detectado — analizando APK interna: {real_apk.name}")

        try:
            self._log(f"Cargando APK: {real_apk.name}")
            with _capture_androguard(self._progress):
                apk, _, dx = AnalyzeAPK(str(real_apk))

            self._log("Extrayendo metadatos...")
            metadata = self._extract_metadata(apk)

            detection_results: list[DetectionResult]
            if self._engine == "apkid":
                detection_results = self._run_apkid_detector(real_apk)
                if not detection_results:
                    detection_results = self._run_builtin_detectors(apk, dx)
            else:
                detection_results = self._run_builtin_detectors(apk, dx)

        finally:
            if tmp_dir and tmp_dir.exists():
                import shutil
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return AnalysisResult(
            analyzed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            results=detection_results,
            **metadata,
        )
