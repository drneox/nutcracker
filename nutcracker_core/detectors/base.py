"""Clases base para los detectores de protecciones anti-root."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class DetectionResult:
    """Resultado de un detector individual."""

    name: str
    detected: bool
    strength: str  # "low", "medium", "high"
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "detected": self.detected,
            "strength": self.strength,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionResult":
        return cls(
            name=data["name"],
            detected=data["detected"],
            strength=data.get("strength", "medium"),
            details=data.get("details", []),
        )


class BaseDetector:
    """Clase base para todos los detectores."""

    name: str = "BaseDetector"
    strength: str = "medium"

    def detect(
        self,
        apk,
        dx,
        all_strings: set,
        all_classes: set,
    ) -> DetectionResult:
        raise NotImplementedError
