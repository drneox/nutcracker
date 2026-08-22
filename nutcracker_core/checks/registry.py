"""Registry de checks: descubre y unifica checks estáticos (adaptador) y
dinámicos (nuevos). Patrón de auto-descubrimiento análogo al plugin loader
(nutcracker_core/plugins/__init__.py), pero para checks de análisis en vez de
comandos CLI."""

from __future__ import annotations

from .base import Check

_STATIC: list[Check] = []
_DYNAMIC: list[Check] = []


def register_static(check: Check) -> Check:
    _STATIC.append(check)
    return check


def register_dynamic(check: Check) -> Check:
    _DYNAMIC.append(check)
    return check


def all_checks() -> list[Check]:
    return [*_STATIC, *_DYNAMIC]


def static_checks() -> list[Check]:
    return list(_STATIC)


def dynamic_checks() -> list[Check]:
    return list(_DYNAMIC)


def reset() -> None:
    """Solo para tests: vacía el registry para poder repoblar desde cero."""
    _STATIC.clear()
    _DYNAMIC.clear()
