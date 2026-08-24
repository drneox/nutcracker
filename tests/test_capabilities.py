"""Tests de nutcracker_core/capabilities.py — el registro de capacidades
plugin→plugin (contrato: el consumidor resuelve por nombre y degrada a None
si el proveedor no está, sin importarlo directamente)."""

from __future__ import annotations

import pytest

from nutcracker_core import capabilities


@pytest.fixture(autouse=True)
def _clean_registry():
    yield
    capabilities.unregister("test.cap")
    capabilities.unregister("test.lazy")
    capabilities.unregister("test.broken")


def test_get_unregistered_returns_none():
    assert capabilities.get("test.cap") is None
    assert not capabilities.available("test.cap")


def test_register_and_get_roundtrip():
    sentinel = object()
    capabilities.register("test.cap", sentinel)
    assert capabilities.get("test.cap") is sentinel
    assert capabilities.available("test.cap")


def test_register_replaces_previous_provider():
    capabilities.register("test.cap", "viejo")
    capabilities.register("test.cap", "nuevo")
    assert capabilities.get("test.cap") == "nuevo"


def test_lazy_factory_runs_once_and_caches():
    calls = []

    def factory():
        calls.append(1)
        return {"provider": len(calls)}

    capabilities.register_lazy("test.lazy", factory)
    assert calls == []  # no se materializó al registrar

    first = capabilities.get("test.lazy")
    second = capabilities.get("test.lazy")
    assert first == {"provider": 1}
    assert first is second
    assert calls == [1]  # una sola ejecución


def test_lazy_importerror_marks_unavailable_without_retry():
    calls = []

    def factory():
        calls.append(1)
        raise ImportError("plugin viejo sin este módulo")

    capabilities.register_lazy("test.broken", factory)
    assert capabilities.get("test.broken") is None
    assert capabilities.get("test.broken") is None
    assert not capabilities.available("test.broken")
    assert calls == [1]  # no reintenta


def test_register_replaces_failed_lazy():
    def factory():
        raise ImportError("roto")

    capabilities.register_lazy("test.broken", factory)
    assert capabilities.get("test.broken") is None

    capabilities.register("test.broken", "recuperado")
    assert capabilities.get("test.broken") == "recuperado"


def test_unregister_clears_everything():
    capabilities.register("test.cap", "x")
    capabilities.register_lazy("test.lazy", lambda: "y")
    capabilities.get("test.lazy")  # materializa
    capabilities.unregister("test.cap")
    capabilities.unregister("test.lazy")
    assert capabilities.get("test.cap") is None
    assert capabilities.get("test.lazy") is None
