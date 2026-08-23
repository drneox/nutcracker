"""capabilities.py — registro ligero de capacidades entre plugins.

Los plugins de nutcracker son módulos independientes entre sí (aipwn incluso
vive en un repo git separado, clonado dentro de plugins/). Para que un plugin
pueda ofrecer funcionalidad a otro SIN que el consumidor lo importe
directamente (acoplamiento plugin→plugin), el proveedor registra sus
capacidades acá por nombre y el consumidor las resuelve en tiempo de uso:

    # proveedor (en su register(), ver plugins/aipwn/__init__.py):
    capabilities.register("aipwn.has_resume_state", agent_memory.has_resume_state)

    # consumidor (en tiempo de uso, nunca en tiempo de import):
    fn = capabilities.get("aipwn.has_resume_state")
    if fn is not None and fn(package):
        ...

Si el proveedor no está instalado, ``get()`` devuelve ``None`` y el
consumidor degrada la feature en vez de crashear -- mismo contrato que antes
se lograba con imports tolerantes try/except, pero sin que el consumidor
conozca rutas internas del otro plugin.

``register_lazy()`` difiere imports pesados (p.ej. ``aipwn.query`` importa
any_llm vía query_agent) hasta el primer uso real, para no pagar ese costo
en cada invocación del CLI (load_plugins importa cada plugin siempre).
"""

from __future__ import annotations

from typing import Any, Callable

_PROVIDERS: dict[str, Any] = {}
_LAZY_FACTORIES: dict[str, Callable[[], Any]] = {}
_LAZY_FAILED: set[str] = set()


def register(name: str, provider: Any) -> None:
    """Registra ``provider`` (cualquier objeto) bajo ``name``. Reemplaza lo
    que hubiera antes, incluida una factory perezosa."""
    _PROVIDERS[name] = provider
    _LAZY_FACTORIES.pop(name, None)
    _LAZY_FAILED.discard(name)


def register_lazy(name: str, factory: Callable[[], Any]) -> None:
    """Registra una capacidad cuyo provider se materializa recién en el
    primer ``get()`` que la pida. Si la factory lanza ``ImportError`` (plugin
    proveedor presente pero incompleto/viejo), la capacidad queda marcada
    como no disponible: ``get()`` devuelve ``None`` sin reintentar."""
    _LAZY_FACTORIES[name] = factory
    _PROVIDERS.pop(name, None)
    _LAZY_FAILED.discard(name)


def get(name: str) -> Any | None:
    """El provider registrado bajo ``name``, o ``None`` si nadie lo registró
    (o su factory perezosa falló). El resultado de una factory exitosa se
    cachea: la factory corre una sola vez."""
    if name in _PROVIDERS:
        return _PROVIDERS[name]
    if name in _LAZY_FAILED:
        return None
    factory = _LAZY_FACTORIES.get(name)
    if factory is None:
        return None
    try:
        provider = factory()
    except ImportError:
        _LAZY_FAILED.add(name)
        return None
    _PROVIDERS[name] = provider
    return provider


def available(name: str) -> bool:
    return get(name) is not None


def unregister(name: str) -> None:
    """Quita una capacidad del registro. Pensado para tests (aislar el
    estado global entre casos)."""
    _PROVIDERS.pop(name, None)
    _LAZY_FACTORIES.pop(name, None)
    _LAZY_FAILED.discard(name)
