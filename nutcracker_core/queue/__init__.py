"""Cola de ejecución masiva de nutcracker (Fase 1 del plan).

    from nutcracker_core.queue.engine import QueueEngine

Pool paralelo para jobs estáticos + lock por dispositivo para jobs dinámicos
(dos análisis dinámicos nunca corren a la vez sobre el mismo serial ADB). Cada
job corre en un subproceso aislado del CLI existente (`nutcracker analyze`/
`scan`), así que reutiliza el pipeline de análisis tal cual sin duplicarlo.
"""
