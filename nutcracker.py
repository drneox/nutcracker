#!/usr/bin/env python3
"""
nutcracker - CLI principal.

Uso:
    python nutcracker.py scan <url_o_package_id>           # descarga desde APKPure + analiza
    python nutcracker.py scan <url> --source google-play   # descarga desde Google Play + analiza
    python nutcracker.py analyze <ruta_apk>                # analiza una APK local

El grupo de comandos y su orquestación viven en nutcracker_core/cli/ y
nutcracker_core/orchestrator.py (Fase 0.2 del plan) — este archivo es solo el
punto de entrada.
"""

from nutcracker_core.cli import cli

if __name__ == "__main__":
    cli()
