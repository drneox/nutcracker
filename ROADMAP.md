# Roadmap — nutcracker

`[ ]` pendiente · `[~]` en progreso · `[x]` completado

## OSINT
- [ ] **GitHub Search con token** — el scraping HTML actual falla sin login. Leer `GITHUB_TOKEN` del entorno y usar la REST API de code search; caer al scraping como fallback.
- [ ] **Secretos de BuildConfig en el PDF** — se extraen internamente pero no se muestran en el reporte. Agregar subsección en `_osint_section`.

## Plataformas
- [ ] **Soporte iOS / IPA** — descarga con `ipatool`, análisis estático de Mach-O con `jtool2`/`class-dump`, secretos en `.plist`/`.strings`, análisis de `Info.plist` (permisos, ATS), detección de jailbreak checks. MVP solo estático; dinámico requiere jailbreak.

## Arquitectura
- [ ] **Separar `vuln_scanner.py`** — 1400+ líneas con tres responsabilidades. Partir en `scan_types.py` (dataclasses), `vuln_scanner.py` (regex + semgrep) y `leak_scanner.py` (apkleaks, gitleaks). Hacerlo antes de agregar nuevas fuentes de leaks o portar a Go.
- [ ] **Portar scanner de secretos a Go** — `string_extractor.py` y las reglas HC* son los pasos más lentos. Binario Go `nutcracker-strings` que recibe un directorio y patrones, devuelve JSON. Python lo invoca como subprocess igual que semgrep. Prerequisito: separar módulos primero.
