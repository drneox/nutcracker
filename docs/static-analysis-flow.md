# Flujo de análisis estático de nutcracker

> Documento generado a partir del análisis del código en `nutcracker_core/`.
> Última revisión: 2026-07-27.

## Resumen

El flujo está centralizado en `orchestrator.py::_run_analysis()` (línea 446),
que orquesta toda la cadena desde la APK hasta el reporte final. Esto es lo que
pasa, paso a paso, cuando se corre `nutcracker analyze <apk>` o
`nutcracker scan <url>`.

## Diagrama general

```
┌─────────────────────────────────────────────────────────────────────┐
│  nutcracker analyze <apk> / scan <url>                              │
│  (CLI en cli/analyze.py o cli/scan.py → orchestrator._run_analysis) │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  1. APKAnalyzer.analyze(apk_path)              [analyzer.py]        │
│     ── Androguard: AnalyzeAPK() → apk, dex, dx                     │
│     ── Extrae metadata: package, version, min/target SDK            │
│     ── Detectores anti-root (ALL_DETECTORS, 8 en total):            │
│        KnownLibraries, SafetyNet, ManualChecks, Magisk,             │
│        DexGuard, Appdome, SignatureCheck, CertificatePinning        │
│        (engine "native" usa los builtin; "apkid" usa APKiD)         │
│     → AnalysisResult (protected?, confidence, detections[])         │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  2. _post_analysis_flow(result, apk_path)      [orchestrator.py:615]│
│     Decide el método de decompilación según protección detectada:   │
│                                                                     │
│     ├─ ¿DexGuard? → _do_dexguard_deobf():                           │
│     │     frida-dexdump (memoria) → FART fallback → jadx fallback   │
│     │     → _decompile_and_scan()                                   │
│     │                                                               │
│     └─ Sin DexGuard → _do_decompile():                              │
│           jadx directo sobre el APK                                 │
│           → _do_manifest_scan + _do_vuln_scan + _do_osint_scan      │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  3. Decompilación                               [decompiler.py]     │
│     get_available_tool() → jadx (preferido) o apktool (fallback)    │
│     decompile(apk, ./decompiled/)                                   │
│     → ./decompiled/<package>/sources/*.java                         │
│     → ./decompiled/<package>/resources/AndroidManifest.xml          │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  4. Manifest scan                   [manifest_analyzer.py]          │
│     _do_manifest_scan() → analyze_decompiled_dir()                 │
│     Busca misconfigs: debuggable, allowBackup, cleartext traffic,   │
│     exported components, targetSdk bajo, network security config    │
│     → Misconfiguration[] (no se persisten en findings, gap Fase 2)  │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  5. Vuln + Leak scan                [vuln_scanner.py, leak_scanner] │
│     _do_vuln_scan() → auto_scan(source_dir, engine, leak_engine)    │
│                                                                     │
│     auto_scan() elige motor:                                        │
│     ├─ engine="semgrep" → scan_with_semgrep (p/android p/owasp)     │
│     └─ engine="regex"   → scan_directory() con RULES (~54 reglas)   │
│                                                                     │
│     scan_directory() aplica las VulnRule regex sobre .java/.kt/.xml │
│     (filtra SDK/terceros: Android, Firebase, MSAL, okhttp, etc.)    │
│                                                                     │
│     Leaks (paralelo, según config leak_scan):                       │
│     ├─ native (HC*)  → scan_directory con reglas hardcoded          │
│     ├─ apkleaks      → scan_with_apkleaks(apk) [subproceso]         │
│     └─ gitleaks      → scan_with_gitleaks(dir) [subproceso]         │
│                                                                     │
│     + _scan_xml_resources_for_secrets() → keys en strings.xml       │
│     + scan_native_libs() → .so (anti-debug, hardcoded, symbols)     │
│     + scan_manifest_components() → exported providers/receivers     │
│     → ScanResult(findings: VulnFinding[])                           │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  6. OSINT                          [osint.py]                       │
│     _do_osint_scan() → run_osint()                                 │
│     Alimentado por los leak_findings del paso anterior              │
│     Busca: crt.sh, GitHub, grep.app, FOFA, Shodan, Postman,         │
│            Google dorks, Wayback Machine                            │
│     → OsintResult (secrets, subdomains, public_leaks, auth_flows)   │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  7. Persistencia + Reporte                                        │
│     save_analysis_json() → reports/<package>/<timestamp>.json       │
│     _save_vuln_json()    → reports/<package>/vuln.json              │
│                           + decompiled/vuln_<package>.json (legacy) │
│     _save_osint_json()   → reports/<package>/osint.json             │
│     build_masvs_report()→ MASVS score (24 controles v2.1)           │
│     _generate_pdf()      → reports/<package>/<timestamp>.pdf        │
│     fire_post_hooks("after_analysis") → store/hooks.py (SQLite)     │
│                                          + plugins/aireview (IA)    │
└─────────────────────────────────────────────────────────────────────┘
```

## Detalle por componente

### 1. APKAnalyzer (`nutcracker_core/analyzer.py`)

`APKAnalyzer.analyze(apk_path)` es el punto de entrada al análisis de
protecciones anti-root. Usa **Androguard** (`AnalyzeAPK`) para cargar el APK y
obtener tres objetos: `apk` (manifest + metadata), `dex` (código Dalvik) y `dx`
(índice de análisis).

- `_extract_metadata()`: package, versionName, versionCode, minSdk, targetSdk.
- `_build_string_set(dx)`: todas las strings del DEX.
- `_build_class_set(dx)`: todos los nombres de clase.
- `_run_builtin_detectors()`: corre los 8 detectores de `detectors/` sobre los
  sets de strings/clases.
- `_run_apkid_detector()`: alternativa con APKiD (subproceso), traduce las
  categorías de APKiD a `DetectionResult`.

Salida: `AnalysisResult` con los siguientes campos derivados:
- `protected`: al menos un detector con `detected=True`.
- `protection_broken`: protección detectada Y bypass runtime exitoso con
  volcado de DEX (`dex_count > 0`).
- `aipwn_bypass_confirmed`: bypass confirmado por aipwn sin volcado de DEX
  (campo nuevo del ROADMAP, verificación dual del veredicto).
- `confidence`: `none` / `low` / `medium` / `high` según cantidad de
  detectores positivos.

Detectores disponibles (`nutcracker_core/detectors/`):

| Detector | Archivo | Qué busca |
|---|---|---|
| `KnownLibrariesDetector` | `libraries.py` | SDKs de protección (DexGuard, Appdome, Promon, Arxan...) |
| `SafetyNetDetector` | `safetynet.py` | Google Play Integrity / SafetyNet API |
| `ManualChecksDetector` | `manual_checks.py` | Heurísticas varias (RootBeer, detection de Frida, etc.) |
| `MagiskDetector` | `magisk.py` | Hooks anti-Magisk |
| `DexGuardDetector` | `dexguard.py` | DexGuard específico (strings, clase Runtime) |
| `AppdomeDetector` | `appdome.py` | Appdome (runtime application shielding) |
| `SignatureCheckDetector` | `signature_check.py` | Verificación de firma en runtime |
| `CertificatePinningDetector` | `certificate_pinning.py` | SSL pinning nativo/Js |

### 2. `_post_analysis_flow` (`orchestrator.py:615`)

Decide **cómo** decompilar según lo que detectó el paso 1:

- **App sin DexGuard:** ruta simple → `_do_decompile()` → jadx directo.
- **App con DexGuard detectado:** `_do_dexguard_deobf()` intenta:
  1. `frida-dexdump` (volcado de DEX en memoria con Frida + device conectado).
  2. Fallback a FART (volcado en memoria con hooks propios).
  3. Último fallback a jadx (aunque la ofuscación hará que el scan sea pobre).
  Los `.dex` resultantes se deobfuscan con `deobfuscator.decompile_dumps()` y se
  pasan a `_decompile_and_scan()`.

`_pipeline_decompilation_mode(protected)` define el modo: `none` / `jadx` /
`frida-dexdump` / `FART`.

### 3. Decompilación (`nutcracker_core/decompiler.py`)

`get_available_tool()` devuelve `"jadx"` si está en `PATH`, si no `"apktool"`
como fallback. `decompile()` corre la herramienta sobre el APK y genera:

```
./decompiled/<package>/
├── sources/        # .java decompilado (jadx)
└── resources/      # AndroidManifest.xml, strings.xml, layout/, etc.
```

### 4. Manifest scan (`nutcracker_core/manifest_analyzer.py`)

`analyze_decompiled_dir()` parsea `AndroidManifest.xml` y busca
misconfiguraciones:

- `debuggable=true`
- `allowBackup=true`
- `usesCleartextTraffic=true`
- Componentes `exported` sin permisos (activities, services, providers,
  receivers)
- `targetSdkVersion` bajo
- Network security config permisiva

Cada misconfig se mapea a MASVS vía `MISCONFIG_TO_MASVS`. **Limitación conocida**
(Fase 2): estos hallazgos no se persisten en la tabla `findings` porque no pasan
por `store/hooks.py` — viven solo en memoria y en el JSON del análisis.

### 5. Vuln + Leak scan (`nutcracker_core/vuln_scanner.py`, `leak_scanner.py`)

`_do_vuln_scan()` → `auto_scan(source_dir, engine, leak_engine)`. `auto_scan` es
el **punto de entrada unificado** del SAST:

**Motor de código (`engine`):**
- `"semgrep"`: `scan_with_semgrep()` con `p/android p/owasp-top-ten` por defecto.
- `"regex"`: `scan_directory()` con `RULES` (~54 reglas regex de
  `scan_types.py`).
- `"auto"`: usa semgrep si está instalado, si no regex.

`scan_directory` aplica cada `VulnRule` sobre `.java`/`.kt`/`.xml`, filtrando
archivos de SDK/terceros (`Android`, `Firebase`, `MSAL`, `okhttp`, etc.) para
reducir falsos positivos.

**Motores de leaks (`leak_engine`):**
- `native` (reglas `HC*`): `scan_directory` con reglas hardcoded de secretos.
- `apkleaks`: `scan_with_apkleaks(apk)` — subproceso externo.
- `gitleaks`: `scan_with_gitleaks(dir)` — subproceso externo.

**Scans adicionales integrados:**
- `_scan_xml_resources_for_secrets()`: keys en `strings.xml` / XML de recursos.
- `scan_native_libs()`: `.so` del APK — anti-debug, hardcoded secrets, símbolos
  sospechosos, entropía.
- `scan_manifest_components()`: providers/receivers exported con handler
  peligrosos.

Salida: `ScanResult(findings: list[VulnFinding])`. Cada `VulnFinding` incluye
`masvs`, `maswe` y `cwe` mapeados desde `RULE_TO_MASVS` / `RULE_TO_MASWE` /
`RULE_TO_CWE` en `masvs.py`.

### 6. OSINT (`nutcracker_core/osint.py`)

`run_osint()` toma los leak_findings del paso anterior y busca exposición pública:
- `crt.sh` — subdominios vía Certificate Transparency.
- GitHub — código fuente filtrado (scraping HTML; ROADMAP: migrar a REST API con
  `GITHUB_TOKEN`).
- `grep.app` — código público.
- FOFA / Shodan — exposición de infra.
- Postman — colecciones públicas.
- Google dorks, Wayback Machine.

Salida: `OsintResult(secrets, subdomains, public_leaks, auth_flows)`.

### 7. Persistencia + Reporte

**Archivos planos:**
```
reports/<package>/
├── <timestamp>.json    # AnalysisResult completo
├── <timestamp>.pdf     # PDF con secciones: findings, OSINT, MASVS
├── vuln.json           # ScanResult (lo que lee aipwn)
└── osint.json          # OsintResult
```
Más una copia legacy en `decompiled/vuln_<package>.json` (para `aireview`).

**SQLite (`nutcracker.db`)** vía `store/hooks.py` (post-hook `after_analysis`):
- `apps`: una fila por package (última corrida, veredicto).
- `runs`: una fila por corrida.
- `findings`: todos los `VulnFinding` con su taxonomía MASVS/MASWE/CWE.
- `artifacts`: rutas a APK, reportes, etc.

**MASVS:** `build_masvs_report(result, vuln_scan, manifest_analysis)` calcula el
score sobre los 24 controles MASVS v2.1. Cada control está `pass`, `fail` o
`warn` según los hallazgos. Cobertura actual: 18/24 controles con check
(`docs/owasp-mas-coverage.md`).

**Post-hooks:** `fire_post_hooks("after_analysis")` dispara:
- `store/hooks.py` (SQLite, siempre).
- `plugins/aireview` (análisis con IA del JSON, si está instalado).

## Framework de checks (Fase 2, paralelo)

`nutcracker_core/checks/` es un framework unificado con auto-descubrimiento que
**envuelve** los 3 registros manuales vía `checks/static/adapter.py`:

- `vuln_scanner.RULES` (~54 reglas regex)
- `native_scanner._NATIVE_RULES`
- `analyzer.ALL_DETECTORS` (8 detectores anti-root)
- `manifest_analyzer` (misconfigs)

Más 2 checks dinámicos (`debuggable`, `cleartext_traffic`) que corren en el
device. El registry se usa para generar `docs/owasp-mas-coverage.md` (matriz de
cobertura 18/24 controles).

**Limitación conocida** (Fase 2): el objetivo era migrar cada regla a un `.py`
individual en `checks/static/`, pero se dejó un adaptador por costo/beneficio.

## Comando `scan` (URL/Play Store)

Es idéntico al `analyze`, pero arranca con `downloader.py` (descarga el APK
desde Google Play con token AAS, o desde una URL directa) antes de entrar al
mismo `_run_analysis()`. Lleva `--keep-apk` siempre (la cola lo fuerza para
re-usos).

## Persistencia dual (Fase 0)

Todo análisis queda en **dos lugares**:
1. **Archivos planos** (igual que antes): `reports/<package>/*.json` + `.pdf`
2. **SQLite** (`nutcracker.db`): tablas `apps`, `runs`, `findings`, `artifacts`,
   `schedule` — vía el post-hook `after_analysis` en `store/hooks.py`.

## Integración con el dashboard

El dashboard (`plugins/dashboard/`) lee de la base SQLite (no de los JSON
planos):
- `GET /api/apps` — lista de apps analizadas.
- `GET /api/apps/{package}` — detalle + último run.
- `GET /api/apps/{package}/findings` — hallazgos paginados.
- `GET /api/queue` — jobs encolados (static / dynamic / aipwn).

El motor de colas (`queue/engine.py`) usa `orchestrator.build_job_cmd()` para
lanzar análisis como subprocesos aislados, reusando todo el flujo descrito aquí.

## Integración con aipwn

`plugins/aipwn/__init__.py::_load_scan_result()` lee el `vuln.json` del paso 5
para alimentar al ExploitAgent. Si no existe (porque el análisis estático nunca
completó el paso 7, o porque alguien decompiló manualmente), cae a un fallback:
corre `scan_directory()` en vivo sobre `decompiled/<package>/` y construye los
hallazgos al momento. Este fallback es lo que produce el mensaje:

```
[aipwn] no vuln JSON found — running live scan on decompiled/<package>
```

No es un error — es degradación esperada. El agente funciona igual con el
live-scan.

## Referencias cruzadas

- `ROADMAP.md` — ítems pendientes (iOS, port a Go, verdict dual, GitHub token).
- `docs/owasp-mas-coverage.md` — matriz de cobertura MASVS.
- `plan.md` — historial detallado de las Fases 0-4.