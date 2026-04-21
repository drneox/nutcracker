<p align="center">
  <img src="docs/assets/nutcracker-logo.png" alt="Nutcracker logo" width="360">
</p>

<p align="center">
  <a href="https://github.com/drneox/nutcracker/stargazers">
    <img src="https://img.shields.io/github/stars/drneox/nutcracker?style=for-the-badge&logo=github&logoColor=F3F4F6&labelColor=0B0F14&color=2F3742" alt="GitHub stars">
  </a>
  <a href="https://github.com/drneox/nutcracker/network/members">
    <img src="https://img.shields.io/github/forks/drneox/nutcracker?style=for-the-badge&logo=github&logoColor=F3F4F6&labelColor=0B0F14&color=3C4654" alt="GitHub forks">
  </a>
  <a href="https://github.com/drneox/nutcracker/issues">
    <img src="https://img.shields.io/github/issues/drneox/nutcracker?style=for-the-badge&logo=github&logoColor=F3F4F6&labelColor=0B0F14&color=C1121F" alt="GitHub issues">
  </a>
  <a href="https://github.com/drneox/nutcracker/commits/main">
    <img src="https://img.shields.io/github/last-commit/drneox/nutcracker?style=for-the-badge&logo=github&logoColor=F3F4F6&labelColor=0B0F14&color=5A6472" alt="GitHub last commit">
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=F3F4F6&labelColor=0B0F14" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/platform-Android-3FA34D?style=for-the-badge&logo=android&logoColor=F3F4F6&labelColor=0B0F14" alt="Android platform">
  <img src="https://img.shields.io/badge/dynamic%20analysis-Frida-B4232C?style=for-the-badge&labelColor=0B0F14" alt="Frida dynamic analysis">
</p>

# nutcracker v0.1 — Mobile Security & Offensive Threat Intelligence

Herramienta de análisis de aplicaciones Android orientada a investigadores de seguridad.
Descarga apps directamente desde Google Play, detecta y intenta eludir protecciones
anti-root/RASP (DexGuard, Arxan, Appdome, Promon, RootBeer), las decompila, extrae secretos y endpoints hardcodeados,
analiza configuraciones inseguras del manifest y lanza reconocimiento OSINT sobre el package ID,
dominios, endpoints y secretos extraídos (subdominios vía crt.sh, leaks públicos en GitHub/Postman/FOFA/Wayback y búsquedas web opcionales).
Todo el hallazgo se consolida en un informe PDF técnico listo para reportar.

---

## Características principales

- Descarga APKs desde Google Play (vía apkeep + AAS token), APKPure o URL directa
- Soporte para App Bundles (AAB): detección de splits y `adb install-multiple`
- Detección estática de protecciones: DexGuard, Arxan, Appdome, RootBeer, Promon Shield, etc.
- Filtrado inteligente de SDKs de analytics (AppMetrica, AppsFlyer, etc.) para evitar falsos positivos
- Desofuscación dinámica mediante `frida_server`, `gadget` o `fart`, según el pipeline configurado
- Instrumentación opcional con Frida Gadget como ruta embebida de fallback
- Escáner de vulnerabilidades: semgrep (OWASP MASTG) + 38 reglas regex internas
- Búsqueda de leaks/secretos configurable: reglas HC internas + apkleaks + gitleaks sobre código decompilado y APK original
- Módulo OSINT opcional: subdominios vía crt.sh, leaks públicos en GitHub/Postman/FOFA/Wayback, filtro anti-falsos-positivos y búsquedas web opcionales vía DuckDuckGo
- Análisis de AndroidManifest.xml: permisos peligrosos, componentes exportados, `network security config` y configuraciones inseguras
- Informe PDF completo: portada, resumen ejecutivo, anti-root, bypass RASP, configuraciones inseguras, leaks, OSINT y vulnerabilidades
- Modo batch para escanear múltiples apps en secuencia
- Módulos controlables por feature flags en `config.yaml`

---

## Requisitos del sistema

### macOS (instalación con Homebrew)

```bash
brew install apkeep       # descarga APKs de Google Play / APKPure
brew install jadx         # decompila APKs a Java + XML
brew install apktool      # desempaqueta/reempaqueta APKs (necesario para gadget_inject)
brew install semgrep      # análisis estático (reglas OWASP MASTG)
brew install android-platform-tools  # adb
```

### Linux (Ubuntu/Debian)

```bash
# Herramientas base
sudo apt update
sudo apt install -y openjdk-21-jre-headless jadx apktool adb curl

# semgrep (vía pipx recomendado)
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install semgrep

# apkeep (binario oficial)
APKEEP_VERSION="0.18.0"
curl -L -o /tmp/apkeep.tgz \
  "https://github.com/EFForg/apkeep/releases/download/v${APKEEP_VERSION}/apkeep-x86_64-unknown-linux-musl.tar.gz"
tar -xzf /tmp/apkeep.tgz -C /tmp
sudo install /tmp/apkeep /usr/local/bin/apkeep
apkeep --version
```

> Si usas otra distro (Fedora/Arch), instala equivalentes de `openjdk`, `jadx`, `apktool` y `adb`,
> y mantén `apkeep` desde su release oficial.

### Java (requerido por jadx y apktool)

```bash
# Java 11+ requerido. Ejemplo con OpenJDK:
brew install openjdk@21
```

Versión probada: `openjdk 23.0.1`

### Android SDK (requerido para emulador y firma de APKs)

Instalar desde [Android Studio](https://developer.android.com/studio) o con `sdkmanager`.
La herramienta detecta el SDK automáticamente en `~/Library/Android/sdk` (macOS).

Componentes necesarios:

```bash
# Desde Android Studio → SDK Manager, o con sdkmanager:
sdkmanager "platform-tools"                     # adb
sdkmanager "emulator"                           # emulador AVD
sdkmanager "build-tools;34.0.0"                 # apksigner, zipalign
sdkmanager "system-images;android-34;google_apis;arm64-v8a"  # imagen AVD
avdmanager create avd -n nutcracker_avd -k "system-images;android-34;google_apis;arm64-v8a"
```

> `apksigner` y `zipalign` son necesarios para el parcheado de APKs Bundle y para
> la inyección de Frida Gadget. Se encuentran en `~/Library/Android/sdk/build-tools/<ver>/`.

---

## Instalación Python

```bash
git clone <repo>
cd nutcracker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Dependencias Python (requirements.txt)

| Paquete | Uso |
|---|---|
| `androguard` | Análisis estático de APKs (DEX, manifest, strings) |
| `click` | CLI |
| `rich` | Salida en terminal con colores y spinners |
| `pyyaml` | Lectura de `config.yaml` |
| `fpdf2` | Generación de informes PDF |
| `loguru` | Logging estructurado |
| `requests` | HTTP (descarga frida-server, comunicación interna) |

> **Nota:** `frida`, `frida-tools`, `frida-dexdump`, `semgrep` y `apkleaks` son
> herramientas de sistema (pip o Homebrew), no dependencias del proyecto.
> Se validan con `shutil.which()` antes de usarse; si no están instaladas,
> el módulo correspondiente se salta con un warning.

---

## Uso con Docker (híbrido)

Este modo corre `nutcracker` dentro de Docker y usa un emulador/dispositivo conectado en el host.
Es la opción recomendada para Windows + WSL.

### 1) Construir y abrir shell del contenedor

```bash
docker compose build
docker compose run --rm nutcracker
```

### 2) Verificar que ADB del contenedor ve el host

Dentro del contenedor:

```bash
adb devices
frida-ls-devices
```

Si no aparece nada, en el host (Windows/Linux/macOS) reinicia ADB:

```bash
adb kill-server
adb start-server
adb devices
```

### 3) Ejecutar análisis desde el contenedor

```bash
python nutcracker.py analyze downloads/app.apk
```

### Notas para Windows + WSL

- El emulador suele correr en Windows, no en WSL.
- El contenedor se conecta al `adb server` del host vía `ADB_SERVER_SOCKET=tcp:host.docker.internal:5037`.
- Si Frida no resuelve `-D emulator-xxxx`, usar `-U` (el flujo del proyecto ya contempla esto en emulador).

---

## Reglas de análisis estático (semgrep)

Las reglas OWASP MASTG para código decompilado con jadx provienen de:
[mindedsecurity/semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security)

```bash
git clone https://github.com/mindedsecurity/semgrep-rules-android-security \
    semgrep_rules_android

# Para actualizar:
git -C ./semgrep_rules_android pull
```

El path se configura en `config.yaml`:
```yaml
strategies:
  scanner_config: "p/secrets ./semgrep_rules_android/rules"
```

> **Nota:** Los perfiles `p/android`, `p/secrets` y `p/owasp-top-ten` ya no están
> disponibles en el registro público de semgrep (HTTP 404 desde ~2025). Usar las reglas locales.

---

## Obtener el AAS Token de Google Play

apkeep requiere un AAS token de larga duración para descargar desde Google Play.

```bash
# Asistente interactivo (guiado paso a paso en el dispositivo):
python nutcracker.py setup-token

# Opcional: elegir dispositivo y método
python nutcracker.py setup-token --serial emulator-5554 --method auto
```

---

## Uso básico

```bash
source .venv/bin/activate

# Analizar una APK local:
python nutcracker.py analyze downloads/app.apk

# Descargar y analizar desde Google Play (URL o package ID):
python nutcracker.py scan 'https://play.google.com/store/apps/details?id=com.ejemplo.app'
python nutcracker.py analyze com.ejemplo.app

# Escaneo masivo desde un listado de paquetes:
python nutcracker.py batch packages.txt
```

---

## Configuración (`config.yaml` / `config.yaml.example`)

Usa [config.yaml.example](config.yaml.example) como fuente de verdad.
La práctica recomendada es copiar ese archivo a `config.yaml` y ajustar solo los valores que necesites.

```yaml
google_play:
  email: "tu@gmail.com"
  aas_token: "aas_et/..."

downloader:
  output_dir: "./downloads"
  keep_apk: true

reports:
  output_dir: "./reports"
  save_json: false
  save_pdf: true

features:                       # Feature flags: habilita o deshabilita módulos
  anti_root_analysis: true      # Detección de protecciones anti-root
  decompilation: true           # Decompilación (jadx o runtime, según el pipeline)
  manifest_scan: true           # Análisis de configuraciones inseguras del manifest
  vuln_scan: false              # Escáner de vulnerabilidades (regex + semgrep)
  leak_scan: true               # Escáner de leaks/secretos
  osint_scan: true              # OSINT: subdominios y leaks públicos
  report_pdf: true              # Generar informe PDF
  report_json: false            # Generar informe JSON

leak_scan:
  native: true                  # Reglas HC internas sobre código decompilado
  apkleaks: true                # apkleaks sobre el APK original
  gitleaks: true                # gitleaks sobre código decompilado

osint:
  crt_sh: true                  # Enumeración de subdominios vía crt.sh
  github_search: true           # Búsqueda de leaks públicos en GitHub
  github_token: ''              # PAT opcional para usar la API de Code Search
  fofa_search: false            # Búsqueda de activos expuestos en FOFA
  fofa_key: ''                  # API key de FOFA para search/all
  postman_search: true          # Búsqueda de colecciones públicas en Postman
  execute_dorks: false          # Búsquedas web opcionales vía DuckDuckGo
  dork_engines:
    - duckduckgo
  dork_max_per_engine: 5        # Máximo de queries web por motor
  dork_max_results_per_dork: 5  # Máximo de resultados por query
  wayback_search: true          # Búsqueda de URLs históricas en archive.org
  wayback_limit_per_domain: 200 # Máximo de URLs archivadas por dominio
  wayback_filter_interesting: true  # Filtra a rutas/queries sensibles

strategies:
  anti_root_engine: native      # Motor de detección anti-root
  scanner_engine: auto          # auto | semgrep | regex | none
  scanner_config: "p/secrets ./semgrep_rules_android/rules"
  show_emulator: true
  runtime_target: emulator      # auto | emulator | device
  default_emulator_avd: ""
  default_device_id: ""
  frida_host: ""               # host:port para Frida TCP
  frida_server_version: ""     # versión explícita de frida-server

pipelines:
  protected:                    # Apps con protección detectada
    decompilation: runtime      # Decompilación vía runtime (frida-dexdump)
    fallback_jadx: true         # Si runtime falla, intentar jadx
    runtime_methods:            # Se ejecutarán en el orden listado abajo
    # - frida_server: extracción runtime usando Frida con frida-server en el dispositivo o emulador
    # - gadget: instrumentación mediante Frida Gadget embebido en la APK
    # - fart: flujo alternativo de extracción runtime de DEX
    - frida_server
    - gadget
    - fart
  unprotected:                  # Apps sin protección
    decompilation_jadx: true    # Decompilación estática directa

auto:
  unattended: true              # Modo sin intervención manual

batch:
  list_file: ""                # Archivo de lista opcional para batch
  stop_on_error: false
```

---

## Flujo de análisis dinámico

```
APK
 └─► Instalar en emulador AVD
      ├─► frida-dexdump        (estrategia principal: vuelca DEX desde memoria)
      │    └─► falla →
      ├─► Frida Gadget inject   (si pipeline.protected incluye gadget)
      │    └─► falla →
      └─► FART (classloader hook via Frida script)
               └─► jadx → escaneo → PDF
```

### Secciones del informe PDF

| Sección | Descripción |
|---|---|
| Cover | Veredicto binario de protección (SIN PROTECCION / PROTECCION ROTA / PROTEGIDA) y metadata de la APK |
| Executive Summary | Resumen ejecutivo con datos de la app y riesgo por módulo |
| Anti-Root Analysis | Protecciones detectadas vs eludidas (5 detectores) |
| Bypass RASP | Técnicas de bypass para cada protección encontrada |
| Misconfigurations | Análisis del AndroidManifest.xml: `debuggable`, `allowBackup`, `cleartext`, componentes exportados y permisos peligrosos |
| Leaks | Secretos hardcodeados: API keys, tokens, credenciales AWS/Firebase |
| Vulnerabilidades | Hallazgos de semgrep + regex clasificados por severidad |

### Reducción de falsos positivos

Los detectores implementan múltiples capas de filtrado:

- **Anti-root**: Whitelist de 30+ namespaces de SDKs de analytics (AppMetrica, AppsFlyer, Adjust, etc.). Strings de root-check de SDKs no se cuentan como protección de la app.
- **DexGuard**: Requiere firma de vendor (guardsquare, arxan) como evidencia obligatoria. Multidex + alta entropía sin vendor sig no se reporta.
- **Leaks (regex)**: Patrones de ignore para HC002 (passwords), HC006 (crypto keys), AUTH001 (tokens en logs) que filtran constantes de framework.
- **Leaks (apkleaks)**: Post-filtrado de categorías ruidosas y patrones de FP (versiones JWT, X.509, firmas de Facebook SDK).

### Soporte para App Bundles (AAB)

Cuando apkeep descarga solo el split base (`base.apk`), la herramienta:
1. Detecta splits adicionales en la misma carpeta del paquete
2. Usa `adb install-multiple` con todos los splits
3. Si no hay splits locales: parchea el `AndroidManifest.xml` binario para anular
   `requiredSplitTypes` y reinstala

---

## Roadmap

Ver [ROADMAP.md](ROADMAP.md) para las tareas pendientes: mejoras OSINT, soporte iOS/IPA y migración parcial a Go.

---

## Estructura del proyecto

```
nutcracker/
├── nutcracker.py                   # CLI principal (click)
├── config.yaml                     # Configuración local
├── config.yaml.example             # Plantilla de configuración
├── setup.sh                        # Script de instalación rápida
├── requirements.txt                # Dependencias Python
├── docker-compose.yml              # Entorno Docker para ejecución híbrida
├── Dockerfile                      # Imagen base del proyecto
├── docs/assets/                    # Logo y recursos del README
├── downloads/                      # APKs descargadas
├── decompiled/                     # Código decompilado por jadx / frida-dexdump
├── frida_scripts/                  # Scripts Frida de bypass generados
├── reports/                        # PDFs e informes JSON generados
├── semgrep_rules_android/          # Reglas OWASP MASTG
├── tools/                          # Utilidades auxiliares
└── nutcracker_core/
  ├── __init__.py                 # Paquete principal
    ├── analyzer.py                 # Análisis estático principal (androguard)
  ├── apk_tools.py                # Utilidades de manipulación e instalación de APKs
  ├── config.py                   # Carga y acceso a config.yaml
  ├── device.py                   # Dispositivos, SDK, Frida y utilidades adb
    ├── downloader.py               # Descarga APKs (Google Play / APKPure / URL directa)
    ├── decompiler.py               # Interfaz jadx
    ├── deobfuscator.py             # Flujo FART para dispositivo físico
  ├── frida_bypass.py             # Scripts Frida (bypass, FART)
    ├── manifest_analyzer.py        # Análisis de AndroidManifest.xml y configuraciones inseguras
  ├── osint.py                    # Subdominios, leaks públicos, Wayback y búsquedas web opcionales
    ├── pdf_reporter.py             # Generación del informe PDF (fpdf2)
    ├── pipeline.py                 # Pipeline de análisis end-to-end
  ├── reporter.py                 # Reportes JSON y salida en consola
  ├── runtime.py                  # Orquestación de análisis dinámico
    ├── string_extractor.py         # Extracción de strings del APK
  ├── vuln_scanner.py             # Semgrep + regex + apkleaks + gitleaks
    └── detectors/
    ├── __init__.py             # Export del subpaquete de detectores
    ├── appdome.py              # Detector de Appdome
    ├── base.py                 # Base común para detectores
        ├── dexguard.py             # Detector DexGuard / Arxan (requiere firma de vendor)
        ├── libraries.py            # Detector librerías anti-root (solo clases, no strings)
        ├── magisk.py               # Detector Magisk / SuperSU / KernelSU / Frida
        ├── safetynet.py            # Detector SafetyNet / Play Integrity API
        └── manual_checks.py        # Checks manuales (con filtrado de SDKs de analytics)
```


