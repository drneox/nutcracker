
> Documento generado a partir del análisis del código en
> `nutcracker_core/plugins/aipwn/`.
> Última revisión: 2026-07-27.

## Resumen

`python3 nutcracker.py aipwn <package>` ejecuta un **agente autónomo ReAct con
LLM** que bypasea protecciones Android (root detection, SSL pinning, anti-Frida,
emulator detection, signature verification) usando Frida, y luego opcionalmente
confirma vulnerabilidades en runtime mediante un ExploitAgent.

## Diagrama general

```
┌─────────────────────────────────────────────────────────────────────┐
│  nutcracker aipwn <package>            [__init__.py::register()]     │
│  --serial / --max-runs / --capture-sec / --force / --only-bypass    │
│  --report                                                            │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  1. Carga de contexto              [__init__.py::aipwn_cmd]          │
│     ── _load_analysis_json(package) → AnalysisResult previo          │
│     ── Busca decompiled/<package>/ o runtime_dump_<package>/        │
│     ── _load_scan_result(package) → ScanResult (vuln.json)           │
│         ├─ Si no existe vuln.json → live scan (scan_directory)       │
│         └─ Enriquece con manifest components                        │
│     ── _init_i18n(config)                                            │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  2. run_aipwn()                    [aipwn.py]                        │
│     ── Setup TeeWriter (log a logs/<pkg>_<ts>_aipwn.txt)            │
│     ── Crea aipwn_memory/                                           │
│     ── _run_aipwn_inner():                                          │
│        ├─ Paso 0: ¿app instalada? → _auto_download_apk + install    │
│        ├─ Paso 1: script previo (si no --force)                     │
│        ├─ Paso 2: FridaAgent.run() ← EL CEREBRO                     │
│        └─ Modo exploit (si bypass OK y scan_result): ExploitAgent   │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  3. Paso 1 — Script previo         [aipwn.py::_find_latest_script]  │
│     Busca frida_scripts/bypass_<package>_<ts>_agent.js              │
│     ── Si existe y no --force:                                      │
│        ├─ launch_frida_capture(script)                              │
│        └─ Si success → retorna inmediatamente (sin llamar al LLM)   │
│     ── Si falla o no existe → continúa al agente LLM                │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  4. FridaAgent — Loop ReAct        [frida_agent.py]                  │
│     System prompt (fase 1-3, reglas de terminación)                 │
│     + Contexto inicial (package, protecciones, memoria pasada)      │
│                                                                      │
│     while not terminated and iter < max_llm_iterations:              │
│       1. _check_operator_chat() ← poll dashboard mailbox (Fase 3)    │
│       2. Anti-bucle pressure (si N iters sin run_frida_script)       │
│       3. LLMClient.chat(messages, tools=TOOL_SCHEMAS)                │
│          ├─ any-llm SDK (OpenAI/Anthropic/Ollama)                    │
│          ├─ Retry con backoff (429, context too long)                │
│          └─ Auto-fallback: sin imágenes si vision no soportado       │
│       4. Mostrar thinking + "Nutcracker says"                       │
│       5. Por cada tool_call en response.tool_calls:                  │
│          ├─ dispatch_tool(ctx, name, args)                           │
│          ├─ Inyecta hints dinámicos según el resultado               │
│          ├─ Detecta señales Phase 2b (SIGSEGV, watchdog, etc.)      │
│          ├─ Detecta ClassLoader integrity fail → inyecta prompt      │
│          └─ Si report_success/report_failure → terminated=True       │
│       6. _prune_messages() si contexto > 60KB                       │
│                                                                      │
│     Al terminar:                                                    │
│     ── _write_bypass_result() → reports/<pkg>/bypass_result.json    │
│     ── _save_memory() → aipwn_memory/<pkg>_memory.json              │
│     → AgentResult(success, script_path, explanation, ...)           │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  5. 27 Herramientas del agente    [frida_agent_tools.py]            │
│     (definidas en TOOL_SCHEMAS, dispatchadas por dispatch_tool)     │
│                                                                      │
│     Análisis estático (no consumen Frida run):                       │
│     ── get_app_analysis: protecciones del AnalysisResult             │
│     ── get_heuristic_bypass_script: script base cacheado servidor   │
│     ── read_decompiled_class: lee .java decompilado                  │
│     ── search_in_decompiled: grep sobre código fuente                │
│     ── list_classes_matching: busca clases por keyword               │
│     ── enumerate_runtime_classes: clases reales en runtime (Frida)   │
│     ── get_class_methods: firmas exactas de métodos                  │
│     ── get_certificate_pins: lee network_security_config.xml         │
│                                                                      │
│     Ejecución Frida (consumen run slot):                             │
│     ── run_frida_script: ejecuta JS en device (on_frida_run cb)     │
│     ── relaunch_with_gadget: inyecta gadget y reinstala              │
│     ── patch_native_lib: parchea .so, repaqueta, firma, reinstala    │
│                                                                      │
│     Diagnóstico (no consumen run):                                   │
│     ── probe_security_violations: captura stack trace del bloqueo    │
│     ── take_screenshot: captura pantalla → mensaje visual al LLM     │
│     ── sniff_network_calls: captura HTTP fallido (SSL, 4xx)          │
│     ── trace_method_execution: Stalker sobre una clase/método        │
│     ── get_frida_output_history: stdout+logcat de runs anteriores    │
│                                                                      │
│     Native (no consumen run):                                        │
│     ── get_loaded_native_libs: lista .so cargados                    │
│     ── enumerate_native_exports: exports de un .so                   │
│     ── strings_native_lib: strings de un .so con filtro              │
│     ── resolve_native_symbol: dirección de un símbolo                │
│     ── disassemble_native_lib: objdump/r2 a un offset                │
│     ── pull_apk_from_device: extrae base+splits del device           │
│     ── get_apk_signature: firma original del APK                     │
│                                                                      │
│     Terminación:                                                    │
│     ── report_success: marca bypass OK, guarda script                │
│     ── report_failure: marca fallo con razón                        │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  6. frida_capture                  [frida_capture.py]                │
│     launch_frida_capture(package, script_js, serial, duration):     │
│     ── setup_frida_server() si hace falta (push + chmod + run)      │
│     ── frida -U -s script.js -f package (spawn) o attach            │
│     ── Captura stdout del script + logcat por N segundos             │
│     ── _parse_result(): analiza outputs y construye FridaRunResult  │
│        ├─ success/bypass_confirmed                                  │
│        ├─ security_blocked (custom RASP detectó bypass)             │
│        ├─ app_running/app_crashed                                   │
│        ├─ emulator_detected                                         │
│        ├─ hooks_failed[] (ClassNotFoundException, etc.)             │
│        ├─ crash_lines[] (FATAL EXCEPTION, stack trace)              │
│        ├─ sigsegv_in_native_lib                                     │
│        ├─ terminated_on_detach (watchdog nativo)                    │
│        └─ classloader_integrity_failed                              │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  7. ExploitAgent (opcional)        [exploit_agent.py]                │
│     Solo si: bypass OK + scan_result + exploit_mode=True             │
│                                                                      │
│     Recibe ScanResult.findings → por cada VulnFinding:               │
│     ── EXPLOIT_STRATEGY[rule_id] → tool a llamar                     │
│        ├─ send_deeplink (INJ004)                                    │
│        ├─ send_broadcast (COMP004)                                  │
│        ├─ start_exported_component (COMP006/7, COMP001/2/3/5, INFO)  │
│        ├─ read_shared_prefs (ST001)                                 │
│        ├─ read_app_file (ST002/3/4)                                 │
│        ├─ confirm_cleartext_traffic (NET001/2)                      │
│        ├─ inject_sql_payload (INJ001, COMP008)                      │
│        ├─ read_native_secret (NAT004)                               │
│        └─ None → report directo (HC*, NAT sin confirmación)         │
│     ── Genera PoC, ejecuta, observa (screenshot/logcat/file)        │
│     ── ExploitReport con PoCResults (confirmed, poc, evidence)      │
└──────────────────────────────────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  8. Persistencia + Reporte                                         │
│     ── aipwn_memory/<pkg>_memory.json: sesión persistente            │
│     ── reports/<pkg>/bypass_result.json: resultado del bypass        │
│     ── reports/<pkg>/exploit_report_<pkg>.json: exploit (si --report)│
│     ── reports/<pkg>/exploit_report_<pkg>.pdf: PDF standalone        │
│     ── reports/<pkg>/nutcracker_<pkg>_full_report.pdf: fusionado    │
│     ── frida_scripts/bypass_<pkg>_<ts>_agent.js: script reutilizable│
│     ── logs/<pkg>_<ts>_aipwn.txt: log completo de la sesión         │
│     ── AnalysisResult.aipwn_bypass_confirmed=True (para MASVS)      │
└─────────────────────────────────────────────────────────────────────┘
```

## Detalle por componente

### 1. Entrada CLI (`plugins/aipwn/__init__.py`)

El comando `nutcracker aipwn <package>` acepta:

| Opción | Descripción |
|---|---|
| `--serial`, `-s` | Serial ADB del dispositivo (default: USB) |
| `--max-runs` | Máximo de ejecuciones Frida (default: `aipwn.max_frida_runs`) |
| `--capture-sec` | Segundos de observación por run (default: `aipwn.capture_seconds`) |
| `--force` | Omite validación de script previo, va directo al LLM |
| `--only-bypass` | Solo bypass, sin ExploitAgent |
| `--report` | Guarda exploit results como JSON + PDF |

Antes de llamar a `run_aipwn()`, carga contexto:

- `_load_analysis_json(package)` → lee el último `AnalysisResult` de
  `reports/<package>/`. Si no existe, el agente opera sin contexto de
  protecciones detectadas estáticamente.
- `_load_scan_result(package)` → lee el `vuln.json` para alimentar al
  ExploitAgent. Si no existe, cae a **live-scan** (`scan_directory()` sobre el
  directorio decompilado). Esto produce el mensaje:
  `[aipwn] no vuln JSON found — running live scan on decompiled/<package>`.
- `_init_i18n(config)` → inicializa traducciones.

Si el bypass se confirma (`agent_result.success`), se persiste el flag
`aipwn_bypass_confirmed=True` en el `AnalysisResult` (re-escrito a disco) para
que `build_masvs_report()` lo recoja en futuras corridas — un bypass confirmado
en runtime es evidencia válida de `RESILIENCE` roto aunque no se haya volcado
DEX en memoria.

### 2. Orquestador (`aipwn.py::run_aipwn`)

`run_aipwn()` envuelve la lógica en un `_TeeWriter` que duplica toda la salida
ANSI del terminal a `logs/<pkg>_<ts>_aipwn.txt` (sin códigos ANSI). Aplica a
todas las consolas (`aipwn.py`, `frida_agent.py`, `frida_capture.py`,
`frida_agent_tools.py`) para que nada se pierda.

`_run_aipwn_inner()` hace:

1. **Paso 0 — App instalada:** si `check_app_installed()` devuelve `False`,
   intenta `_auto_download_apk()` (Google Play con AAS token o APKPure) e
   `_adb_install()` (maneja splits, firma incompatible, abis).
2. **Paso 1 — Script previo:** si no `--force`, busca el último
   `bypass_<package>_*.js`. Si existe y pasa `launch_frida_capture()`, retorna
   éxito inmediatamente **sin llamar al LLM** (ahorro de tokens).
3. **Paso 2 — FridaAgent:** crea el agente con todo el contexto y llama
   `agent.run()`.
4. **Modo exploit:** si `exploit_mode=True`, `result.success=True` y hay
   `scan_result`, lanza `ExploitAgent`.

### 3. FridaAgent (`frida_agent.py`)

El corazón del módulo. Es un **loop ReAct** (Reason + Act) con function calling.

#### System prompt

Define una estrategia de escalada en **3 fases obligatorias**:

- **Fase 1 — Java-level bypass:**
  1. `get_app_analysis` → entiende qué protecciones hay.
  2. `get_heuristic_bypass_script` → script base probado (cacheado en servidor)
     con hooks para File.exists, Runtime.exec, PackageManager, RootBeer,
     Build fields spoof, Frida detection hiding, etc.
  3. `get_certificate_pins` si hay SSL pinning (lee
     `network_security_config.xml`).
  4. `probe_security_violations` o `read_decompiled_class` para encontrar RASP
     custom.
  5. `list_classes_matching` / `enumerate_runtime_classes` para clases
     relevantes.
  6. `get_class_methods` para firmas exactas.
  7. Escribe solo los hooks adicionales necesarios + siempre incluye
     `FLAG_SECURE` bypass.
  8. `run_frida_script` con `extend_heuristic_base=true`.

- **Fase 2 — Native-level escalation (obligatoria si Java falla):**
  - Señales de activación: `security_blocked=True`, `app_running=False`,
    `app_crashed=True`, `hooks_failed` de SSL.
  - `get_loaded_native_libs` → `enumerate_native_exports` → `Interceptor.attach`
    sobre `SSL_CTX_set_verify`, `SSL_do_handshake`, `CONSCRYPT_checkServerTrusted`,
    etc.

- **Fase 3 — Universal fallback (obligatoria si Fase 2 falla):**
  - Reflection-based SSL bypass (`HttpsURLConnection`,
    `OkHttpClient.Builder`).
  - `Java.deoptimizeEverything()`.
  - Spoof de signature (`PackageManager.getPackageInfo`).

#### Sub-prompts condicionales

Se **inyectan dinámicamente** cuando el loop detecta señales específicas:

- **`_PHASE2B_PROMPT`** — RASP self-integrity bypass. Se activa cuando:
  `sigsegv_in_native_lib=True`, o muerte instantánea con
  `extend_heuristic_base=True` (DT_PREINIT_ARRAY), o `terminated_on_detach`
  (watchdog nativo). Estrategias: spawn gating, `Memory.patchCode()`, binary
  patch permanente.

- **`_CLASSLOADER_INTEGRITY_PROMPT`** — DexGuard / APK tamper detection. Se
  activa cuando el crash contiene "tamper"/"signature",
  `INSTALL_FAILED_TEST_ONLY`, o crash tras `relaunch_with_gadget`. Estrategias:
  spoof de signature in-memory, hook ClassLoader con spawn gating, patch nativo
  del check.

#### LLMClient

Usa `any-llm-sdk` (`from any_llm import completion`) que abstrae OpenAI,
Anthropic y Ollama con una interfaz unificada. Maneja:

- **API key vía env var** (mecanismo más fiable): `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`.
- **Thinking blocks:** extrae `reasoning_content` (DeepSeek thinking mode) o
  bloques `thinking` (Anthropic extended thinking).
- **Auto-fallback de visión:** si el error indica que el proveedor no soporta
  imágenes (`_is_vision_unsupported_error`), reintenta sin los bloques de imagen
  (`_strip_image_blocks`).
- **Retry con backoff:** 3 intentos. Backoff exponencial para 429/rate limit,
  poda agresiva de contexto para "prompt too long", sin reintento para
  quota/credits exhausted.

#### Mecanismos anti-bucle

- **Pressure message:** si pasan `max_llm_iterations // 3` iteraciones sin
  `run_frida_script`, se inyecta un mensaje `[SYSTEM]` forzando al agente a
  actuar. Se repite cada iteración hasta que ejecute Frida.
- **Bloqueo de duplicados:** `enumerate_runtime_classes` con el mismo patrón
  devuelve un mensaje `[SYSTEM]` prohibiendo repetir la búsqueda.
- **Context pruning:** `_prune_messages()` recorta resultados de herramientas
  antiguas (`role=tool`) a 300 chars cuando el historial supera 60KB. Protege
  system prompt, primer user, y últimos 4 mensajes.

#### Terminación inteligente (anti-alucinación)

El system prompt tiene **reglas estrictas** para evitar falsos positivos de
`report_success`:

1. Tras cualquier `run_frida_script` con `bypass_confirmed=true`, el LLM debe
   llamar `take_screenshot` PRIMERO.
2. Debe describir explícitamente qué ve:
   - Elemento interactivo (botón, campo, label, icono), o
   - Color de marca + panel de contenido no vacío.
3. **Patrones de razonamiento prohibidos** (hardcodeados):
   - "bypass_confirmed=true por tanto éxito"
   - "app_running=true por tanto funciona" (splash atascado también tiene
     `app_running=true`)
   - "sesiones pasadas mostraron éxito" (alucinación — no hay memoria in-LLM)
   - "pantalla oscura es el theme"
   - "tomemos otro screenshot para verificar" (si ya hay colores de marca +
     panel, está confirmado)

#### Wiring del dashboard (`_check_operator_chat`)

Si la corrida viene de un job de la cola lanzado por el dashboard, la variable
`NUTCRACKER_DASHBOARD_URL` apunta a la API local. Antes de cada turno del LLM,
se hace poll best-effort de `/api/chat/<package>/pending`. Si hay mensajes del
operador, se inyectan como `role: user` reales — el LLM los ve y puede actuar en
consecuencia. Sin dashboard (uso CLI normal), es un no-op inmediato. Cualquier
fallo de red se ignora en silencio.

### 4. Herramientas (`frida_agent_tools.py`)

27 herramientas definidas en `TOOL_SCHEMAS` (JSON Schema para function calling),
dispatchadas por `dispatch_tool(ctx, name, args, next_run_idx)`.

**`ToolContext`** es un dataclass que lleva todo el estado compartido: package,
`decompiled_dir`, `analysis_result`, serial, `frida_host`, `capture_seconds`,
`scripts_dir`, callback `on_frida_run`, `runtime_dump_dir`.

| Categoría | Herramientas | Consume run |
|---|---|---|
| Análisis estático | `get_app_analysis`, `get_heuristic_bypass_script`, `read_decompiled_class`, `search_in_decompiled`, `list_classes_matching`, `enumerate_runtime_classes`, `get_class_methods`, `get_certificate_pins` | No |
| Ejecución Frida | `run_frida_script`, `relaunch_with_gadget`, `patch_native_lib` | Sí |
| Diagnóstico | `probe_security_violations`, `take_screenshot`, `sniff_network_calls`, `trace_method_execution`, `get_frida_output_history` | No |
| Native | `get_loaded_native_libs`, `enumerate_native_exports`, `strings_native_lib`, `resolve_native_symbol`, `disassemble_native_lib`, `pull_apk_from_device`, `get_apk_signature` | No |
| Terminación | `report_success`, `report_failure` | — |

Cada herramienta devuelve un string JSON que el LLM ve como `role: tool`.
Además, tras cada `run_frida_script`, el loop inyecta **hints dinámicos** según
el resultado: `security_blocked` → instrucciones de RASP custom,
`ClassNotFoundException` → patrón de ClassLoader isolation, `app_crashed` →
"analiza crash_lines, no reportes fallo todavía".

### 5. Captura Frida (`frida_capture.py`)

`launch_frida_capture(package, script_js, serial, duration)`:

1. `setup_frida_server()` si hace falta — push del `frida-server` matching arch,
   chmod +x, run en background.
2. Ejecuta `frida -U -s script.js -f package` (spawn) o attach.
3. Captura stdout del script + logcat por `duration` segundos.
4. `_parse_result()` analiza los outputs y construye `FridaRunResult`:

| Campo | Significado |
|---|---|
| `success` / `bypass_confirmed` | Heurísticas indican bypass exitoso |
| `security_blocked` | Custom RASP detectó el bypass |
| `app_running` | La app sigue viva tras el run |
| `app_crashed` | FATAL EXCEPTION o SIGKILL |
| `emulator_detected` | Logcat muestra detección de emulador |
| `hooks_failed[]` | Hooks que fallaron (ClassNotFoundException, etc.) |
| `crash_lines[]` | Stack trace del crash |
| `sigsegv_in_native_lib` | SIGSEGV dentro de lib de seguridad |
| `terminated_on_detach` | Watchdog nativo mata al desatachar |
| `classloader_integrity_failed` | ClassLoader integrity check |

### 6. ExploitAgent (`exploit_agent.py`)

Segundo agente LLM que corre **solo si** bypass OK + `scan_result` +
`exploit_mode=True`. Recibe los `VulnFinding` del análisis estático y, por cada
uno, decide una estrategia vía `EXPLOIT_STRATEGY[rule_id]`:

| rule_id | Estrategia |
|---|---|
| `INJ004` | `send_deeplink` |
| `COMP004` | `send_broadcast` |
| `COMP006/7`, `COMP001/2/3/5` | `start_exported_component` |
| `INFO001` | `start_exported_component` (debuggable) |
| `ST001` | `read_shared_prefs` |
| `ST002/3/4` | `read_app_file` |
| `NET001/2` | `confirm_cleartext_traffic` |
| `INJ001`, `COMP008` | `inject_sql_payload` |
| `NAT004` | `read_native_secret` |
| `HC*`, `NAT*` (otros) | `None` — report directo (no requiere runtime) |

Genera un PoC, lo ejecuta, observa (screenshot/logcat/file), y produce
`ExploitReport` con `PoCResults` (confirmed, poc, evidence).

### 7. Memoria persistente (`agent_memory.py`)

`aipwn_memory/<pkg>_memory.json` guarda las últimas 10 sesiones:

- **Hooks que funcionaron** (reutilizar).
- **Hooks que fallaron** (evitar).
- **Clases confirmadas en runtime** (seguras para `Java.use`).
- **Clases de análisis estático** (pueden diferir del runtime; verificar con
  `enumerate_runtime_classes` antes de `Java.use`).
- Notas del outcome.

`build_memory_context()` construye un bloque de texto que se inyecta en el
primer mensaje del agente para que **no repita errores** en corridas futuras.

### 8. Persistencia + Reporte

| Salida | Ruta |
|---|---|
| Script reutilizable | `frida_scripts/bypass_<pkg>_<ts>_agent.js` |
| Memoria de sesión | `aipwn_memory/<pkg>_memory.json` |
| Resultado del bypass | `reports/<pkg>/bypass_result.json` |
| Log completo | `logs/<pkg>_<ts>_aipwn.txt` |
| Exploit JSON | `reports/<pkg>/exploit_report_<pkg>.json` |
| Exploit PDF standalone | `reports/<pkg>/exploit_report_<pkg>.pdf` |
| PDF fusionado | `reports/<pkg>/nutcracker_<pkg>_full_report.pdf` |
| Flag MASVS | `AnalysisResult.aipwn_bypass_confirmed=True` |

## Configuración (`config.yaml`)

```yaml
llm:
  provider: openai        # openai | anthropic | ollama
  model: gpt-4o
  api_key: sk-...
  base_url: ...           # opcional, para endpoints OpenAI-compatible
  max_tokens: 4096
  timeout: 120

aipwn:
  max_frida_runs: 5
  max_llm_iterations: 30
  capture_seconds: 30
  scripts_dir: frida_scripts
  show_thinking: true
```

## Limitación conocida — Mensajes multimodales con z.ai/GLM

El proveedor OpenAI-compatible z.ai/GLM rechaza el formato de mensaje
multimodal (imagen) que `frida_agent.py` construye para `take_screenshot`:

```
LLM error: ... "messages.content.type is invalid, allowed values: ['text']"
```

`LLMClient.chat()` tiene un fallback automático
(`_is_vision_unsupported_error` → reintenta sin imágenes), pero esto significa
que el agente pierde la capacidad de ver la pantalla — crítica para la regla de
terminación que exige confirmación visual antes de `report_success`. Ver
`ROADMAP.md` sección *aipwn*.

## Integración con el dashboard

Cuando `aipwn` se lanza como job de la cola (`queue add --aipwn`):

- El dashboard setea `NUTCRACKER_DASHBOARD_URL`.
- `FridaAgent._check_operator_chat()` hace poll del mailbox
  (`/api/chat/<pkg>/pending`) antes de cada turno del LLM.
- Los mensajes del operador se inyectan como `role: user` reales.
- El razonamiento del agente se streamea por el WebSocket de live-logs.

El motor de colas (`queue/engine.py`) usa `orchestrator.build_job_cmd(aipwn=True)`
para lanzar el análisis como subproceso aislado, reusando todo el flujo descrito
aquí.

## Referencias cruzadas

- `docs/static-analysis-flow.md` — flujo del análisis estático que alimenta a
  aipwn.
- `docs/owasp-mas-coverage.md` — cobertura MASVS (incluye `RESILIENCE-*` que
  aipwn puede confirmar).
- `ROADMAP.md` — limitación multimodal, verdict dual.
- `plan.md` — Fase 3 (wiring del dashboard con el agente).