<img src="https://github.com/user-attachments/assets/25fc8264-d594-49b4-a8a5-2b7cded1f52a" alt="AiPWN banner">

# AiPWN

**AiPWN** es un plugin de [nutcracker.sh](https://nutcracker.sh) que utiliza IA para bypassear protecciones RASP (Runtime Application Self-Protection) en aplicaciones Android y confirmar vulnerabilidades en tiempo de ejecución.

El plugin orquesta dos agentes basados en LLM:

- **BypassAgent** — analiza el código decompilado, genera y adapta scripts Frida de forma iterativa hasta conseguir bypass exitoso de las protecciones de la app.
- **ExploitAgent** — tras el bypass, confirma dinámicamente las vulnerabilidades detectadas por el escáner estático de nutcracker ejecutando pruebas ADB/Frida sobre el dispositivo real.

Ambos operan de forma autónoma e iterativa, sin intervención manual.

---

## Requisitos

- Dispositivo Android con **root** y **frida-server** corriendo
- **ADB** instalado y el dispositivo visible (`adb devices`)
- Python 3.11+
- nutcracker con un resultado de análisis estático previo (`nutcracker scan <package>`)

---

## Instalación

```bash
pip install -r requirements.txt
```

El plugin se carga automáticamente desde nutcracker. No requiere instalación adicional.

---

## Uso

```bash
nutcracker aipwn <package_id> [opciones]
```

### Ejemplos

```bash
# Bypass + confirmación de vulnerabilidades (comportamiento por defecto)
nutcracker aipwn com.example.app

# Solo bypass Frida, sin confirmación de vulnerabilidades
nutcracker aipwn com.example.app --only-bypass

# Bypass + confirmación + guardar informe JSON y PDF
nutcracker aipwn com.example.app --report

# Forzar re-ejecución ignorando bypass cacheado
nutcracker aipwn com.example.app --force

# Dispositivo específico
nutcracker aipwn com.example.app --serial R3CN90XXXXX
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `--serial`, `-s` | Serial ADB del dispositivo (por defecto: primer dispositivo USB) |
| `--max-runs N` | Máximo de ejecuciones Frida (override de `aipwn.max_frida_runs`) |
| `--capture-sec N` | Segundos de captura por ejecución (override de `aipwn.capture_seconds`) |
| `--only-bypass` | Ejecuta solo el bypass Frida; omite la confirmación de vulnerabilidades |
| `--report` | Guarda los resultados de explotación como JSON + PDF en `reports/<package>/` |
| `--force` | Fuerza re-ejecución aunque exista un bypass cacheado |

---

## Configuración

En el archivo `config.yaml` de nutcracker:

```yaml
llm:
  provider: openai        # Proveedor LLM: openai, anthropic, ollama
  model: gpt-4o           # Modelo (ej: gpt-4o, claude-3-5-sonnet, qwen2.5-coder:32b)
  api_key: sk-...         # API key del proveedor (no necesaria para Ollama)
  base_url: ''            # URL base personalizada (ver sección LLM local)
  max_tokens: 4096        # Máximo de tokens por respuesta
  timeout: 120            # Timeout en segundos por llamada al LLM

aipwn:
  max_frida_runs: 10      # Máximo de ejecuciones Frida por sesión
  max_llm_iterations: 30  # Máximo de iteraciones del agente LLM
  capture_seconds: 15     # Segundos de captura de salida Frida por ejecución
  scripts_dir: frida_scripts  # Directorio donde se guardan los scripts generados
  show_thinking: true     # Mostrar el razonamiento interno del agente
```

### Parámetros LLM

| Clave | Descripción | Default |
|-------|-------------|---------|
| `provider` | Proveedor LLM: `openai`, `anthropic`, `ollama` | — |
| `model` | Nombre del modelo | — |
| `api_key` | API key del proveedor | — |
| `base_url` | URL base personalizada | `''` |
| `max_tokens` | Tokens máximos por respuesta | `4096` |
| `timeout` | Timeout por llamada (segundos) | `120` |

### Parámetros AiPWN

| Clave | Descripción | Default |
|-------|-------------|---------|
| `max_frida_runs` | Máximo de ejecuciones Frida por sesión | `10` |
| `max_llm_iterations` | Máximo de iteraciones del agente LLM | `30` |
| `capture_seconds` | Segundos de captura por ejecución | `15` |
| `scripts_dir` | Directorio de scripts generados | `frida_scripts` |
| `show_thinking` | Mostrar razonamiento interno del agente | `true` |

---

## LLM local (Ollama / LM Studio)

AiPWN soporta cualquier proveedor con API compatible con OpenAI. Para usar un modelo local:

**Ollama:**
```yaml
llm:
  provider: ollama
  model: qwen2.5-coder:32b   # o llama3.1:70b, deepseek-coder-v2, etc.
  base_url: http://localhost:11434/v1
  api_key: ""
```

**LM Studio / vLLM / llama.cpp:**
```yaml
llm:
  provider: openai
  model: local-model
  base_url: http://localhost:8080/v1
  api_key: fake-key
```

> **Nota:** Los agentes requieren soporte de *function calling* (tool use). Para el BypassAgent se recomienda un modelo de al menos 32B parámetros (Qwen2.5-Coder 32B, DeepSeek-R1 32B). El ExploitAgent funciona bien desde 14B.

---

## Flujo de ejecución

```
nutcracker aipwn <package>
        │
        ▼
  ┌─────────────┐     Script cacheado?  ──yes──▶  Ejecutar script previo
  │ BypassAgent  │                                     │
  │  (bypass)   │◀── no ────────────────────────────  │
  └─────────────┘                                      │
        │ bypass exitoso                               │
        ▼                                              │
  ┌──────────────┐  --only-bypass?  ──yes──▶  Fin     │
  │ ExploitAgent │                                     ▼
  │  (exploit)   │◀── no ─────────────────────────────┘
  └──────────────┘
        │
        ▼
  ┌─────────────────┐  --report?  ──yes──▶  JSON + PDF en reports/<package>/
  │  Resultado      │
  └─────────────────┘
```

1. **BypassAgent** recibe el código decompilado de la app. Obtiene un script base heurístico, lo adapta al objetivo y lo ejecuta con Frida. Analiza la salida y screenshots para determinar si el bypass fue exitoso; si no, itera ajustando el script hasta alcanzar `max_frida_runs`.

2. Si el bypass fue exitoso, **ExploitAgent** toma el resultado del análisis estático de nutcracker y confirma cada vulnerabilidad ejecutando comandos ADB o scripts Frida específicos por regla. Las vulnerabilidades con evidencia estática suficiente (claves hardcodeadas, configuraciones inseguras) se marcan como confirmadas directamente sin prueba dinámica adicional.

3. Con `--report`, se genera un informe PDF que incluye el estado del bypass, screenshots de confirmación y el detalle de cada vulnerabilidad confirmada.

---

## Salida

### Memoria del agente

Tras cada sesión, AiPWN guarda en `aipwn_memory/<package>_memory.json` el resultado y el script que funcionó. En futuras ejecuciones, el agente parte de ese script como base, reduciendo el número de iteraciones necesarias.

### Informe de explotación (`--report`)

Con `--report` se genera en `reports/<package>/`:

- `exploit_report_<package>.json` — resultados en formato máquina
- `exploit_report_<package>.pdf` — informe **AiPWN Agents** (bypass + exploit) con:
  - Contador de vulnerabilidades **CONFIRMADAS / NO CONFIRMADAS / OMITIDAS**
  - Resultado del bypass (script usado, screenshot)
  - Detalle por vulnerabilidad: evidencia, comando PoC, script Frida, impacto

Si existe un informe de análisis estático (`nutcracker_<package>_report.pdf`), los resultados del exploit se añaden como sección adicional al mismo PDF.
