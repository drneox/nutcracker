"""
frida_agent.py — Loop ReAct con function calling para bypass automático de protecciones.

El agente recibe:
  - Contexto inicial: análisis de la app, protecciones detectadas
  - Herramientas: leer código fuente, buscar clases, ejecutar Frida, reportar resultado

El agente decide autónomamente qué explorar, qué hookear y cómo corregir errores.
El historial de mensajes completo se mantiene en cada llamada al LLM.

Soporta:
  - OpenAI (gpt-4o, gpt-4-turbo, etc.)
  - Anthropic (claude-3-5-sonnet, etc.)
  - Ollama (llama3.1:70b, qwen2.5-coder, etc.) vía endpoint OpenAI-compatible
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from any_llm import completion as _llm_completion

from rich.console import Console
from rich.markup import escape as _escape

from .frida_agent_tools import (
    TOOL_SCHEMAS,
    ToolContext,
    dispatch_tool,
    tool_report_success,
)
from .frida_capture import FridaRunResult, check_app_installed, launch_frida_capture
from .agent_memory import (
    build_memory_context,
    clear_resume_state,
    load_sessions,
    save_resume_state,
    save_session,
)
from nutcracker_core.i18n import t
from . import print_agent_says as _print_agent_says, print_agent_thinking as _print_agent_thinking

if TYPE_CHECKING:
    from .analyzer import AnalysisResult

console = Console()

# Tools que ejecutan Frida de verdad y por lo tanto consumen un slot de
# max_frida_runs -- "run_frida_script" e "intercept_and_modify" (MITM activo,
# también corre vía ctx.on_frida_run). Antes solo se chequeaba el nombre
# "run_frida_script" a mano en 3 lugares del loop de abajo; con el set nuevo,
# cualquier tool que se agregue a este grupo en el futuro queda gateada por
# el mismo límite de presupuesto sin tener que tocar el loop de nuevo.
_FRIDA_SLOT_TOOL_NAMES = frozenset({"run_frida_script", "intercept_and_modify"})

# Respuestas consecutivas del LLM sin ningún tool call que se toleran antes de
# abortar la corrida (cada una recibe un nudge pidiéndole que actúe — ver el
# loop del agente). Típicamente el modelo se quedó sin max_tokens a mitad de
# un razonamiento largo y la respuesta se cortó antes de la tool call.
_MAX_NO_TOOLCALL_STREAK = 3

# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are an expert Android security researcher specialized in bypassing app protections with Frida.

Your goal is to bypass ALL active protections in the target app (SSL pinning, root detection, \
anti-Frida, emulator detection, signature verification) so that network traffic can be intercepted and the app \
functions without integrity failures.

## Bypass Strategy — Three Phases (MUST follow in order)

### Phase 1: Java-level bypass

1. Call `get_app_analysis` to understand what protections are detected.
2. **Call `get_heuristic_bypass_script`** — this CACHES a battle-tested base script server-side \
   with proven hooks for: File.exists (root paths), Runtime.exec, PackageManager (Magisk/SuperSU), \
   Google Play/GMS spoofing, Build fields spoof, SystemProperties, RootBeer, ClassLoader deferred \
   hooking, Instrumentation.callActivityOnCreate (blocks restriction screens), TelephonyManager \
   (IMEI/IMSI spoof), PairIP LicenseClient, AlertDialog security dialog blocking, finishAffinity, \
   Socket port 27042/27043, File.listFiles(/proc), File.exists for root paths AND emulator detection \
   paths (/dev/socket/qemud, /dev/qemu_pipe, /sys/qemu_trace, /dev/goldfish_pipe), and Frida detection hiding. \
   You receive only a summary. **Do NOT copy the script — it is applied automatically.**
3. **If SSL pinning is detected**, call `get_certificate_pins` immediately after `get_heuristic_bypass_script`. \
   It reads `network_security_config.xml`, embedded certs, and OkHttp/TrustKit patterns from static files — \
   no Frida run needed. The `hook_recommendation` field tells you exactly which class/method to hook.
4. **MANDATORY before running any script**: Either call `probe_security_violations` (preferred for \
   unknown/obfuscated apps — captures exact stack trace at the moment of blocking, no name guessing needed) \
   OR call `read_decompiled_class` on the app's main entry point (MainActivity, Application subclass). \
   Look for custom RASP/Frida/root/emulator detection methods — these are NOT covered by the base script \
   unless they follow standard patterns. Any custom `detectFrida()`, `runRaspChecks()`, or obfuscated \
   equivalents MUST be individually hooked. **Skip this only if the app has no decompiled source AND \
   probe_security_violations returns no violations.**
5. Call `list_classes_matching` with keywords relevant to the protections found in `get_app_analysis`. \
   Prioritize what was detected: if SSL pinning was found, search ssl/certificate/trust/pinning first; \
   if root detection, search root/check/detect/verify; if signature, search signature/tamper/integrity. \
   Only expand to broader keywords (emulator, device, build, safe, protect) if the targeted search is insufficient. \
   **STOP after 3–5 `list_classes_matching` calls** — do not exhaustively search every keyword.
5. **If decompiled source is incomplete or classes are missing/obfuscated**, call \
   `enumerate_runtime_classes` with the same keywords to find the real runtime class names.
6. Call `get_class_methods` on every candidate class before writing a hook — get exact method \
   signatures and parameter types to avoid overload guessing.
7. Write ONLY the additional hooks needed (SSL pinning, signature check, custom RASP methods, etc.) — NOT the full base. \
   **ALWAYS include this FLAG_SECURE bypass in every Phase 1 script** so that `take_screenshot` works from the start \
   (banking apps routinely set `FLAG_SECURE`; this hook is harmless if the flag is not used): \
   `Java.perform(function(){try{var W=Java.use('android.view.Window');W.setFlags.overload('int','int').implementation=function(f,m){f&=~0x2000;return this.setFlags(f,m);};}catch(e){}});`
8. Call `run_frida_script` with `extend_heuristic_base=true` and your small additional script. \
   **You should reach step 8 within 8–10 tool calls total. If you haven't run a script yet by \
   tool call 10, stop analyzing and run the best available script now.**

### Phase 2: Native-level escalation (REQUIRED when Java hooks are insufficient)

**You MUST escalate to Phase 2 if a `run_frida_script` result returns `security_blocked=True`, \
`app_running=False` after the app had time to start, `app_crashed=True`, or non-empty `hooks_failed` \
entries for SSL-related hooks. DO NOT call report_failure before completing Phase 2. \
DO NOT go back to more static analysis — go directly to Phase 2 tools.**

**Before using Interceptor.attach on native functions**: Call `resolve_native_symbol` with the \
function names you plan to hook. If any address is null or throws "TypeError: not a function", \
`Interceptor.attach` will fail. Use only the addresses confirmed as interceptable.

9. Call `get_loaded_native_libs` to discover which .so files the app has loaded \
   (libssl.so, libconscrypt_jni.so, libboringssl.so, libssl_bridge.so, vendor-specific .so files, etc.).
10. For any unfamiliar vendor .so (not a well-known SSL library), call `strings_native_lib` with \
    filter keywords like "ssl", "cert", "pin", "verify" to quickly understand what it does \
    without spending a Frida run. If strings reveal it's a security library, include it in step 11.
11. Call `enumerate_native_exports` for each relevant SSL/security library with patterns: \
    "ssl", "verify", "cert", "pin", "trust", "check".
12. Write a Frida script that combines Java hooks (Phase 1) with native Interceptor.attach hooks \
    on the SSL functions found. Common targets: `SSL_CTX_set_verify`, `SSL_do_handshake`, \
    `SSL_verify_cert_chain`, `X509_verify_cert`, `CONSCRYPT_checkServerTrusted`.
13. Call `run_frida_script` with the combined script.

### Phase 3: Universal fallback (REQUIRED when specific hooks still fail)

**You MUST attempt Phase 3 if Phases 2 and 2b still return security_blocked=True or app_running=False.**

13. Try reflection-based SSL bypass: hook `javax.net.ssl.HttpsURLConnection` \
    setSSLSocketFactory, `okhttp3.OkHttpClient.Builder` class constructor, \
    and use `Java.deoptimizeEverything()` before hooks to force JIT-interpreted mode.
14. If signature verification is blocking: hook `android.content.pm.PackageManager.getPackageInfo` \
    and spoof the signature.
15. Call `run_frida_script` with this universal bypass.

### Termination

16. **CRITICAL — Success confirmation rule**: After ANY `run_frida_script` call, if \
    `bypass_confirmed=true`, call `take_screenshot` FIRST to visually confirm the app screen \
    looks normal. Analyze the screenshot carefully:\
    \n    **✔ PASS (call `report_success`)**: Any of the following qualifies — call \
    `report_success` immediately WITHOUT taking extra screenshots or calling `sniff_network_calls`:\
    \n      - App shows a functional screen: login form, home screen, dashboard, menu, or \
    any interactive UI with buttons/fields, text labels, navigation elements.\
    \n      - **App's branded color scheme is visible AND a content panel/card/form area is \
    present** — e.g. teal/green background + white login panel, blue background + card, \
    brand logo + input fields. If you can see the brand's signature color AND a non-empty content \
    area, that IS a successful bypass even if individual labels are not fully legible.\
    \n      - You can describe at least one specific UI element (button label, text, icon, \
    form field, or recognizable brand color + content area combination).\
    \n    **✘ FAIL — keep bypassing, do NOT call `report_success`**:\
    \n      - Security dialog, "rooted device" / "security violation" / "integrity check failed" message\
    \n      - Block screen or hard PIN/password prompt injected by the app\
    \n      - **Splash screen that is stuck / frozen / looping** — a splash screen visible for \
    more than a few seconds means the app is hanging at startup, likely blocked by a backend \
    integrity check, certificate pinning still active, or a native RASP watchdog. \
    A splash screen is NOT a successful bypass — treat it the same as a block screen.\
    \n      - Black screen, dark screen, or blank white screen — even if the app uses a dark theme, \
    a PASS requires visible UI elements (text, buttons, icons). A dark screen with no discernible \
    UI elements is NOT a successful bypass. Do NOT rationalize a dark/black screen as "dark theme".\
    \n      - Loading spinner that never resolves\
    \n      - Any screen where you cannot name a specific UI element visible on screen\
    \n    **MANDATORY before calling `report_success`**: State explicitly what you see. Any of \
    these is sufficient — call `report_success` immediately once you can state one of them:\
    \n      (a) A specific interactive element: button, input field, label, icon (e.g. "login \
    button labeled Ingresar", "email field", "navigation bar with 3 tabs").\
    \n      (b) The app's branded color scheme + a non-empty content area (e.g. "teal background \
    with a white login panel", "blue header with a card below it", "brand logo + form area").\
    \n    If you can state EITHER (a) OR (b), call `report_success` — do NOT take more screenshots \
    or call sniff_network_calls first.\
    \n    **ABSOLUTELY FORBIDDEN reasoning patterns** — these arguments do NOT override the \
    visual check and MUST NOT be used to justify `report_success`:\
    \n      - "bypass_confirmed=true therefore the bypass succeeded" — bypass_confirmed only \
    means Frida hooks ran; it says nothing about the app UI being functional.\
    \n      - "app_running=true therefore the app is working" — a stuck loading screen also \
    has app_running=true.\
    \n      - "past sessions / previous runs showed this as success" — you have no memory of \
    past sessions; any claim about past sessions is a hallucination. Ignore it.\
    \n      - "the dark/white/light color is the app's theme" — theme color is irrelevant; \
    what matters is whether interactive UI elements are visible.\
    \n      - "no security dialog therefore bypass succeeded" — absence of a block screen is \
    necessary but NOT sufficient; a functional screen is required.\
    \n      - "the screenshot is too small / low resolution, let me take another one" — if you \
    can already see the app's branded colors AND a content panel, the resolution does not matter. \
    Taking another screenshot or calling sniff_network_calls to 'verify further' when branded \
    UI is already visible is FORBIDDEN. Call `report_success` immediately.\
    \n      - "I want to verify the app has fully loaded its React Native / Flutter / native UI" — \
    React Native bundle load time is not your concern. If branded colors + content area = loaded.\
    \n      - "let me check if the app is still running" — if you just saw a branded screen with \
    a content panel, the app is clearly running. Do NOT call any extra tool; call `report_success`.\
    \n    **When you see a stuck splash screen or dark screen**: call `sniff_network_calls` to \
    check if an HTTP request is failing (SSL error, 401, 403, server-side jailbreak check), OR \
    call `get_frida_output_history` to look for logcat errors. Then continue bypassing accordingly.\
    \n    **`bypass_confirmed=false` is final** — do NOT call `report_success` manually based on \
    your own reasoning. If `app_crashed=True` appears without `app_running=True`, that is a \
    real crash (FATAL EXCEPTION or SIGKILL) of the target package. If `app_running=True` and \
    `app_crashed=True`, escalate to Phase 2 to identify the crash cause from `crash_lines`.
17. If bypass succeeded → call `report_success`.
18. Only call `report_failure` if ALL THREE phases have been attempted AND all available Frida run \
    slots have been used. If you still have unused slots, keep trying variations. The failure report \
    MUST include what each phase found and why each approach failed.

## Diagnostic tools (do NOT consume Frida run slots — use freely)

- **`take_screenshot`** — capture the device screen right now and analyze it visually. Use this \
  whenever you want to see what is on screen: security dialogs, blocked UI, error messages, PIN \
  prompts, or any visual state. The image is sent directly to you for analysis. Does NOT count \
  as a Frida run. Use it freely.
- **`probe_security_violations`** — use this FIRST when you don't know where the security check lives. \
  Hooks System.exit, finishAffinity, Process.killProcess and AlertDialog.setCancelable(false), captures \
  the Java stack trace at the exact moment of the block, and filters to app-package frames only. \
  The result tells you the exact class+method that triggered the block — works on obfuscated apps too. \
  Call this before static analysis when protections are unknown or obfuscated.
- **`sniff_network_calls`** — use when the app passes hooks but freezes on splash screen or makes \
  no visible progress. Reveals which HTTP request is failing (SSL error, 4xx/5xx, timeout).
- **`trace_method_execution`** — use when you don't know which code path triggers a detection. \
  Stalker reveals the exact execution path inside a class or method.
- **`get_frida_output_history`** — use when you need the full untruncated stdout + logcat of a \
  previous run. Call with `run_index=-1` for the last run.
- **`resolve_native_symbol`** — resolve native symbol addresses at runtime and test if \
  `Interceptor.attach` works on them. Call this BEFORE writing native hooks when you got \
  "TypeError: not a function" — it shows whether the address is null (symbol not exported), \
  points to an un-interceptable stub, or is truly interceptable. Does NOT count as a Frida run.
- **`pull_apk_from_device`** — extract ALL APKs (base + splits) from the device via `adb pull`. \
  IMPORTANT: `libloader.so` and other native libs are often in `split_config.arm64_v8a.apk`, \
  NOT in `base.apk`. Call this before `disassemble_native_lib` or `patch_native_lib` if they \
  report "not found". Does NOT count as a Frida run.
- **`disassemble_native_lib`** — extract a .so from ANY split APK and disassemble at a specific \
  file offset. Use after a SIGSEGV to understand what instruction is at the crash site. \
  Requires radare2 or objdump. Does NOT count as a Frida run.
- **`relaunch_with_gadget`** — use when `anti_frida_detected=true`. Auto-pulls ALL split APKs \
  if not locally available. For React Native apps, prefer `apk-mitm` over `objection` \
  (`npm install -g apk-mitm`). Consumes ONE Frida run slot.
- **`patch_native_lib`** — permanently patch bytes in a .so inside any split APK, repackage, \
  sign and reinstall. For RASP that runs before Frida attaches. Call `disassemble_native_lib` \
  first. Consumes ONE Frida run slot.

## Important rules

- **EVERY response MUST start with 1-3 sentences of reasoning in plain text explaining what you \
  are doing and why, THEN end with exactly one tool call.** This reasoning is shown to the operator.
- **NEVER skip the reasoning text. NEVER respond with a tool call only.**
- **MUST call `report_success` or `report_failure` eventually. These are mandatory.**
- **ALWAYS call `get_heuristic_bypass_script` before writing any script. It is the mandatory base.**
- ALWAYS read the decompiled source code or inspect classes BEFORE adding hooks on top of the base.
- When a class is obfuscated (short names like 'a', 'b', 'c'), use `enumerate_runtime_classes` \
  with patterns like 'trust', 'ssl', 'root' to find the real runtime class names.
- Use `get_class_methods` to get exact signatures before writing overload hooks — never guess.
- **Calling the original method**: ALWAYS store the overload in a variable and call it with `.call(this, ...)`. \
  NEVER call `this.methodName(...)` inside an `implementation` — that calls the hook itself (infinite recursion). \
  Correct pattern: `var orig = Cls.method.overload(...); orig.implementation = function(a, b) { return orig.call(this, a, b); };`
- When `run_frida_script` returns non-empty `hooks_failed`, use `get_class_methods` to verify exact signatures.
- **`Interceptor.attach` TypeError diagnosis**: "TypeError: not a function" means the address \
  resolved to null or points to an un-interceptable syscall stub. Call `resolve_native_symbol` \
  FIRST to confirm the address is valid before any native Interceptor.attach. If the address is \
  null, the symbol is not exported — try the `__` prefixed variant (`__kill`, `__tgkill`) or \
  use `Memory.scanSync` on libc to find the instruction sequence manually.
- **NEVER use `Module.findExportByName(lib, sym)` or `Module.getExportByName(lib, sym)` (the \
  static, two-argument form) — REMOVED in Frida 17, throws "TypeError: not a function" \
  immediately (confirmed live, 2026-08-21, Frida 17.16.4) even though this exact pattern is the \
  most common one in older tutorials/training data. If you write this and get "TypeError: not a \
  function" right at that line (not inside `Interceptor.attach`), THIS is the cause, not an \
  invalid address. Use instead: `Module.findGlobalExportByName(sym)` for a global search (returns \
  null if missing, matches the old `Module.findExportByName(null, sym)`), or \
  `Process.findModuleByName(lib)` (returns null if the module isn't loaded) then \
  `.findExportByName(sym)` on that module object for a specific library.
- **Split APK apps**: If `disassemble_native_lib` or `patch_native_lib` report "not found in APK", \
  the library lives in a split APK (e.g. `split_config.arm64_v8a.apk`). Call `pull_apk_from_device` \
  to download ALL splits — the tools then search across all of them automatically.
- **ClassLoader isolation**: If `hooks_failed` contains `ClassNotFoundException` for SSL/OkHttp/pinning classes, \
  those classes are in a custom class loader. Wrap those hooks using `Java.enumerateClassLoaders()` to find \
  the loader that contains the class, then set `Java.classFactory.loader = foundLoader` before calling \
  `Java.use()`. Do NOT skip these hooks — they are the active SSL pinning path.
- When `run_frida_script` returns `app_crashed=True`, read the `crash_lines` field in the result — \
  it contains the relevant exception and stack trace. Analyze it to identify the crashing class before acting.
- **DO NOT call `report_failure` just because Java hooks failed. Native hooks (Phase 2) are required first.**
- When bypassing SSL pinning, hook ALL TrustManager implementations found, not just the first one.
- For emulator detection: hook `Build` fields (FINGERPRINT, MODEL, MANUFACTURER, PRODUCT, BRAND, DEVICE), \
  `SystemProperties`, and any custom emulator-check classes. Return real device values.
- Use `Java.deoptimizeEverything()` at script start when dealing with heavily obfuscated apps.
- Each `run_frida_script` call consumes one of your limited execution slots. Use them wisely — \
  but exhausting them through genuine attempts is acceptable; calling report_failure early is not.

## Custom RASP method bypass patterns (use when heuristic base is not enough)

When you find a custom detection method in decompiled source, hook it based on its return type:
- Returns boolean (isRooted, isFrida, isEmulator, checkXxx, detectXxx) → return false
- Returns List/Collection of violations → return empty `java.util.ArrayList`
- Returns void but shows a blocking dialog → suppress it (no-op implementation)
- Returns int/enum security status → return 0 (OK/safe)

Read the source with `read_decompiled_class` first to identify the exact class name, method name, \
and return type. Then use `get_class_methods` to get exact signatures. Never guess.
"""

_PHASE2B_PROMPT = """\
## Phase 2b: RASP self-integrity bypass and DT_PREINIT_ARRAY evasion

You have triggered Phase 2b because one of the following signals was detected:
- SIGSEGV inside a native security library (RASP detected GOT/PLT hook)
- App terminates on Frida detach (native watchdog)
- `extend_heuristic_base=true` kills the app instantly but pure native scripts run fine (DT_PREINIT_ARRAY)

### Strategy A — Spawn gating (for DT_PREINIT_ARRAY RASP)
Use `spawn_gated=true` in `run_frida_script`. This pauses the process BEFORE any native library \
init runs. Your hooks execute before DT_PREINIT_ARRAY code. Do NOT combine with `extend_heuristic_base=true`.

Steps: intercept `android_dlopen_ext` or `dlopen` → on library load, use `Memory.patchCode()` to \
patch the integrity check entry point → write `RET` (ARM64: c0035fd6) or `MOV x0,#0; RET`.

### Strategy B — Memory.patchCode() (when Interceptor causes SIGSEGV in RASP lib)
Do NOT use `Interceptor.attach` when self-integrity is confirmed. Use `Memory.patchCode()` instead \
— it writes bytes directly to executable memory without touching the GOT/PLT.

ARM64 patch bytes: NOP=1f2003d5, RET=c0035fd6, MOV x0,#0;RET=000080d2+c0035fd6, MOV x0,#1;RET=200080d2+c0035fd6

Steps:
12a. `strings_native_lib` with the RASP library + keywords (frida, root, tamper, hook, cert, integrity). \
     JNI function names found (e.g. `Java_com_example_App_checkRoot`) can be used as `symbol_name` directly.
12b. `disassemble_native_lib` with `symbol_name` (from strings) or `offset` (from SIGSEGV crash address). \
     Identify the check type: CRC, conditional branch, kill(), SIGKILL raise.
12c. `run_frida_script` with `Memory.patchCode()` at the target offset + `extend_heuristic_base=true`.

### Strategy C — Permanent binary patch (when Memory.patchCode is insufficient)
Use `patch_native_lib` to modify the .so inside the APK before Frida attaches. Required when the \
RASP runs before the JVM starts or when it hashes its own code pages to detect in-memory patches.

Steps:
12d. `pull_apk_from_device` if APK not locally available.
12e. `disassemble_native_lib` to confirm the exact instruction at the target offset.
12f. `patch_native_lib` with library name, offset, and patch bytes — tool repackages, signs, reinstalls.
12g. `run_frida_script` — patched APK is already installed.

For the watchdog-on-detach pattern: find the detection branch with `disassemble_native_lib`, \
patch the conditional branch to NOP so the watchdog always reports clean.
"""

_CLASSLOADER_INTEGRITY_PROMPT = """\
## ClassLoader integrity bypass (DexGuard / custom APK tamper detection)

You have triggered ClassLoader integrity bypass because the app crashed or refused to load after \
APK repackaging (gadget injection or patch_native_lib). Signals: SecurityException with "tamper" \
or "signature", INSTALL_FAILED_TEST_ONLY, app crash immediately after relaunch_with_gadget, \
or Java.perform throws before any hook fires.

DexGuard and similar protectors verify APK signature inside the ClassLoader before decrypting classes. \
Repackaging breaks this check. Strategies below — apply in order:

### Strategy 1 — Spoof signature in-memory (no repackaging needed)
Use `run_frida_script` WITHOUT gadget (standard attach). Hook signature verification APIs so the \
app sees its original signature even when hooked:

- `android.content.pm.PackageManager.getPackageInfo` → intercept calls where flags include \
  GET_SIGNATURES (0x40) or GET_SIGNING_CERTIFICATES (0x8000000). Call the original, then \
  replace result.signatures with the original APK signatures captured before patching.
- `android.content.pm.Signature.toByteArray` → return the original signature bytes.
- `java.security.MessageDigest.digest` → if called on a Signature object, return the expected hash.

This avoids repackaging entirely — the app loads normally and your hooks run in the same process.

### Strategy 2 — Hook ClassLoader before integrity check (spawn gating)
Use `spawn_gated=true` in `run_frida_script`. Hook `dalvik.system.BaseDexClassLoader` constructor \
and `loadClass` to prevent the integrity check from running. With spawn gating your hook is active \
before DexGuard's ClassLoader initializes.

Target: `dalvik.system.DexClassLoader.$init` and `dalvik.system.PathClassLoader.$init` → \
call original then clear any pending integrity timer/flag set in the constructor.

### Strategy 3 — Find and patch the integrity check natively
If Strategies 1-2 fail, use `disassemble_native_lib` on the DexGuard native lib to find the \
signature comparison function, then `Memory.patchCode` to NOP the check. Combine with spawn gating.

Steps:
CL-1. Try Strategy 1 first — write a `run_frida_script` that hooks PackageManager.getPackageInfo \
      with `extend_heuristic_base=true`. This is the least invasive approach.
CL-2. If the app still crashes, switch to `spawn_gated=true` (Strategy 2). Do NOT use \
      extend_heuristic_base with spawn_gated.
CL-3. If both fail, call `strings_native_lib` on the DexGuard lib with keyword "signature" then \
      `disassemble_native_lib` to find the check, then `Memory.patchCode` (Strategy 3).
"""

_INITIAL_USER_MSG = """\
App package: {package}
Objective: bypass ALL active protections (SSL pinning, root detection, emulator detection, anti-Frida).
You have {max_runs} Frida execution slots available.
Decompiled source code: {decompiled_str}.
{analysis_context}
Start by calling `get_app_analysis` to see what protections were detected, then explore \
the relevant classes before writing any script.
"""


def _build_analysis_context(analysis_result: "AnalysisResult | None") -> str:
    """
    Serializa los resultados del análisis estático en un bloque de contexto
    para el mensaje inicial del agente. Genérico — no hardcodea estrategias.
    """
    if analysis_result is None:
        return ""

    detected = [r for r in analysis_result.results if r.detected]
    if not detected:
        return ""

    lines = ["Protections detected by static analysis (use this to guide your strategy):"]
    for r in detected:
        detail_str = "; ".join(r.details[:5]) if r.details else "no details"
        lines.append(f"  - {r.name} [strength={r.strength}]: {detail_str}")

    return "\n".join(lines) + "\n"


# ── LLM Client ────────────────────────────────────────────────────────────────

class LLMClient:
    """
    Cliente LLM usando any-llm-sdk — soporta OpenAI, Anthropic y Ollama
    con una interfaz unificada sin código específico por provider.
    """

    def __init__(self, config: dict) -> None:
        self.provider = str(config.get("provider", "openai")).lower()
        self.model = str(config.get("model", "gpt-4o"))
        self._api_key: str | None = config.get("api_key") or None
        self._api_base: str | None = config.get("base_url") or None
        self.max_tokens = int(config.get("max_tokens", 4096))
        self._timeout = int(config.get("timeout", 120))

    def chat(
        self,
        messages: list[dict],
        tools: list[dict],
    ) -> "_LLMResponse":
        """Llama al LLM y retorna una respuesta normalizada."""
        # any-llm puede ignorar api_key kwarg en algunos providers; setear
        # la env var correspondiente es el mecanismo más fiable.
        if self._api_key:
            _ENV_VAR = {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "ollama": None,
            }.get(self.provider)
            if _ENV_VAR and not os.environ.get(_ENV_VAR):
                os.environ[_ENV_VAR] = self._api_key

        try:
            return self._do_completion(messages, tools)
        except Exception as e:
            # Si el error es por imágenes no soportadas, reintenta sin ellas
            if _is_vision_unsupported_error(e):
                _print_agent_says(t("aipwn_screenshot_no_vision_says"))
                messages_no_images = _strip_image_blocks(messages)
                return self._do_completion(messages_no_images, tools)
            raise

    def _do_completion(self, messages: list[dict], tools: list[dict]) -> "_LLMResponse":
        response = _llm_completion(
            model=self.model,
            provider=self.provider,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            max_tokens=self.max_tokens,
            api_key=self._api_key,
            api_base=self._api_base,
            client_args={"timeout": self._timeout},
        )
        msg = response.choices[0].message
        tool_calls = []
        # id -> arguments JSON string ya saneado (nunca el crudo truncado del modelo).
        # FIX (2026-08-03, verificado en vivo job 2809): _raw_msg más abajo releía
        # tc.function.arguments crudo del objeto del SDK, sin pasar por este
        # try/except -- si el modelo truncaba el JSON, el fallback a {} solo se
        # usaba para despachar la tool localmente, pero el string inválido quedaba
        # guardado para siempre en self.messages. Cada llamada siguiente reenviaba
        # ese mensaje roto y Azure lo rechazaba con el mismo 400 ("Assistant tool
        # call function.arguments must be valid JSON") en los 3 reintentos --
        # irrecuperable, mataba el job entero. Ahora ambos usos comparten el mismo
        # valor saneado.
        sanitized_args_json: dict[str, str] = {}
        if msg.tool_calls:
            for tc in msg.tool_calls:
                raw_args = tc.function.arguments or "{}"
                try:
                    arguments = json.loads(raw_args)
                    sanitized_args_json[tc.id] = raw_args
                except json.JSONDecodeError:
                    # Model returned truncated JSON — treat as empty args
                    arguments = {}
                    sanitized_args_json[tc.id] = "{}"
                tool_calls.append(_ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=arguments,
                ))

        # Extraer thinking blocks de Anthropic (content es lista en extended thinking)
        # y reasoning de DeepSeek thinking mode (any_llm normaliza a msg.reasoning.content).
        thinking_text = ""
        text_content = msg.content or ""
        # any_llm normaliza reasoning_content / thinking → msg.reasoning (objeto con .content)
        _reasoning_content: str | None = None
        _reasoning_obj = getattr(msg, "reasoning", None)
        if _reasoning_obj is not None:
            if isinstance(_reasoning_obj, dict):
                _reasoning_content = _reasoning_obj.get("content") or None
            else:
                _reasoning_content = getattr(_reasoning_obj, "content", None) or None
        if _reasoning_content:
            thinking_text = _reasoning_content
        elif isinstance(msg.content, list):
            thinking_parts = []
            text_parts = []
            for block in msg.content:
                if isinstance(block, dict):
                    if block.get("type") == "thinking":
                        thinking_parts.append(block.get("thinking", ""))
                    elif block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                elif hasattr(block, "type"):
                    if block.type == "thinking":
                        thinking_parts.append(getattr(block, "thinking", ""))
                    elif block.type == "text":
                        text_parts.append(getattr(block, "text", ""))
            thinking_text = "\n".join(thinking_parts)
            text_content = "\n".join(text_parts)

        # Construir raw_message para el historial.
        # DeepSeek thinking mode requiere que reasoning_content se devuelva en cada turno.
        _raw_msg: dict = {
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": sanitized_args_json[tc.id],
                    },
                }
                for tc in (msg.tool_calls or [])
            ] or None,
        }
        if _reasoning_content:
            _raw_msg["reasoning_content"] = _reasoning_content

        return _LLMResponse(
            content=text_content,
            thinking=thinking_text,
            tool_calls=tool_calls,
            raw_message=_raw_msg,
        )


@dataclass
class _ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class _LLMResponse:
    content: str
    thinking: str  # thinking blocks de Anthropic extended thinking (vacío para otros providers)
    tool_calls: list[_ToolCall]
    raw_message: dict  # para añadir al historial


# ── Resultado del agente ──────────────────────────────────────────────────────

@dataclass
class AgentResult:
    success: bool
    script_path: Path | None
    explanation: str
    failure_reason: str
    frida_runs: int
    iterations: int
    last_frida_result: FridaRunResult | None
    screenshot_path: Path | None = None


# ── Agente ────────────────────────────────────────────────────────────────────

# ── Agente ────────────────────────────────────────────────────────────────────────
class FridaAgent:
    """
    Agente ReAct con function calling para bypass autónomo de protecciones Android.
    """

    def __init__(
        self,
        package: str,
        decompiled_dir: Path | None,
        analysis_result: "AnalysisResult | None",
        config: dict,
        serial: str | None = None,
        frida_host: str | None = None,
        max_frida_runs: int = 5,
        max_llm_iterations: int = 30,
        capture_seconds: int = 30,
        scripts_dir: Path = Path("frida_scripts"),
        runtime_dump_dir: Path | None = None,
        resume_state: dict | None = None,
        extra_iterations: int = 0,
    ) -> None:
        """``resume_state`` (de ``agent_memory.load_resume_state()``) continúa
        una sesión previa que terminó sin conclusión (límite de iteraciones,
        LLM sin tool_calls, error de LLM) en vez de arrancar una conversación
        nueva -- ver botón "+N iteraciones" del dashboard. ``extra_iterations``
        extiende el presupuesto exactamente esa cantidad más allá de donde se
        cortó (no reinicia a ``max_llm_iterations`` desde cero: si ya estaba en
        la iteración 31 con extra_iterations=5, el nuevo tope queda en 36)."""
        self.package = package
        self.max_frida_runs = max_frida_runs
        self.last_frida_result: FridaRunResult | None = None

        if resume_state:
            self.frida_runs_used = int(resume_state.get("frida_runs_used", 0))
            self.iteration = int(resume_state.get("iteration", 0))
            self.max_llm_iterations = self.iteration + max(1, extra_iterations)
        else:
            self.frida_runs_used = 0
            self.iteration = 0
            self.max_llm_iterations = max_llm_iterations

        llm_config = config.get("llm", {})
        self.llm = LLMClient(llm_config)
        aipwn_config = config.get("aipwn", {})
        self.show_thinking: bool = bool(aipwn_config.get("show_thinking", True))

        self._iters_since_last_run: int = 0  # iteraciones LLM sin run_frida_script
        self._no_toolcall_streak: int = 0  # respuestas LLM consecutivas sin tool_calls
        self._enumerated_patterns: set[str] = set()  # patrones ya buscados con enumerate_runtime_classes

        self.ctx = ToolContext(
            package=package,
            decompiled_dir=decompiled_dir,
            analysis_result=analysis_result,
            serial=serial,
            frida_host=frida_host,
            capture_seconds=capture_seconds,
            scripts_dir=scripts_dir,
            on_frida_run=self._execute_frida,
            runtime_dump_dir=runtime_dump_dir,
        )

        self._phase2b_injected: bool = False  # inyectar Phase2b solo una vez
        self._classloader_injected: bool = False  # inyectar ClassLoader bypass solo una vez
        self._last_screenshot_path: Path | None = None  # último PNG guardado a disco
        self._hooks_failed_all: list[str] = []
        self._key_classes_seen: list[str] = []
        self._runtime_classes_seen: list[str] = []  # nombres CONFIRMADOS en runtime (de enumerate_runtime_classes)

        if resume_state:
            # Continúa la conversación tal cual quedó -- no reconstruye el
            # prompt inicial ni vuelve a inyectar memoria (ya está adentro de
            # los mensajes guardados).
            self.messages: list[dict] = list(resume_state.get("messages", []))
        else:
            self.messages = [
                {"role": "system", "content": _SYSTEM_PROMPT},
            ]

            # Mensaje inicial con contexto
            initial = _INITIAL_USER_MSG.format(
                package=package,
                max_runs=max_frida_runs,
                decompiled_str=(
                    "available" if (decompiled_dir is not None and decompiled_dir.exists())
                    else "NOT available"
                ),
                analysis_context=_build_analysis_context(analysis_result),
            )
            self.messages.append({"role": "user", "content": initial})

            # ── Memoria persistente ──────────────────────────────────────────
            _sessions = load_sessions(package)
            _mem_ctx = build_memory_context(_sessions)
            if _mem_ctx:
                self.messages.append({"role": "user", "content": _mem_ctx})

    def _save_memory(self, outcome: str, notes: str = "") -> None:
        """Persiste la sesión actual. Seguro de llamar más de una vez (idempotente en cuanto a datos)."""
        _protections = [
            r.name for r in (self.ctx.analysis_result.results if self.ctx.analysis_result else [])
            if r.detected
        ]
        save_session(
            package=self.package,
            outcome=outcome,
            frida_runs=self.frida_runs_used,
            iterations=self.iteration,
            protections=_protections,
            working_hooks=[],
            failed_hooks=list(dict.fromkeys(self._hooks_failed_all)),
            key_classes=self._key_classes_seen[:20],
            notes=notes[:2000],
            runtime_classes=self._runtime_classes_seen[:30] or None,
        )

    def _prune_messages(self, max_chars: int = 60_000) -> None:
        """
        Recorta el historial de mensajes si supera max_chars estimados.
        Estrategia: truncar el contenido de resultados de herramientas (role=tool)
        antiguos, preservando siempre el system, el primer user, y los últimos 4 mensajes.
        """
        total = sum(len(str(m.get("content") or "")) for m in self.messages)
        if total <= max_chars:
            return

        # Indices protegidos: system (0), primer user (1), últimos 4 mensajes
        protected = {0, 1, len(self.messages) - 1, len(self.messages) - 2,
                     len(self.messages) - 3, len(self.messages) - 4}

        for i, msg in enumerate(self.messages):
            if total <= max_chars:
                break
            if i in protected:
                continue
            if msg.get("role") == "tool" and isinstance(msg.get("content"), str):
                original_len = len(msg["content"])
                # Mantener los primeros 300 chars del resultado (suficiente para contexto)
                msg["content"] = msg["content"][:300] + "\n[... truncated to save context ...]"
                total -= original_len - len(msg["content"])

        if total > max_chars:
            console.print(f"[yellow][aipwn] {t('aipwn_context_pruned', kb=total // 1000)}[/yellow]")

    def _check_operator_chat(self) -> None:
        """Wiring del dashboard (Fase 3, follow-up de plan.md): si esta corrida
        fue lanzada por el dashboard como job de la cola, `NUTCRACKER_DASHBOARD_URL`
        apunta a su API local. Antes de cada turno del LLM, hace un poll
        best-effort del mailbox de chat de este package y, si hay mensajes
        pendientes del operador, los inyecta en la conversación como un
        mensaje `user` real -- el LLM los ve y puede actuar en consecuencia
        en su siguiente respuesta.

        Sin dashboard corriendo (uso normal por CLI, la inmensa mayoría de las
        corridas), la env var no existe y esto es un no-op inmediato: ningún
        costo ni comportamiento nuevo para el flujo existente. Cualquier fallo
        de red (dashboard caído, timeout) se ignora en silencio -- el agente
        nunca debe abortar por un problema de este canal opcional.
        """
        dashboard_url = os.environ.get("NUTCRACKER_DASHBOARD_URL")
        if not dashboard_url:
            return
        try:
            import urllib.parse
            import requests

            url = f"{dashboard_url.rstrip('/')}/api/chat/{urllib.parse.quote(self.package, safe='')}/pending"
            # Si el dashboard tiene login activado, autenticamos con el token
            # interno inyectado por env (ver plugins/dashboard/__init__.py) --
            # sin esto el middleware de auth rechazaría este poll con 401.
            headers = {}
            _token = os.environ.get("NUTCRACKER_DASHBOARD_TOKEN")
            if _token:
                headers["X-Nutcracker-Token"] = _token
            resp = requests.get(url, timeout=2, headers=headers)
            if resp.status_code != 200:
                return
            messages = resp.json().get("messages", [])
        except Exception:
            return
        for text in messages:
            console.print(f"[bold magenta][operador][/bold magenta] {_escape(text)}")
            self.messages.append({
                "role": "user",
                "content": f"[Message from the human operator, via the dashboard chat] {text}",
            })

    def _execute_frida(
        self,
        script_js: str,
        rationale: str,
        iteration: int,
    ) -> FridaRunResult:
        """Callback invocado por tool_run_frida_script."""
        self.frida_runs_used += 1
        console.print(
            f"\n[bold cyan][aipwn][/bold cyan] "
            f"{t('aipwn_frida_run_counter', current=self.frida_runs_used, total=self.max_frida_runs)}"
        )
        result = launch_frida_capture(
            package=self.package,
            script_js=script_js,
            serial=self.ctx.serial,
            frida_host=self.ctx.frida_host,
            duration=self.ctx.capture_seconds,
            iteration=self.frida_runs_used,
        )
        self.last_frida_result = result
        console.print(f"[dim]  [aipwn] {result.summary()}[/dim]", markup=False)
        return result

    def run(self) -> AgentResult:
        """Ejecuta el loop ReAct hasta que el agente termina o se agota el presupuesto."""
        console.print(
            f"\n[bold green][aipwn][/bold green] "
            f"{t('aipwn_agent_starting', package=self.package)}"
        )
        console.print(
            f"[dim]  LLM: {self.llm.model} {t('aipwn_via')} {self.llm.provider} | "
            f"{t('aipwn_max_runs')}={self.max_frida_runs}[/dim]\n"
        )

        # ── Verificar que la app está instalada antes de llamar al LLM ──────
        _adb = shutil.which("adb")
        _adb_args = [_adb] + (["-s", self.ctx.serial] if self.ctx.serial and _adb else [])
        if _adb and not check_app_installed(_adb_args, self.package):
            msg = t('aipwn_app_not_installed', package=self.package)
            console.print(f"[bold red][aipwn] {msg}[/bold red]")
            return AgentResult(
                success=False,
                script_path=None,
                explanation=msg,
                failure_reason=msg,
                frida_runs=0,
                iterations=0,
                last_frida_result=None,
            )

        final_script_path: Path | None = None
        final_explanation = ""
        final_failure = ""
        terminated = False
        # True en los cortes SIN conclusión (límite de iteraciones, LLM sin
        # tool_calls, error de LLM) -- esos son los que se pueden reanudar con
        # el botón "+N iteraciones" del dashboard. False en report_success/
        # report_failure (terminated=True): ahí el agente sí concluyó, no hay
        # nada que continuar.
        resumable = False

        while not terminated:
            self.iteration += 1

            if self.iteration > self.max_llm_iterations:
                console.print(
                    f"[yellow][aipwn] LLM iteration limit ({self.max_llm_iterations}) reached.[/yellow]"
                )
                final_failure = f"LLM iteration limit ({self.max_llm_iterations}) reached without conclusion."
                resumable = True
                break

            # Pruning: recortar resultados de herramientas antiguas si el contexto es muy grande
            self._prune_messages()

            # Wiring del dashboard (Fase 3): inyectar mensajes del operador si
            # esta corrida viene de un job de la cola lanzado por el dashboard.
            self._check_operator_chat()

            # Presión anti-bucle: umbral dinámico = max_llm_iterations // 3 (mínimo 3)
            _pressure_threshold = max(3, self.max_llm_iterations // 3)
            if self._iters_since_last_run >= _pressure_threshold and self.frida_runs_used < self.max_frida_runs:
                pressure = (
                    f"[SYSTEM] You have spent {self._iters_since_last_run} iterations exploring "
                    "without calling run_frida_script. STOP exploring. You have enough information. "
                    "Write a Frida script NOW using everything you have found so far and call "
                    "run_frida_script immediately. Do not enumerate more classes, do not read more "
                    "decompiled code, do not call get_frida_output_history. ACT."
                )
                self.messages.append({"role": "user", "content": pressure})
                # NO resetear — pressure se repite cada iteración hasta que actúe

            console.print(f"[dim]  [agent] {t('aipwn_agent_calling_llm', iteration=self.iteration)}[/dim]")

            _llm_retries = 3
            response = None
            for _attempt in range(_llm_retries):
                try:
                    response = self.llm.chat(self.messages, tools=TOOL_SCHEMAS)
                    break
                except Exception as e:
                    import time as _time
                    _e_str = str(e)
                    # Credits exhausted / quota errors — no point retrying
                    _is_credits = any(x in _e_str for x in ("1302", "insufficient_quota", "credits", "billing"))
                    if _is_credits:
                        console.print(f"[red][aipwn] LLM quota/credits exhausted — stopping.[/red] {e}")
                        final_failure = f"LLM quota error: {e}"
                        break
                    # Prompt too long — prune aggressively and retry immediately
                    _is_too_long = any(x in _e_str for x in (
                        "1261", "max length", "prompt.*too long", "context.*too long",
                        "context_length_exceeded", "maximum context length",
                    ))
                    if _is_too_long and _attempt < _llm_retries - 1:
                        _prune_target = max(20_000, 60_000 // (2 ** (_attempt + 1)))
                        console.print(
                            f"[yellow][aipwn] Prompt too long — pruning to ~{_prune_target//1000}KB and retrying...[/yellow]"
                        )
                        self._prune_messages(max_chars=_prune_target)
                        continue  # retry immediately without sleep
                    if _attempt < _llm_retries - 1:
                        _is_rate_limit = "429" in _e_str or "rate limit" in _e_str.lower()
                        _delay = 10 * (2 ** _attempt) if _is_rate_limit else (2 ** (_attempt + 1))
                        console.print(
                            f"[yellow][aipwn] LLM error (attempt {_attempt + 1}/{_llm_retries}): {e} — retrying in {_delay}s...[/yellow]"
                        )
                        _time.sleep(_delay)
                    else:
                        console.print(f"[red][aipwn] {t('aipwn_llm_error')}[/red] {e}")
                        final_failure = f"LLM error: {e}"
            if response is None:
                resumable = True
                break

            # Añadir respuesta al historial
            self.messages.append(response.raw_message)

            if response.thinking and self.show_thinking:
                console.print()
                console.rule(f"[dim]{t('aipwn_thinking')}[/dim]", style="dim")
                console.print(response.thinking, style="dim italic")
                console.rule(style="dim")
                console.print()

            _display_content = response.content
            if not _display_content and response.thinking:
                # Model returned only thinking + tool call with no text block —
                # use last non-empty paragraph of thinking as reasoning preview
                _last_para = [p.strip() for p in response.thinking.split("\n\n") if p.strip()]
                _display_content = _last_para[-1] if _last_para else ""

            if _display_content and self.show_thinking:
                console.print(f'[bold cyan]{t("aipwn_nutcracker_says")}[/bold cyan] "{_escape(_display_content)}"')
            elif _display_content:
                console.print(f'[bold cyan]{t("aipwn_nutcracker_says")}[/bold cyan] "{_escape(_display_content[:300])}"')

            if not response.tool_calls:
                # El LLM respondió sin tool call — inesperado (visto en vivo:
                # se queda sin max_tokens a mitad de un razonamiento largo,
                # cortando la respuesta antes de llegar a la tool call, o
                # vuelca el script como texto plano). Antes esto abortaba la
                # corrida entera con un mensaje engañoso de "iteration limit"
                # (job 18, 2026-08-24: cortó en la llamada 11 con límite 40).
                # Ahora se le hace un nudge y se continúa; solo se corta tras
                # _MAX_NO_TOOLCALL_STREAK respuestas consecutivas sin tools.
                self._no_toolcall_streak += 1
                if self._no_toolcall_streak >= _MAX_NO_TOOLCALL_STREAK:
                    console.print(
                        f"[yellow][aipwn] {t('aipwn_agent_no_tool_calls_warn', n=self._no_toolcall_streak)}[/yellow]"
                    )
                    final_failure = t("aipwn_agent_no_tool_calls", n=self._no_toolcall_streak)
                    resumable = True
                    break
                console.print(
                    f"[yellow][aipwn] {t('aipwn_agent_no_tool_calls_nudge', n=self._no_toolcall_streak, max=_MAX_NO_TOOLCALL_STREAK)}[/yellow]"
                )
                self.messages.append({
                    "role": "user",
                    "content": (
                        "[SYSTEM] Your last response contained NO tool call. You MUST respond "
                        "with a tool call — never with plain text or code blocks. If you were "
                        "writing a Frida script, call run_frida_script with it NOW. Keep your "
                        "reasoning short so the tool call fits within the token budget."
                    ),
                })
                continue

            # Hubo tool calls — resetear la racha de respuestas sin herramientas
            self._no_toolcall_streak = 0

            # Ejecutar cada tool call
            for tc in response.tool_calls:
                console.print(f"[cyan][agent][/cyan] → {tc.name}({_pretty_args(tc.arguments)})")

                # Bloquear enumerate_runtime_classes si el patrón ya fue buscado
                if tc.name == "enumerate_runtime_classes":
                    pat = tc.arguments.get("pattern", "").strip().lower()
                    if pat in self._enumerated_patterns:
                        tool_result_content = (
                            f"[SYSTEM] Pattern '{pat}' was already searched with enumerate_runtime_classes. "
                            "Do not repeat the same search. Use the results you already have, "
                            "or search a different pattern, or write the Frida script now."
                        )
                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": tool_result_content,
                        })
                        continue
                    self._enumerated_patterns.add(pat)

                # Verificar límite de ejecuciones Frida
                if tc.name in _FRIDA_SLOT_TOOL_NAMES and self.frida_runs_used >= self.max_frida_runs:
                    tool_result_content = t(
                        "aipwn_frida_limit_reached", limit=self.max_frida_runs
                    )
                    console.print(f"[yellow][aipwn] {t('aipwn_frida_limit_msg')}[/yellow]")
                else:
                    tool_result_content, extra = dispatch_tool(
                        self.ctx,
                        tc.name,
                        tc.arguments,
                        self.frida_runs_used + 1,
                    )

                    if tc.name == "report_success":
                        final_script_path = extra
                        final_explanation = tc.arguments.get("explanation", "")
                        terminated = True

                    elif tc.name == "report_failure":
                        final_failure = tc.arguments.get("reason", "")
                        terminated = True

                    # Rastrear clases inspeccionadas para memoria persistente
                    if tc.name == "get_class_methods":
                        _cls = tc.arguments.get("class_name", "").strip()
                        if _cls and _cls not in self._key_classes_seen:
                            self._key_classes_seen.append(_cls)

                    # Capturar nombres runtime confirmados por enumerate_runtime_classes
                    if tc.name == "enumerate_runtime_classes" and isinstance(tool_result_content, str):
                        try:
                            import json as _json
                            _found = _json.loads(tool_result_content)
                            if isinstance(_found, list):
                                for _rc in _found[:50]:
                                    if isinstance(_rc, str) and _rc not in self._runtime_classes_seen:
                                        self._runtime_classes_seen.append(_rc)
                        except Exception:
                            pass

                    # Resetear contador cuando el agente ejecuta Frida
                    if tc.name in _FRIDA_SLOT_TOOL_NAMES:
                        self._iters_since_last_run = 0
                        # Acumular hooks fallidos para memoria persistente
                        if self.last_frida_result and self.last_frida_result.hooks_failed:
                            for _hf in self.last_frida_result.hooks_failed:
                                if _hf not in self._hooks_failed_all:
                                    self._hooks_failed_all.append(_hf)
                        # ── Detectar señales de Phase 2b e inyectar instrucciones ──────────
                        if not self._phase2b_injected:
                            try:
                                _rd = json.loads(tool_result_content)
                                _sigsegv_in_rasp = _rd.get("sigsegv_in_native_lib", False)
                                _instant_death = (
                                    _rd.get("app_running") is False
                                    and tc.arguments.get("extend_heuristic_base") is True
                                    and _rd.get("app_crashed") is False
                                )
                                _watchdog = _rd.get("terminated_on_detach", False)
                                if _sigsegv_in_rasp or _instant_death or _watchdog:
                                    self.messages.append({
                                        "role": "user",
                                        "content": _PHASE2B_PROMPT,
                                    })
                                    self._phase2b_injected = True
                            except Exception:
                                pass
                        # ── Detectar fallo de ClassLoader integrity tras repackaging ────────
                        if not self._classloader_injected and tc.name in (
                            "relaunch_with_gadget", "patch_native_lib", "run_frida_script"
                        ):
                            try:
                                _rd2 = json.loads(tool_result_content)
                                _crash_lines = " ".join(_rd2.get("crash_lines", [])).lower()
                                _classloader_signals = (
                                    "tamper" in _crash_lines
                                    or "signature" in _crash_lines
                                    or "install_failed_test_only" in _crash_lines
                                    or _rd2.get("classloader_integrity_failed", False)
                                    or (
                                        tc.name == "relaunch_with_gadget"
                                        and _rd2.get("app_crashed") is True
                                        and not _rd2.get("sigsegv_in_native_lib", False)
                                    )
                                )
                                if _classloader_signals:
                                    self.messages.append({
                                        "role": "user",
                                        "content": _CLASSLOADER_INTEGRITY_PROMPT,
                                    })
                                    self._classloader_injected = True
                            except Exception:
                                pass
                        # ── bypass_confirmed o fallo: construir hints para el LLM ────────
                        r = self.last_frida_result
                        hints: list[str] = []
                        if r and (r.success or r.bypass_confirmed):
                            hints.append(
                                "bypass_confirmed=True — the heuristic analysis indicates the bypass "
                                "succeeded. Before calling report_success, call take_screenshot to "
                                "visually confirm the app screen looks normal (no security dialog, "
                                "no block screen, no PIN prompt). If the screen looks good, call "
                                "report_success immediately. If you see a security dialog or block "
                                "screen, continue bypassing."
                            )
                        else:
                            # ── Hints para casos de fallo ───────────────────────────────────
                            try:
                                run_data = json.loads(tool_result_content)
                                if run_data.get("security_blocked"):
                                    if self.frida_runs_used <= 2:
                                        hints.append(
                                            "IMPORTANT: security_blocked=True — the heuristic base was not enough. "
                                            "The app has custom detection logic that requires manual hooks. "
                                            "Read the app's main entry point source (MainActivity, Application subclass) "
                                            "with read_decompiled_class to find custom detection methods. "
                                            "Then apply the Custom RASP bypass patterns from your instructions: "
                                            "boolean methods → return false, List<String> methods → return empty ArrayList, "
                                            "void dialog methods → no-op. Use extend_heuristic_base=true."
                                        )
                                    else:
                                        hints.append(
                                            f"IMPORTANT: security_blocked=True (Frida run {self.frida_runs_used}). "
                                            "Custom Java hooks are not enough — escalate to native hooks: "
                                            "Interceptor.attach on SSL/verify functions, Java.deoptimizeEverything(), "
                                            "Java.enumerateClassLoaders() for isolated class loaders. "
                                            "Run immediately, do NOT enumerate more classes."
                                        )
                                if not run_data.get("app_running") and not run_data.get("app_crashed"):
                                    hints.append(
                                        "IMPORTANT: app_running=False with no crash — the app exited silently. "
                                        "This is the strongest signal of active protection: the app detected "
                                        "something and self-terminated. Use enumerate_runtime_classes and "
                                        "get_class_methods to find the class responsible for this exit."
                                    )
                                if run_data.get("app_crashed"):
                                    hints.append(
                                        "IMPORTANT: app_crashed=True — see crash_lines in the result above "
                                        "for the exact exception and stack trace. Analyze the crash to "
                                        "identify the root cause before deciding on the next action. "
                                        "DO NOT call report_failure — a crash is a bypass opportunity."
                                    )
                                if run_data.get("emulator_detected"):
                                    hints.append(
                                        "IMPORTANT: emulator_detected=True — logcat shows explicit emulator "
                                        "detection. Use enumerate_runtime_classes('emulator') and "
                                        "enumerate_runtime_classes('device') to find the detection class."
                                    )
                                # ClassNotFoundException → custom class loader
                                hooks_failed = run_data.get("hooks_failed", [])
                                cnf_classes = [
                                    h for h in hooks_failed if "ClassNotFoundException" in h
                                ]
                                if cnf_classes:
                                    failed_names = ", ".join(
                                        h.split('"')[1] if '"' in h else h[:80]
                                        for h in cnf_classes[:5]
                                    )
                                    hints.append(
                                        f"IMPORTANT: {len(cnf_classes)} hook(s) failed with "
                                        f"ClassNotFoundException ({failed_names}). "
                                        "These classes exist in a CUSTOM CLASS LOADER, not the default one. "
                                        "In your next script, wrap those hooks with Java.enumerateClassLoaders() "
                                        "to find the correct loader and call Java.classFactory.loader = cl "
                                        "before Java.use(). Example pattern:\n"
                                        "  Java.enumerateClassLoaders({ onMatch: function(cl) {\n"
                                        "    try {\n"
                                        "      var cls = cl.loadClass('okhttp3.CertificatePinner');\n"
                                        "      Java.classFactory.loader = cl;\n"
                                        "      // hook here\n"
                                        "    } catch(e) {}\n"
                                        "  }, onComplete: function(){} });"
                                    )
                            except (json.JSONDecodeError, Exception):
                                pass

                        # Aplicar todos los hints (bypass_confirmed o fallo) al tool result
                        if hints:
                            tool_result_content = tool_result_content + "\n\n" + "\n".join(hints)

                # Añadir resultado de herramienta al historial
                self.messages.append(
                    _tool_result_message(tc, tool_result_content)
                )

                # Para take_screenshot: inyectar la imagen como mensaje de usuario
                # (los mensajes role=tool solo admiten texto; las imágenes van en role=user)
                # Si el modelo no soporta visión, LLMClient.chat() capturará el error
                # y reintentará sin los bloques de imagen automáticamente.
                if tc.name == "take_screenshot":
                    img_msg = _screenshot_image_message(
                        tool_result_content, self.llm.provider
                    )
                    if img_msg:
                        self.messages.append(img_msg)
                    # Extraer path del PNG guardado a disco por tool_take_screenshot
                    try:
                        import json as _j
                        _ss = _j.loads(tool_result_content).get("screenshot_path", "")
                        if _ss:
                            self._last_screenshot_path = Path(_ss)
                    except Exception:
                        pass

                if terminated:
                    break

            # Incrementar contador de iteraciones sin Frida sólo si no hubo run
            ran_frida = any(tc.name in _FRIDA_SLOT_TOOL_NAMES for tc in response.tool_calls)
            if not ran_frida:
                self._iters_since_last_run += 1
            # (reset ya ocurre dentro del loop de tool_calls cuando sí corre Frida)

        # ── Guardar bypass_result.json para el reporte posterior ────────────
        _write_bypass_result(
            package=self.package,
            success=final_script_path is not None,
            script_path=final_script_path,
            explanation=final_explanation or final_failure,
            screenshot_path=self._last_screenshot_path,
            frida_runs=self.frida_runs_used,
            iterations=self.iteration,
        )

        # ── Guardar sesión en memoria persistente ─────────────────────────
        self._save_memory(
            outcome="success" if final_script_path is not None else "failure",
            notes=final_explanation or final_failure,
        )

        # ── Estado de reanudación (botón "+N iteraciones" del dashboard) ────
        # Solo en cortes sin conclusión (ver el flag `resumable` arriba). Un
        # report_success/report_failure real limpia cualquier sesión pendiente
        # vieja -- ya no hay nada que continuar.
        if resumable:
            save_resume_state(
                package=self.package,
                messages=self.messages,
                frida_runs_used=self.frida_runs_used,
                iteration=self.iteration,
            )
        else:
            clear_resume_state(self.package)

        return AgentResult(
            success=final_script_path is not None,
            script_path=final_script_path,
            explanation=final_explanation,
            failure_reason=final_failure,
            frida_runs=self.frida_runs_used,
            iterations=self.iteration,
            last_frida_result=self.last_frida_result,
            screenshot_path=self._last_screenshot_path,
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_bypass_result(
    package: str,
    success: bool,
    script_path: "Path | None",
    explanation: str,
    screenshot_path: "Path | None",
    frida_runs: int,
    iterations: int,
) -> None:
    """
    Escribe reports/<package>/bypass_result.json con los datos del bypass
    para que ExploitAgent / el generador de PDF los consuma después.
    """
    import datetime
    import json as _json
    out_dir = Path("reports") / package
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "package": package,
        "success": success,
        "script_path": str(script_path) if script_path else "",
        "explanation": explanation,
        "screenshot_path": str(screenshot_path) if screenshot_path else "",
        "frida_runs": frida_runs,
        "iterations": iterations,
        "timestamp": datetime.datetime.now().isoformat(),
    }
    out_path = out_dir / "bypass_result.json"
    out_path.write_text(_json.dumps(payload, indent=2, ensure_ascii=False))


def _relaunch_persistent(script_path: Path, package: str, serial: str | None, frida_host: str | None = None) -> None:
    """
    Re-lanza el script de bypass en modo attach (-n) en background para que la app
    permanezca abierta y hooked tras el bypass exitoso.
    Modo attach: se conecta al proceso ya corriendo sin reiniciarlo.
    """
    import subprocess
    import sys

    frida_bin = str(Path(sys.executable).parent / "frida")
    if not Path(frida_bin).exists():
        frida_bin = shutil.which("frida") or ""
    if not frida_bin:
        return

    if frida_host:
        cmd = [frida_bin, "-H", frida_host, "-n", package, "-l", str(script_path)]
    elif serial:
        cmd = [frida_bin, "-D", serial, "-n", package, "-l", str(script_path)]
    else:
        cmd = [frida_bin, "-U", "-n", package, "-l", str(script_path)]

    console.print(
        f"[dim][aipwn] Re-attaching with bypass script to keep app alive and hooked...[/dim]"
    )
    try:
        # Lanzar en background — no bloqueamos, la app queda hooked hasta que el usuario salga
        subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        console.print(f"[yellow][aipwn] Re-attach warning: {e}[/yellow]")


def _pretty_args(arguments: dict | list) -> str:
    """Muestra un resumen legible de los argumentos de una tool call."""
    if not isinstance(arguments, dict):
        return repr(arguments)
    skip_keys = {"script_js"}  # demasiado largo para mostrar en consola
    parts = []
    for k, v in arguments.items():
        if k in skip_keys:
            parts.append(f"{k}=<{len(str(v))} chars>")
        elif isinstance(v, str) and len(v) > 80:
            parts.append(f"{k}={repr(v[:77])}...")
        else:
            parts.append(f"{k}={repr(v)}")
    return ", ".join(parts)


def _tool_result_message(tc: _ToolCall, content: str) -> dict:
    """Construye el mensaje de resultado de herramienta para el historial (formato OpenAI).

    any-llm convierte este formato internamente para cada provider.
    """
    return {
        "role": "tool",
        "tool_call_id": tc.id,
        "content": content,
    }


# Palabras clave que distintas APIs usan en el mensaje de error cuando no
# soportan imágenes. Suficiente para el retry sin falsos positivos.
# "content.type is invalid": z.ai/GLM (error 1210 -- su endpoint compatible
# OpenAI solo acepta bloques de texto; encontrado en vivo 2026-08-23).
_VISION_ERROR_HINTS = (
    "image", "vision", "multimodal", "image_url", "does not support",
    "unsupported content", "invalid content type", "content.type is invalid",
)

def _is_vision_unsupported_error(exc: BaseException) -> bool:
    """Devuelve True si la excepción indica que el modelo no acepta imágenes."""
    msg = str(exc).lower()
    return any(hint in msg for hint in _VISION_ERROR_HINTS)


def _strip_image_blocks(messages: list[dict]) -> list[dict]:
    """
    Devuelve una copia del historial sin los bloques de imagen (image_url / image).
    Los mensajes cuyo content queda vacío tras el strip se convierten en
    un placeholder de texto para mantener la coherencia del historial.
    """
    cleaned = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, list):
            text_blocks = [
                b for b in content
                if isinstance(b, dict) and b.get("type") not in ("image_url", "image")
            ]
            if not text_blocks:
                # El mensaje era solo imagen; reemplazar con nota de texto
                new_content = t("aipwn_screenshot_no_vision")
            elif len(text_blocks) == len(content):
                # Sin cambios — evitar copias innecesarias
                cleaned.append(msg)
                continue
            else:
                new_content = text_blocks
            cleaned.append({**msg, "content": new_content})
        else:
            cleaned.append(msg)
    return cleaned


def _screenshot_image_message(tool_result_json: str, provider: str) -> dict | None:
    """
    Dado el JSON devuelto por tool_take_screenshot, construye el mensaje
    multimodal de usuario que inyecta la imagen en el historial.

    Formato varía por provider:
      - OpenAI/compatible: content list con image_url (data URI base64)
      - Anthropic: content list con image source base64

    Devuelve None si la captura falló o si el JSON es inválido.
    """
    try:
        data = json.loads(tool_result_json)
    except (json.JSONDecodeError, ValueError):
        return None

    b64 = data.get("screenshot_b64", "")
    if not b64:
        return None

    img_format = data.get("img_format", "jpeg")
    mime = f"image/{img_format}"

    if provider == "anthropic":
        image_block = {
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": mime,
                "data": b64,
            },
        }
    else:
        # OpenAI, Azure OpenAI, Ollama multimodal, etc.
        image_block = {
            "type": "image_url",
            "image_url": {
                "url": f"data:{mime};base64,{b64}",
                "detail": "high",
            },
        }

    black_screen_warning = data.get("black_screen_warning", False)
    if black_screen_warning:
        intro = (
            "WARNING: The screenshot is almost completely black (mean brightness < 12/255). "
            "This is caused by FLAG_SECURE (WindowManager.LayoutParams.FLAG_SECURE = 0x2000). "
            "A black screenshot does NOT mean the app crashed, is frozen, or the screen is off — "
            "the app is likely fully running and just blocking screen capture. "
            "DO NOT treat this as a splash-screen freeze or app crash.\n\n"
            "NOTE: The Phase 1 script already includes a Window.setFlags hook to clear FLAG_SECURE. "
            "If the screen is still black after that script ran, the app is setting the flag via a "
            "different path that the hook did not intercept. Try one of these alternatives:\n"
            "  1. Hook addFlags instead: Window.addFlags.implementation = function(f) { "
            "return this.addFlags(f & ~0x2000); };\n"
            "  2. Clear the flag reactively in onResume/onWindowFocusChanged after it is set.\n"
            "  3. Hook the DecorView directly: call getWindow().clearFlags(0x2000) via reflection "
            "after the Activity is created.\n"
            "If no Frida script has run yet (this is the first screenshot), include the "
            "Window.setFlags hook in your next run_frida_script call and retry take_screenshot afterwards."
        )
    else:
        intro = (
            "This is a screenshot of the device screen taken right now. "
            "Analyze what you see: any security dialogs, blocked UI, error messages, "
            "or any visual state that gives clues about the current protection status."
        )

    return {
        "role": "user",
        "content": [
            {
                "type": "text",
                "text": intro,
            },
            image_block,
        ],
    }
