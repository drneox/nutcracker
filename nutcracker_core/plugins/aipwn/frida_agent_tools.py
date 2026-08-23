"""
frida_agent_tools.py — Herramientas que el agente LLM puede invocar.

Cada herramienta es una función Python pura que el agente solicita por nombre.
El dispatcher llama a la función correspondiente y retorna el resultado como string
para ser añadido al historial de mensajes del agente.

Herramientas disponibles:
    read_decompiled_class       — lee el .java decompilado de una clase
    search_in_decompiled        — grep en todo el código decompilado
    list_classes_matching       — nombres de clase que contienen keyword
    enumerate_runtime_classes   — lista clases CARGADAS EN VIVO por el app (no decompilado)
    get_class_methods           — enumera métodos y firmas de una clase en runtime
    get_heuristic_bypass_script — script de bypass heurístico generado por el analizador estático
    get_certificate_pins        — parsea network_security_config.xml, certs embebidos y OkHttp/TrustKit
    get_loaded_native_libs      — lista las .so nativas cargadas por el app en runtime
    enumerate_native_exports    — enumera exports de una librería nativa (.so)
    get_app_analysis            — resumen del análisis de nutcracker
    take_screenshot             — captura la pantalla del dispositivo y la envía al LLM como imagen
    probe_security_violations   — hookea System.exit/finishAffinity/AlertDialog y captura stack traces
    sniff_network_calls         — intercepta URLs y códigos de respuesta HTTP en vivo (solo Java)
    capture_traffic             — captura pasiva Java+nativa (SSL_read/write, cubre Flutter) con headers/body
    intercept_and_modify        — MITM activo: log/block/replace de tráfico Java+nativo en vivo
    trace_method_execution      — traza (Stalker) todos los métodos de una clase en vivo
    resolve_native_symbol       — resuelve direcciones de símbolos nativos y testea interceptabilidad
    pull_apk_from_device        — extrae TODOS los APKs del dispositivo (base + splits) vía adb pull
    get_apk_signature           — extrae la firma original del APK para spoofear PackageManager
    strings_native_lib          — extrae strings legibles de una .so (localiza checks RASP sin desensamblar)
    disassemble_native_lib      — busca una .so en cualquier split APK y la desensambla en un offset o símbolo
    patch_native_lib            — parchea bytes en una .so de cualquier split, reempaqueta y reinstala
    relaunch_with_gadget        — reempaqueta el APK con Frida Gadget y reinstala
    run_frida_script            — ejecuta JS en el dispositivo y retorna resultado
    get_frida_output_history    — recupera el output completo de una ejecución Frida previa
    report_success              — guarda el script final y termina el loop
    report_failure              — termina el loop con diagnóstico
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from nutcracker_core.analyzer import AnalysisResult
    from .frida_capture import FridaRunResult

from rich.console import Console

from nutcracker_core.i18n import t

console = Console()

# ── Schemas OpenAI function-calling ──────────────────────────────────────────

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "read_decompiled_class",
            "description": (
                "Read the decompiled Java source of a specific class. "
                "Use the fully-qualified class name (e.g. com.example.ssl.CustomPinner). "
                "Returns the source code or an error if not found."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Fully-qualified Java class name, e.g. com.example.ssl.CustomPinner",
                    }
                },
                "required": ["class_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_in_decompiled",
            "description": (
                "Search for a text pattern (case-insensitive) across all decompiled Java files. "
                "Returns up to 30 matches with file path, line number and snippet. "
                "Useful to find where a method is called, where a constant is defined, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Text or regex pattern to search for",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 30)",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_classes_matching",
            "description": (
                "List all class names in the decompiled source that contain the given keyword. "
                "Useful for discovery: find all SSL-related classes, all root-check classes, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to match against class names (case-insensitive)",
                    }
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_runtime_classes",
            "description": (
                "Use Frida to list ALL classes actually loaded by the running app that match a pattern. "
                "This is the most reliable way to find obfuscated or hidden classes — use this when "
                "list_classes_matching returns nothing or the decompiled source is incomplete. "
                "Returns up to 200 class names loaded at runtime. Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Case-insensitive substring to filter class names (e.g. 'ssl', 'trust', 'root', 'check')",
                    }
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_class_methods",
            "description": (
                "Use Frida to enumerate ALL declared methods and their full signatures for a given class. "
                "Use this after finding a class name to discover exact method names, parameter types "
                "and return types before writing a hook. Eliminates guesswork about overloads. "
                "Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Fully-qualified class name to inspect, e.g. com.example.a.b",
                    }
                },
                "required": ["class_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_heuristic_bypass_script",
            "description": (
                "Get the full heuristic bypass script already generated by nutcracker's static analyzer. "
                "This script contains battle-tested hooks for: File.exists (root paths), Runtime.exec, "
                "PackageManager (Magisk/SuperSU), Google Play / GMS spoofing, Build fields spoof, "
                "SystemProperties, RootBeer, ClassLoader deferred hooking (auto-hooks any detection class "
                "by keyword), Instrumentation.callActivityOnCreate (blocks restriction screens), "
                "TelephonyManager (IMEI/IMSI spoof), PairIP LicenseClient, and Frida detection in /proc/maps. "
                "ALWAYS call this first and use the returned script as the base. "
                "Then extend it with the specific SSL pinning / signature hooks you discover. "
                "Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_loaded_native_libs",
            "description": (
                "Use Frida to list ALL native .so libraries currently loaded by the running app. "
                "Use this when Java hooks fail and you suspect native SSL/security implementations "
                "(e.g. libssl.so, libconscrypt.so, libboringssl.so, libokhttp.so, app-specific .so files). "
                "Returns library names and paths. Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_native_exports",
            "description": (
                "Use Frida to enumerate exported functions from a specific native .so library. "
                "Use this after get_loaded_native_libs to find SSL/TLS/pinning functions like "
                "SSL_CTX_set_verify, SSL_read, X509_verify_cert, CONSCRYPT_checkServerTrusted, etc. "
                "Then use Interceptor.attach() on these addresses to hook at the native level. "
                "Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "lib_name": {
                        "type": "string",
                        "description": "Library name as returned by get_loaded_native_libs, e.g. 'libssl.so', 'libconscrypt_jni.so'",
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Optional case-insensitive filter for export names (e.g. 'ssl', 'verify', 'cert', 'pin'). Leave empty for all exports.",
                    },
                },
                "required": ["lib_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_app_analysis",
            "description": (
                "Get a summary of the nutcracker analysis for this app: "
                "detected protections, vulnerabilities found, package metadata. "
                "Call this first to understand what protections are in place."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_frida_script",
            "description": (
                "Execute a Frida JavaScript script on the connected device and observe the result. "
                "Returns hooks installed/failed, SSL errors detected, crash info, and whether "
                "the bypass was successful. Use this only after reading relevant class sources. "
                "Each call consumes one of the limited Frida run slots. "
                "Set extend_heuristic_base=true to automatically prepend the cached heuristic "
                "base script — then script_js only needs the ADDITIONAL hooks (SSL, signature, etc.). "
                "Set spawn_gated=true when DT_PREINIT_ARRAY RASP kills the app before Java.perform fires "
                "— this pauses the process before ANY native init runs, loads your script, then resumes, "
                "so your hooks are active before libloader.so/RASP initializes."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "script_js": {
                        "type": "string",
                        "description": "Additional Frida JavaScript hooks to execute. When extend_heuristic_base=true, write ONLY the new hooks — do NOT duplicate the base script.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Brief explanation of what this script attempts to hook and why",
                    },
                    "extend_heuristic_base": {
                        "type": "boolean",
                        "description": "If true, the heuristic base script (from get_heuristic_bypass_script) is automatically prepended. Use true after calling get_heuristic_bypass_script.",
                    },
                    "spawn_gated": {
                        "type": "boolean",
                        "description": (
                            "If true, use spawn-gating: pause the process at the OS entry point "
                            "BEFORE any DT_PREINIT_ARRAY or JNI_OnLoad runs, inject the script, "
                            "then resume. REQUIRED when the RASP kills the app before Java.perform fires. "
                            "Use native hooks (Memory.patchCode, dlopen interception) in spawn-gated mode; "
                            "Java.perform may still not fire if the RASP runs at native level before JVM init. "
                            "Do NOT set extend_heuristic_base=true with spawn_gated=true."
                        ),
                    },
                },
                "required": ["script_js", "rationale"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_frida_output_history",
            "description": (
                "Retrieve the full raw output (stdout + logcat) of a previous Frida execution. "
                "Use this when the summary returned by run_frida_script is not detailed enough to "
                "diagnose a failure — e.g. to read a full stack trace, a crash reason, or see all "
                "console.log lines. run_index=-1 (default) returns the last run. "
                "n_lines limits the output to the last N lines; omit to get everything."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "run_index": {
                        "type": "integer",
                        "description": "Index of the Frida run to retrieve (0=first, -1=last). Default: -1",
                    },
                    "n_lines": {
                        "type": "integer",
                        "description": "Maximum number of lines to return from the end of the output. Omit for full output.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "take_screenshot",
            "description": (
                "Capture the current device screen via ADB and send it to the LLM as an image. "
                "Use this to see what is actually displayed: security dialogs, error screens, "
                "blocked UI, PIN prompts, crash screens, or any visual state the app is in. "
                "This is the fastest way to understand WHY the app is not proceeding. "
                "Use it freely — does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_security_violations",
            "description": (
                "Hook the terminal effects of security enforcement (System.exit, Process.killProcess, "
                "Activity.finishAffinity, Activity.finish, AlertDialog.setCancelable(false)) and capture "
                "the Java stack trace at the exact moment each is called. "
                "Filters to app-package frames only, so the result tells you EXACTLY which class and method "
                "triggered the block — regardless of obfuscation or naming conventions. "
                "Use this BEFORE run_frida_script when you don't know where the security check lives. "
                "The 'violations' array in the result contains the call chain: hook the first frame's "
                "class+method to bypass the protection. Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "duration_seconds": {
                        "type": "integer",
                        "description": "Seconds to observe the app. Default: 15.",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sniff_network_calls",
            "description": (
                "Hook HTTP/HTTPS calls in the running app and log each URL, response code and body snippet. "
                "Use this when the app is stuck on the splash screen or freezes after bypass — it reveals "
                "which network request is failing (SSL error, 4xx/5xx, timeout). Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "duration_seconds": {
                        "type": "integer",
                        "description": "Seconds to observe. Default: 15.",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "capture_traffic",
            "description": (
                "Passive traffic capture in two layers at once: Java/OkHttp (full method, URL, headers "
                "and body of request+response, via peekBody -- does not consume the real stream) AND "
                "native SSL_write/SSL_read hooks on libssl/libboringssl/libconscrypt/libflutter/libcrypto "
                "(plaintext before encryption / after decryption). Use this instead of sniff_network_calls "
                "for Flutter/React-Native/native apps that don't use the Java OkHttp stack -- "
                "sniff_network_calls only sees Java traffic and will report nothing for those. "
                "Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "duration_seconds": {"type": "integer", "description": "Seconds to observe. Default: 20."},
                    "filter": {"type": "string", "description": "Optional substring filter on URL/host (only Java layer). Empty = no filter."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "intercept_and_modify",
            "description": (
                "Active MITM at the process level: apply log/block/replace rules to live traffic "
                "(Java/OkHttp and native SSL_write/SSL_read), while the app runs. Each rule: "
                "{match: substring of URL/host, action: 'log'|'block'|'replace_request_body'|"
                "'replace_response_body'|'set_header', value: depends on action}. "
                "IMPORTANT LIMITATION: at the native layer, replace_response_body on SSL_read can only "
                "rewrite up to the ORIGINAL buffer length the caller reserved -- it cannot grow a "
                "response. For replacements that need to be longer, this only works reliably at the "
                "Java/OkHttp layer (a brand new ResponseBody, no length limit). Tell the operator about "
                "this limitation if a native replacement gets truncated. Consumes ONE Frida run slot."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "rules": {
                        "type": "array",
                        "description": "List of {match, action, value} rules -- see description.",
                        "items": {"type": "object"},
                    },
                    "duration_seconds": {"type": "integer", "description": "Seconds to keep hooks active. Default: 30."},
                },
                "required": ["rules"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "trace_method_execution",
            "description": (
                "Use Frida Stalker to trace every Java method called inside a specific class or method "
                "during a few seconds of app execution. Use this as a last resort when you don't know "
                "which branch of code is triggering a detection or crash — Stalker reveals the exact "
                "execution path. WARNING: Very CPU-intensive; keep target_class as specific as possible. "
                "Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_class": {
                        "type": "string",
                        "description": "Fully-qualified class name to trace (e.g. com.example.security.RootChecker). All methods in this class will be traced.",
                    },
                    "target_method": {
                        "type": "string",
                        "description": "Optional: only trace this specific method name within the class (reduces noise).",
                    },
                    "duration_seconds": {
                        "type": "integer",
                        "description": "How many seconds to observe. Default: 10. Keep low (5-15s).",
                    },
                },
                "required": ["target_class"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "relaunch_with_gadget",
            "description": (
                "Repackage the APK with Frida Gadget embedded and reinstall it, then relaunch. "
                "Use this ONLY when anti_frida_detected=true in run_frida_script results — meaning "
                "the app is detecting frida-server itself (port scan, /proc maps, process name). "
                "Gadget runs as a library inside the APK so it's much harder to detect. "
                "After calling this, use run_frida_script normally — it will attach to the Gadget. "
                "Requires apk-mitm or objection patchapk in PATH. Takes ~60s."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "apk_path": {
                        "type": "string",
                        "description": "Absolute path to the original APK file. If empty, will try to locate it automatically.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_success",
            "description": (
                "Call this when the bypass was successful (last run_frida_script returned success=true). "
                "Saves the final script to disk and terminates the agent loop."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "script_js": {
                        "type": "string",
                        "description": "The final working Frida script content",
                    },
                    "explanation": {
                        "type": "string",
                        "description": (
                            "Detailed summary saved to persistent memory for future sessions. "
                            "Include: (1) each protection found and its exact class/method location, "
                            "(2) what technique worked and why, "
                            "(3) what failed and should NOT be retried, "
                            "(4) any key class names, offsets or hook targets confirmed at runtime. "
                            "Write 300-500 words — this is the only context available in future runs."
                        ),
                    },
                },
                "required": ["script_js", "explanation"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_certificate_pins",
            "description": (
                "Parse the APK's SSL pinning configuration from static files (no Frida run needed). "
                "Reads network_security_config.xml, searches assets/ and res/raw/ for embedded certs "
                "(.pem/.der/.crt/.bks), and scans decompiled Java for OkHttp CertificatePinner or "
                "TrustKit patterns. "
                "Returns: pinning_mechanism (network_security_config / okhttp_certificate_pinner / "
                "trustkit / custom_trustmanager / none), pinned_domains, sha256_pins, "
                "embedded_cert_files, and hook_recommendation explaining exactly which class/method "
                "to hook. Call this early when SSL pinning is detected — it tells you the correct "
                "hook target without wasting Frida run slots on trial-and-error."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "resolve_native_symbol",
            "description": (
                "Resolve native symbol addresses at runtime and test if Interceptor.attach works on them. "
                "Call this BEFORE writing Interceptor.attach hooks when you got 'TypeError: not a function' "
                "— it reveals whether the address is null (symbol not exported), points to an "
                "un-interceptable stub, or is truly interceptable. "
                "Also reports which libc module actually exports each symbol. "
                "Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "symbols": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "List of native symbol names to resolve and test, e.g. "
                            "['kill', 'tgkill', '_exit', 'exit', 'abort', 'raise', 'pthread_kill']. "
                            "For syscall-level functions, also try prefixed variants: '__kill', '__tgkill'."
                        ),
                    },
                    "lib_name": {
                        "type": "string",
                        "description": "Optional: search only in this library (e.g. 'libc.so'). Default: search all loaded modules.",
                    },
                },
                "required": ["symbols"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pull_apk_from_device",
            "description": (
                "Extract the target APK directly from the connected device using 'adb pull'. "
                "Call this when relaunch_with_gadget or patch_native_lib fail with 'APK not found' "
                "— it retrieves the APK from /data/app/ without requiring a market download. "
                "Saves to downloads/<package>/<package>.apk for use by other tools. "
                "Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "strings_native_lib",
            "description": (
                "Extract human-readable strings from a .so library. "
                "Use this BEFORE disassembling to quickly find hardcoded RASP messages, URLs, "
                "certificate hashes, error strings or class names embedded in the native library. "
                "Results help you identify what the library checks without needing to disassemble first. "
                "Pure Python — no external tools required. Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "lib_name": {
                        "type": "string",
                        "description": "Library filename as returned by get_loaded_native_libs, e.g. 'libloader.so'",
                    },
                    "min_length": {
                        "type": "integer",
                        "description": "Minimum string length to include. Default: 6. Increase to reduce noise.",
                    },
                    "filter_keyword": {
                        "type": "string",
                        "description": "Optional case-insensitive keyword filter, e.g. 'root', 'tamper', 'pin', 'cert'. Leave empty for all strings.",
                    },
                },
                "required": ["lib_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disassemble_native_lib",
            "description": (
                "Extract a .so library from the APK and disassemble it. "
                "Accepts either a symbol name (preferred) or a raw address. "
                "Use symbol_name when you know the function name (e.g. 'Java_com_example_checkIntegrity') — "
                "the tool resolves it to an address automatically via the dynamic symbol table. "
                "Use offset when you have a raw crash address from a SIGSEGV (e.g. libloader.so+0x3b1210). "
                "Prefers arm64-v8a. Requires radare2 or objdump (binutils-aarch64-linux-gnu). "
                "Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "lib_name": {
                        "type": "string",
                        "description": "Library filename as returned by get_loaded_native_libs, e.g. 'libloader.so'",
                    },
                    "symbol_name": {
                        "type": "string",
                        "description": "Exported symbol name to disassemble, e.g. 'Java_com_example_App_checkRoot'. Resolved via dynamic symbol table. Use this OR offset.",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Address to start disassembly from (virtual address or file offset for most Android .so). Use this OR symbol_name.",
                    },
                    "num_instructions": {
                        "type": "integer",
                        "description": "Number of instructions to disassemble. Default: 40. Ignored when symbol_name is used and size is known (uses symbol size automatically).",
                    },
                },
                "required": ["lib_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "patch_native_lib",
            "description": (
                "Apply permanent binary patches to a .so inside the APK, repackage, sign and reinstall. "
                "Use this to eliminate RASP self-integrity checks that cannot be bypassed with "
                "Memory.patchCode() at runtime (e.g. checks that run before Frida can attach, or "
                "checks that verify their own code pages). "
                "Call disassemble_native_lib first to confirm the instruction at the target offset. "
                "Common ARM64 patch values: NOP='1f2003d5', RET='c0035fd6', "
                "MOV_X0_0_RET='000080d2c0035fd6'. "
                "Requires apksigner or jarsigner + keytool in PATH. "
                "Consumes ONE Frida run slot (reinstalls and relaunches the app)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "lib_name": {
                        "type": "string",
                        "description": "Library filename to patch, e.g. 'libloader.so'",
                    },
                    "patches": {
                        "type": "array",
                        "description": "List of byte patches to apply to the .so file",
                        "items": {
                            "type": "object",
                            "properties": {
                                "offset": {
                                    "type": "integer",
                                    "description": "File offset in the .so to patch (same offset as used in disassemble_native_lib)",
                                },
                                "hex_bytes": {
                                    "type": "string",
                                    "description": "Replacement bytes as contiguous hex string, e.g. 'c0035fd6' (ARM64 RET) or '1f2003d5' (NOP)",
                                },
                            },
                            "required": ["offset", "hex_bytes"],
                        },
                    },
                    "rationale": {
                        "type": "string",
                        "description": "What each patch does and why (e.g. 'NOP the CRC integrity check at 0x3b1210')",
                    },
                },
                "required": ["lib_name", "patches", "rationale"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_apk_signature",
            "description": (
                "Extract the original APK signing certificate info (subject, SHA-256 fingerprint, "
                "raw signature bytes as hex) from the APK file in downloads/<package>/. "
                "Call this BEFORE relaunch_with_gadget when you plan to spoof "
                "PackageManager.getPackageInfo signatures — you need the original bytes "
                "to return them from the hook. Does NOT count as a Frida run."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_failure",
            "description": (
                "Call this when you have exhausted your analysis and cannot bypass the protections. "
                "Provide a detailed diagnosis of what you found and why bypass is not possible."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": (
                            "Detailed diagnosis saved to persistent memory for future sessions. "
                            "Include: (1) each protection found and where, "
                            "(2) every approach tried and its exact failure (error message, crash offset), "
                            "(3) what the blocker is and why it cannot be bypassed with current tools, "
                            "(4) any partial findings useful for future attempts. "
                            "Write 200-400 words — this is the only context available in future runs."
                        ),
                    }
                },
                "required": ["reason"],
            },
        },
    },
]


# ── Contexto de herramientas ─────────────────────────────────────────────────

class ToolContext:
    """
    Agrupa el estado necesario para ejecutar herramientas:
    decompiled_dir, analysis_result, configuración y callbacks.
    """

    def __init__(
        self,
        package: str,
        decompiled_dir: Path | None,
        analysis_result: "AnalysisResult | None",
        serial: str | None,
        capture_seconds: int,
        scripts_dir: Path,
        on_frida_run: "callable",  # callback(script_js, rationale, iteration) -> FridaRunResult
        frida_host: str | None = None,
        runtime_dump_dir: Path | None = None,
        device_shell: "Callable[[str], str] | None" = None,
        device_logcat: "Callable[[float], str] | None" = None,
    ) -> None:
        self.package = package
        self.decompiled_dir = decompiled_dir
        # Dir de runtime dump (FART) — contiene clases desencriptadas (DexGuard)
        # Las tools buscan aquí primero, luego en decompiled_dir como fallback
        self.runtime_dump_dir = runtime_dump_dir
        self.analysis_result = analysis_result
        self.serial = serial
        self.frida_host = frida_host or None  # e.g. "192.168.1.10:27042"
        self.capture_seconds = capture_seconds
        self.scripts_dir = scripts_dir
        self.on_frida_run = on_frida_run
        # Canal opcional para hablarle al device SIN pasar por un `adb` local
        # (modo relay del co-piloto de consulta -- ver query_agent.py::
        # QueryAgent y query_tools.py::DeviceIO). None (default, CLI/FridaAgent
        # normal) = comportamiento de siempre, shellea a un `adb` local vía
        # _adb_cmd(ctx). Usado por _run_frida_spawngated (run_frida_script con
        # spawn_gated=True) para limpiar/capturar logcat y chequear pidof.
        self.device_shell = device_shell
        self.device_logcat = device_logcat
        # Caché del script heurístico — se rellena en tool_get_heuristic_bypass_script
        self.heuristic_script: str = ""
        # Historial completo de ejecuciones Frida (FridaRunResult) para get_frida_output_history
        self.frida_run_history: list = []
        # True después de relaunch_with_gadget: próximas queries se conectan al Gadget
        self.use_gadget: bool = False


# ── Implementaciones ─────────────────────────────────────────────────────────

# Lock global: solo un proceso Frida a la vez (spawn compite por el proceso del app)
_frida_lock = threading.Lock()


def _frida_connect_args(ctx: "ToolContext", frida_bin: str, package: str, mode: str = "spawn") -> list[str]:
    """
    Devuelve los flags de conexión Frida según la configuración:
      - frida_host configurado  → [-H host:port]
      - serial configurado      → [-D serial]
      - por defecto             → [-U]
    *mode* puede ser 'spawn' (-f) o 'attach' (-n).
    """
    action_flag = ["-f", package] if mode == "spawn" else ["-n", package]
    if ctx.frida_host:
        return [frida_bin, "-H", ctx.frida_host] + action_flag
    if ctx.serial:
        return [frida_bin, "-D", ctx.serial] + action_flag
    return [frida_bin, "-U"] + action_flag


def _run_frida_query(ctx: ToolContext, script_js: str, timeout: int = 20) -> str:
    """
    Ejecuta un script Frida corto (solo para queries de introspección) y retorna el output.
    No consume un slot de run_frida_script — sirve para enumerate_runtime_classes,
    get_class_methods, get_loaded_native_libs, enumerate_native_exports,
    resolve_native_symbol, probe_security_violations, sniff_network_calls y
    trace_method_execution.
    Serializado con _frida_lock para evitar que múltiples spawns compitan por el proceso del app.

    FIX (encontrado en vivo, 2026-08-21, sesión de "Pentest asistido" con relay):
    el chequeo de `adb` de acá abajo era un gate sin uso real -- esta función
    NUNCA shellea a `adb` para nada, solo lanza el binario `frida` directo
    (-H/-D/-U). Con `ctx.frida_host` seteado (modo relay: el device está
    conectado por WebUSB al navegador, no por USB al host del dashboard), no
    hay ningún `adb` LOCAL con ruta al dispositivo -- pero tampoco hace
    falta, porque `frida -H host:port` habla directo por el túnel TCP crudo
    del relay (puerto de frida-server, no el de control de adbd, ver
    relay.py). El gate de adb solo tenía sentido como proxy heurístico de "hay
    un pipeline de dispositivo funcionando" para los modos -U/-D, así que se
    mantiene ahí -- se salta específicamente cuando `frida_host` está seteado.
    """
    if not ctx.frida_host:
        adb = shutil.which("adb")
        if not adb:
            return "ERROR: adb no encontrado"
    frida_bin = str(Path(sys.executable).parent / "frida")
    if not Path(frida_bin).exists():
        frida_bin = shutil.which("frida") or ""
    if not frida_bin:
        return "ERROR: frida no encontrado"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", prefix="nutcracker_query_", delete=False) as tmp:
        tmp.write(script_js)
        script_path = Path(tmp.name)

    try:
        if getattr(ctx, 'use_gadget', False):
            cmds_to_try = [
                [frida_bin, "-H", "127.0.0.1:27042", "-n", "Gadget", "-l", str(script_path)]
            ]
        elif ctx.frida_host or ctx.serial:
            # host remoto o serial ADB: solo attach (no reiniciar)
            attach_cmd = _frida_connect_args(ctx, frida_bin, ctx.package, mode="attach")
            spawn_cmd  = _frida_connect_args(ctx, frida_bin, ctx.package, mode="spawn")
            cmds_to_try = [
                attach_cmd + ["-l", str(script_path)],
                spawn_cmd  + ["-l", str(script_path)],
            ]
        else:
            cmds_to_try = [
                [frida_bin, "-U", "-n", ctx.package, "-l", str(script_path)],
                [frida_bin, "-U", "-f", ctx.package, "-l", str(script_path)],
            ]

        lines: list[str] = []

        with _frida_lock:
            for cmd in cmds_to_try:
                lines = []
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                done_event = threading.Event()

                def _read() -> None:
                    for raw in proc.stdout:  # type: ignore[union-attr]
                        lines.append(raw.rstrip())
                    done_event.set()

                t = threading.Thread(target=_read, daemon=True)
                t.start()
                done_event.wait(timeout=timeout)
                proc.terminate()
                t.join(timeout=3)

                # Si hubo output útil (no solo errores de attach), usar este resultado
                if lines and not all(
                    "unable to attach" in l.lower() or "process not found" in l.lower()
                    for l in lines if l.strip()
                ):
                    break
                # Si falló attach, intentar spawn en la siguiente iteración del for
    finally:
        script_path.unlink(missing_ok=True)

    return "\n".join(lines)


def tool_enumerate_runtime_classes(ctx: ToolContext, pattern: str) -> str:
    """Usa Frida para listar todas las clases cargadas en runtime que coincidan con pattern."""
    safe_pattern = pattern.replace("'", "\\'").replace("\\", "\\\\")
    script = f"""
Java.perform(function() {{
    var results = [];
    var pat = '{safe_pattern.lower()}';
    Java.enumerateLoadedClasses({{
        onMatch: function(name) {{
            if (name.toLowerCase().indexOf(pat) !== -1) {{
                results.push(name);
            }}
        }},
        onComplete: function() {{
            console.log('[runtime_classes] ' + JSON.stringify(results.slice(0, 200)));
        }}
    }});
}});
"""
    console.print(f"[dim]  {t('tools_enum_runtime_launching', pattern=pattern)}[/dim]")
    output = _run_frida_query(ctx, script, timeout=20)
    marker = "[runtime_classes] "
    for line in output.splitlines():
        if marker in line:
            idx = line.index(marker) + len(marker)
            try:
                classes = json.loads(line[idx:])
                console.print(f"[dim]  {t('tools_enum_runtime_found', count=len(classes))}[/dim]")
                if not classes:
                    return f"No se encontraron clases en runtime con '{pattern}'"
                return json.dumps(classes, indent=2)
            except json.JSONDecodeError:
                pass
    if not output.strip():
        return "ERROR: Frida no retornó output. ¿Está el dispositivo conectado y el app en ejecución?"
    return f"ERROR: No se pudo parsear la respuesta de Frida.\nOutput raw:\n{output[:1000]}"


def tool_get_class_methods(ctx: ToolContext, class_name: str) -> str:
    """Usa Frida para listar todos los métodos declarados (con firmas completas) de una clase."""
    safe = class_name.replace("'", "\\'").replace("\\", "\\\\")
    script = f"""
Java.perform(function() {{
    try {{
        var cls = Java.use('{safe}');
        var methods = cls.class.getDeclaredMethods();
        var result = [];
        for (var i = 0; i < methods.length; i++) {{
            result.push(methods[i].toString());
        }}
        var fields = cls.class.getDeclaredFields();
        var fResult = [];
        for (var j = 0; j < fields.length; j++) {{
            fResult.push(fields[j].toString());
        }}
        console.log('[class_methods] ' + JSON.stringify({{methods: result, fields: fResult}}));
    }} catch(e) {{
        console.log('[class_methods_error] ' + e.toString());
    }}
}});
"""
    console.print(f"[dim]  {t('tools_get_methods_launching', class_name=class_name)}[/dim]")
    output = _run_frida_query(ctx, script, timeout=20)
    for line in output.splitlines():
        if "[class_methods] " in line:
            idx = line.index("[class_methods] ") + len("[class_methods] ")
            try:
                data = json.loads(line[idx:])
                console.print(f"[dim]  {t('tools_get_methods_found', count=len(data.get('methods', [])))}[/dim]")
                return json.dumps(data, indent=2)
            except json.JSONDecodeError:
                pass
        if "[class_methods_error] " in line:
            idx = line.index("[class_methods_error] ") + len("[class_methods_error] ")
            return f"ERROR de Frida al inspeccionar clase: {line[idx:]}"
    if not output.strip():
        return "ERROR: Frida no retornó output. ¿Está el dispositivo conectado y el app en ejecución?"
    return f"ERROR: No se pudo parsear la respuesta de Frida.\nOutput raw:\n{output[:1000]}"


def tool_get_heuristic_bypass_script(ctx: ToolContext) -> str:
    """Carga el script heurístico en caché y retorna un resumen compacto."""
    from nutcracker_core.frida_bypass import generate_bypass_script
    import tempfile

    if not ctx.analysis_result:
        return (
            "ERROR: No hay AnalysisResult disponible. "
            "Llama get_app_analysis primero para verificar."
        )
    try:
        with tempfile.TemporaryDirectory() as tmp:
            script_path = generate_bypass_script(ctx.analysis_result, Path(tmp))
            js_content = script_path.read_text(encoding="utf-8")
        # Guardar en caché — NO lo enviamos completo al LLM para ahorrar tokens
        ctx.heuristic_script = js_content
        console.print(f"[dim]  {t('tools_heuristic_cached', chars=len(js_content))}[/dim]")
        return (
            "Heuristic bypass script LOADED and cached (" + str(len(js_content)) + " chars).\n"
            "It contains proven hooks for:\n"
            "  NATIVE (pre-Java.perform, Interceptor.attach — catches native C checks):\n"
            "  - fopen/fopen64 + fgets: filters 'frida'/'gum-js-loop'/'linjector' from /proc/maps reads\n"
            "  - connect: blocks connections to port 27042/27043 (frida-server detection)\n"
            "  JAVA (inside Java.perform):\n"
            "  - File.exists / canExecute (root paths + emulator detection paths: /dev/socket/qemud, /dev/qemu_pipe, /sys/qemu_trace, /dev/goldfish_pipe)\n"
            "  - Runtime.exec (su/busybox commands)\n"
            "  - PackageManager (hide Magisk/SuperSU packages)\n"
            "  - Google Play / GMS spoofing (AOSP emulator)\n"
            "  - Build fields spoof (FINGERPRINT, MODEL, MANUFACTURER, etc.)\n"
            "  - SystemProperties (ro.build.tags, ro.debuggable, etc.)\n"
            "  - RootBeer library bypass\n"
            "  - ClassLoader deferred hook (auto-hooks any detection class by keyword)\n"
            "  - Instrumentation.callActivityOnCreate (blocks restriction screens)\n"
            "  - TelephonyManager IMEI/IMSI spoof\n"
            "  - PairIP LicenseClient bypass\n"
            "  - BufferedReader.readLine: filters frida strings from /proc/maps (Java-level)\n"
            "  - android.net.http.X509TrustManagerExtensions.checkServerTrusted\n"
            "  - SSLContext.init: injects permissive TrustManager (Java.array — NOT JS array)\n"
            "\nDo NOT re-implement any hook listed above. "
            "Call run_frida_script with extend_heuristic_base=true and write only the "
            "ADDITIONAL hooks your analysis requires (e.g. OkHttp CertificatePinner, "
            "app-specific checks). The base is prepended server-side automatically."
        )
    except Exception as exc:
        return f"ERROR generando script heurístico: {exc}"


def tool_get_loaded_native_libs(ctx: ToolContext) -> str:
    """Lista todas las bibliotecas nativas (.so) cargadas por la app en runtime."""
    script = r"""
var libs = Process.enumerateModules().filter(function(m) {
    return m.name.toLowerCase().endsWith('.so');
});
libs.forEach(function(m) {
    console.log('[native_lib] ' + m.name + ' | ' + m.path);
});
console.log('[native_lib_done] ' + libs.length);
"""
    output = _run_frida_query(ctx, script, timeout=8)
    libs: list[dict] = []
    for line in output.splitlines():
        if "[native_lib] " in line:
            parts = line.split("[native_lib] ", 1)[1].split(" | ", 1)
            libs.append({"name": parts[0].strip(), "path": parts[1].strip() if len(parts) > 1 else ""})
        if "[native_lib_done]" in line:
            break
    if not libs:
        return "No se encontraron .so o el app no inició. Asegúrate de que el proceso esté corriendo."
    console.print(f"[dim]  {t('tools_native_libs_found', count=len(libs))}[/dim]")
    return json.dumps({"count": len(libs), "libs": sorted(libs, key=lambda x: x["name"])}, indent=2)


def tool_enumerate_native_exports(ctx: ToolContext, lib_name: str, pattern: str = "") -> str:
    """Enumera los exports de función de una biblioteca nativa, filtrados por patrón opcional."""
    safe_lib = lib_name.replace("'", "\\'").replace("\\", "\\\\")
    safe_pat = pattern.lower().replace("'", "\\'").replace("\\", "\\\\")
    script = f"""
var target = '{safe_lib}'.toLowerCase();
var filter = '{safe_pat}';
var found = [];
Process.enumerateModules().forEach(function(m) {{
    if (m.name.toLowerCase().indexOf(target) === -1) return;
    try {{
        m.enumerateExports().forEach(function(exp) {{
            if (exp.type !== 'function') return;
            var n = exp.name.toLowerCase();
            if (filter && n.indexOf(filter) === -1) return;
            found.push(m.name + '!' + exp.name + ' @ ' + exp.address);
        }});
    }} catch(e) {{}}
}});
if (found.length === 0) {{
    console.log('[native_exports_result] []');
}} else {{
    console.log('[native_exports_result] ' + JSON.stringify(found.slice(0, 300)));
}}
"""
    output = _run_frida_query(ctx, script, timeout=12)
    for line in output.splitlines():
        if "[native_exports_result] " in line:
            raw = line.split("[native_exports_result] ", 1)[1].strip()
            try:
                exports: list[str] = json.loads(raw)
                console.print(f"[dim]  {t('tools_native_exports_found', lib=lib_name, pattern=pattern, count=len(exports))}[/dim]")
                if not exports:
                    return (
                        f"No se encontraron exports en '{lib_name}' con patrón '{pattern}'. "
                        f"Verifica que la librería esté cargada (usa get_loaded_native_libs)."
                    )
                return "\n".join(exports)
            except json.JSONDecodeError:
                return f"Error parseando resultado: {raw[:200]}"
    return (
        f"Frida no retornó exports para '{lib_name}'. "
        f"Asegúrate de que el nombre coincida exactamente con lo que retorna get_loaded_native_libs."
    )


def tool_read_decompiled_class(ctx: ToolContext, class_name: str) -> str:
    """Lee el .java decompilado de una clase por nombre completamente calificado."""
    # Buscar en runtime_dump primero (clases desencriptadas), luego en decompiled_dir
    search_dirs = [d for d in [ctx.runtime_dump_dir, ctx.decompiled_dir] if d and d.exists()]
    if not search_dirs:
        return "ERROR: No hay código fuente decompilado disponible para esta app."

    relative = class_name.replace(".", "/") + ".java"
    for search_dir in search_dirs:
        candidate = search_dir / relative
        if candidate.exists():
            content = candidate.read_text(errors="replace")
            console.print(f"[dim]  {t('tools_read_class', name=class_name, chars=len(content))}[/dim]")
            return content[:8000] if len(content) > 8000 else content

    # Búsqueda parcial por nombre de clase simple
    class_simple = class_name.split(".")[-1]
    for search_dir in search_dirs:
        matches = list(search_dir.rglob(f"{class_simple}.java"))
        if matches:
            content = matches[0].read_text(errors="replace")
            console.print(f"[dim]  {t('tools_read_class', name=str(matches[0]), chars=len(content))}[/dim]")
            return content[:8000] if len(content) > 8000 else content

    return f"ERROR: Clase '{class_name}' no encontrada en el código decompilado."


def tool_search_in_decompiled(
    ctx: ToolContext,
    pattern: str,
    max_results: int = 30,
) -> str:
    """Busca un patrón en todos los archivos .java decompilados."""
    # Buscar en runtime_dump primero (desencriptado), luego en decompiled_dir
    search_dirs = [d for d in [ctx.runtime_dump_dir, ctx.decompiled_dir] if d and d.exists()]
    if not search_dirs:
        return "ERROR: No hay código fuente decompilado disponible."

    results: list[dict] = []
    seen_files: set[str] = set()  # evitar duplicados si ambos dirs tienen el mismo archivo
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"ERROR: Patrón regex inválido: {e}"

    for search_dir in search_dirs:
        for java_file in search_dir.rglob("*.java"):
            if len(results) >= max_results:
                break
            rel = str(java_file.relative_to(search_dir))
            if rel in seen_files:
                continue
            seen_files.add(rel)
            try:
                for i, line in enumerate(java_file.read_text(errors="replace").splitlines(), 1):
                    if compiled.search(line):
                        results.append({
                            "file": rel,
                            "line": i,
                            "snippet": line.strip()[:200],
                        })
                        if len(results) >= max_results:
                            break
            except OSError:
                continue
        if len(results) >= max_results:
            break

    console.print(f"[dim]  {t('tools_search_results', pattern=pattern, count=len(results))}[/dim]")
    if not results:
        return f"No se encontraron resultados para '{pattern}' en el código decompilado."
    return json.dumps(results, indent=2)


def tool_list_classes_matching(ctx: ToolContext, keyword: str) -> str:
    """Lista nombres de clase que contienen keyword (case-insensitive)."""
    search_dirs = [d for d in [ctx.runtime_dump_dir, ctx.decompiled_dir] if d and d.exists()]
    if not search_dirs:
        return "ERROR: No hay código fuente decompilado disponible."

    keyword_lower = keyword.lower()
    classes: list[str] = []
    seen: set[str] = set()

    for search_dir in search_dirs:
        for java_file in search_dir.rglob("*.java"):
            rel = java_file.relative_to(search_dir)
            # Reconstruir nombre de clase desde path relativo
            class_name = str(rel).replace("/", ".").removesuffix(".java")
            if keyword_lower in class_name.lower() and class_name not in seen:
                seen.add(class_name)
                classes.append(class_name)

    console.print(f"[dim]  {t('tools_list_classes', keyword=keyword, count=len(classes))}[/dim]")
    if not classes:
        return f"No se encontraron clases con '{keyword}' en el nombre."
    return "\n".join(sorted(classes))


def tool_get_certificate_pins(ctx: ToolContext) -> str:
    """
    Analiza la configuración de SSL pinning de la app desde archivos estáticos.
    No consume un slot de Frida.
    """
    result: dict = {
        "pinning_mechanism": "none",
        "pinned_domains": [],
        "sha256_pins": [],
        "embedded_cert_files": [],
        "hook_recommendation": "",
    }

    # Preferir runtime_dump (desencriptado) pero caer a decompiled_dir si no hay
    _cert_dir = next(
        (d for d in [ctx.runtime_dump_dir, ctx.decompiled_dir] if d and d.exists()), None
    )
    if not _cert_dir:
        result["error"] = "No decompiled directory available."
        return json.dumps(result, indent=2)

    # Alias local para compatibilidad con el resto de la función
    decompiled_dir = _cert_dir

    # ── 1. network_security_config.xml ──────────────────────────────────────
    nsc_candidates = list(decompiled_dir.rglob("network_security_config.xml"))
    if nsc_candidates:
        nsc_path = nsc_candidates[0]
        try:
            nsc_text = nsc_path.read_text(encoding="utf-8", errors="replace")
            domains = re.findall(r'<domain[^>]*>([^<]+)</domain>', nsc_text)
            result["pinned_domains"] = [d.strip() for d in domains]
            pins = re.findall(
                r'<pin\s+digest=["\']SHA-256["\'][^>]*>([^<]+)</pin>',
                nsc_text, re.IGNORECASE,
            )
            result["sha256_pins"] = [p.strip() for p in pins]
            if pins:
                result["pinning_mechanism"] = "network_security_config"
                result["hook_recommendation"] = (
                    "Pinning via network_security_config.xml. "
                    "Hook: android.security.net.config.NetworkSecurityTrustManager.checkServerTrusted "
                    "or X509TrustManagerExtensions.checkServerTrusted — return without throwing. "
                    "Alternatively use Java.deoptimizeEverything() + hook all "
                    "javax.net.ssl.TrustManager implementations."
                )
        except OSError:
            pass

    # ── 2. Certs embebidos en assets/ y res/raw/ ─────────────────────────────
    cert_extensions = {".pem", ".der", ".crt", ".cer", ".bks", ".keystore", ".p12", ".pfx"}
    cert_files: list[str] = []
    for ext in cert_extensions:
        for f in ctx.decompiled_dir.rglob(f"*{ext}"):
            if any(p in ("assets", "res") for p in f.parts):
                cert_files.append(str(f.relative_to(ctx.decompiled_dir)))
    result["embedded_cert_files"] = cert_files[:20]
    if cert_files and result["pinning_mechanism"] == "none":
        result["pinning_mechanism"] = "custom_trustmanager"
        result["hook_recommendation"] = (
            "Embedded cert files found. The app likely loads them via KeyStore or "
            "CertificateFactory. Hook: java.security.KeyStore.load to accept any keystore, "
            "or all javax.net.ssl.TrustManager implementations to skip verification."
        )

    # ── 3. Escanear código decompilado — OkHttp CertificatePinner / TrustKit ─
    okhttp_pattern = re.compile(
        r'CertificatePinner|certificate.*pinn|\.add\(["\']sha256/', re.IGNORECASE
    )
    trustkit_pattern = re.compile(r'TrustKit|com\.datatheorem\.android', re.IGNORECASE)
    okhttp_files: list[str] = []
    trustkit_files: list[str] = []
    for java_file in decompiled_dir.rglob("*.java"):
        try:
            content = java_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if okhttp_pattern.search(content):
            okhttp_files.append(str(java_file.relative_to(decompiled_dir)))
        if trustkit_pattern.search(content):
            trustkit_files.append(str(java_file.relative_to(decompiled_dir)))

    if trustkit_files:
        result["pinning_mechanism"] = "trustkit"
        result["trustkit_files"] = trustkit_files[:5]
        result["hook_recommendation"] = (
            "TrustKit detected. Hook: com.datatheorem.android.trustkit.pinning."
            "OkHostnameVerifier.verify → return true, and "
            "com.datatheorem.android.trustkit.pinning.PinningTrustManager.checkServerTrusted "
            "→ return without throwing."
        )
    elif okhttp_files and result["pinning_mechanism"] in ("none", "custom_trustmanager"):
        result["pinning_mechanism"] = "okhttp_certificate_pinner"
        result["okhttp_pinner_files"] = okhttp_files[:5]
        result["hook_recommendation"] = (
            "OkHttp CertificatePinner detected. "
            "Hook: okhttp3.CertificatePinner.check (all overloads) → return without throwing. "
            "If ClassNotFoundException, the class is in a custom classloader — use "
            "Java.enumerateClassLoaders() to find it first."
        )

    console.print(f"[dim]  [tools] get_certificate_pins → mechanism={result['pinning_mechanism']}[/dim]")
    return json.dumps(result, indent=2)


def tool_get_app_analysis(ctx: ToolContext) -> str:
    """Retorna un resumen del análisis de nutcracker como JSON."""
    if not ctx.analysis_result:
        return json.dumps({
            "package": ctx.package,
            "analysis": "No disponible — app analizada sin AnalysisResult",
        })

    ar = ctx.analysis_result
    detectors = [
        {
            "name": r.name,
            "detected": r.detected,
            "strength": r.strength,
            "evidence": r.details[:5] if r.details else [],
        }
        for r in ar.results
    ]
    summary = {
        "package": ar.package,
        "version": ar.version_name,
        "min_sdk": ar.min_sdk,
        "target_sdk": ar.target_sdk,
        "protected": ar.protected,
        "confidence": ar.confidence,
        "detectors": detectors,
        "decompilation_info": ar.decompilation_info,
    }
    console.print(f"[dim]  {t('tools_analysis_sent')}[/dim]")
    return json.dumps(summary, indent=2)


def _run_frida_spawngated(
    ctx: ToolContext,
    script_js: str,
    iteration: int,
) -> "FridaRunResult":
    """
    Ejecuta un script Frida con spawn-gating via frida Python API.
    El proceso se pausa en el entry point del OS (antes de DT_PREINIT_ARRAY),
    se carga el script, y luego se resume — los hooks están activos antes de
    que cualquier código nativo de inicialización corra.
    """
    import frida as _frida
    from .frida_capture import FridaRunResult, _parse_result

    # ctx.device_shell/device_logcat (co-piloto en modo relay, ver
    # ToolContext) reemplazan el `adb` local -- sin ellos, comportamiento de
    # siempre (CLI/FridaAgent normal).
    adb_base = [] if ctx.device_shell is not None else _adb_cmd(ctx)

    # ── Obtener dispositivo ──
    try:
        if ctx.frida_host:
            device = _frida.get_device_manager().add_remote_device(ctx.frida_host)
        elif ctx.serial:
            device = _frida.get_device(ctx.serial)
        else:
            device = _frida.get_usb_device(timeout=10)
    except Exception as e:
        empty = FridaRunResult(iteration=iteration, script_js=script_js, output="", logcat="")
        empty.output = f"[spawn-gated] ERROR getting device: {e}"
        return empty

    output_lines: list[str] = []
    logcat_lines: list[str] = []

    def on_message(msg: dict, _data: bytes | None) -> None:
        if msg.get("type") == "send":
            line = str(msg.get("payload", ""))
            output_lines.append(line)
            console.print(f"[dim]  [sg] {line}[/dim]")
        elif msg.get("type") == "error":
            err = f"[JS ERROR] {msg.get('stack', msg.get('description', str(msg)))}"
            output_lines.append(err)
            console.print(f"[yellow]  [sg] {err}[/yellow]")

    # ── Limpiar logcat antes de spawn ──
    if ctx.device_shell is not None:
        ctx.device_shell("logcat -c")
    elif adb_base:
        subprocess.run(adb_base + ["logcat", "-c"], capture_output=True, timeout=5)

    # ── Spawn gated ──
    pid: int | None = None
    session = None
    script = None
    try:
        pid = device.spawn([ctx.package])
        session = device.attach(pid)
        script = session.create_script(script_js)
        script.on("message", on_message)
        script.load()
        # Resume AHORA — DT_PREINIT_ARRAY corre aquí, pero los hooks ya están activos
        device.resume(pid)
        console.print(
            f"[cyan][spawn-gated][/cyan] pid={pid} resumed — script active before native init"
        )
    except Exception as e:
        output_lines.append(f"[spawn-gated] ERROR during spawn/attach/load: {e}")

    # ── Capturar logcat en paralelo ──
    # En relay no hay streaming línea-a-línea real (mismo motivo que
    # launch_frida_capture/logcat_fn) -- una sola captura acotada en un hilo
    # de fondo, sincronizada con el time.sleep(ctx.capture_seconds) de abajo.
    logcat_proc = None
    if ctx.device_logcat is not None:
        try:
            threading.Thread(
                target=lambda: logcat_lines.extend(
                    ctx.device_logcat(float(ctx.capture_seconds) + 5).splitlines()
                ),
                daemon=True,
            ).start()
        except Exception:
            pass
    elif adb_base:
        try:
            logcat_proc = subprocess.Popen(
                adb_base + ["logcat", "-v", "time", "*:W", "OkHttp:D", "SSL:E"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
            )

            def _stream_logcat() -> None:
                assert logcat_proc and logcat_proc.stdout
                for raw in logcat_proc.stdout:
                    logcat_lines.append(raw.rstrip())

            threading.Thread(target=_stream_logcat, daemon=True).start()
        except Exception:
            pass

    time.sleep(ctx.capture_seconds)

    # ── Detach limpio ──
    try:
        if script:
            script.unload()
        if session:
            session.detach()
    except Exception:
        pass
    if logcat_proc:
        logcat_proc.terminate()

    # ── Verificar si la app sigue viva ──
    app_running = False
    if ctx.device_shell is not None:
        try:
            app_running = bool(ctx.device_shell(f"pidof {ctx.package}").strip())
        except Exception:
            pass
    elif adb_base:
        try:
            r = subprocess.run(
                adb_base + ["shell", "pidof", ctx.package],
                capture_output=True, text=True, timeout=5,
            )
            app_running = bool(r.stdout.strip())
        except Exception:
            pass

    output = "\n".join(output_lines)
    logcat = "\n".join(logcat_lines)
    return _parse_result(iteration, script_js, output, logcat, app_running=app_running, package=ctx.package)


def tool_resolve_native_symbol(
    ctx: ToolContext,
    symbols: list[str],
    lib_name: str = "",
) -> str:
    """
    Resuelve direcciones de símbolos nativos en runtime y testea si Interceptor.attach funciona.
    No consume slot de Frida.
    """
    safe_lib = lib_name.replace("'", "\\'") if lib_name else ""
    syms_json = json.dumps(symbols)

    script = f"""
(function() {{
    // Module.findExportByName/getExportByName (forma estática, sin objeto
    // Module previo) fue ELIMINADA en Frida 17 -- lanza "TypeError: not a
    // function" en vez de devolver null (confirmado en vivo, 2026-08-21,
    // sesión real con Frida 17.16.4). Reemplazo con la misma semántica
    // (null si no se encuentra, nunca lanza): Module.findGlobalExportByName
    // para búsqueda global, Process.findModuleByName(lib).findExportByName
    // para una lib puntual -- ambas siguen devolviendo null si no existen.
    function findExport(libName, symbolName) {{
        if (!libName) return Module.findGlobalExportByName(symbolName);
        var mod = Process.findModuleByName(libName);
        return mod ? mod.findExportByName(symbolName) : null;
    }}
    var targets = {syms_json};
    var searchLib = {json.dumps(safe_lib)};
    targets.forEach(function(sym) {{
        var fromLib = findExport(searchLib, sym);
        // También buscar variantes con prefijo __
        var fromLibc  = findExport('libc.so', sym);
        var fromLibc2 = findExport('libc.so', '__' + sym);
        var addr = fromLib || fromLibc || fromLibc2;
        var entry = {{
            symbol: sym,
            resolved_addr: addr ? addr.toString() : null,
            found_in_lib: addr
                ? (Process.findModuleByAddress(addr) || {{}}).name || 'unknown'
                : null,
            interceptable: null,
            intercept_error: null,
        }};
        if (addr) {{
            try {{
                var ih = Interceptor.attach(addr, {{ onEnter: function() {{}} }});
                ih.detach();
                entry.interceptable = true;
            }} catch(e) {{
                entry.interceptable = false;
                entry.intercept_error = e.message;
            }}
        }}
        console.log('SYM_RESOLVE ' + JSON.stringify(entry));
    }});
}})();
"""
    raw = _run_frida_query(ctx, script, timeout=20)

    results: list[dict] = []
    for line in raw.splitlines():
        if "SYM_RESOLVE " in line:
            try:
                results.append(json.loads(line.split("SYM_RESOLVE ", 1)[1]))
            except Exception:
                pass

    if not results:
        return (
            "No symbol resolution results — app may not be running or Frida can't attach.\n"
            f"Raw output:\n{raw[-1000:]}"
        )

    lines = [f"Symbol resolution results ({len(results)} symbols):"]
    interceptable_addrs: list[str] = []
    for r in results:
        sym = r.get("symbol", "?")
        addr = r.get("resolved_addr")
        lib = r.get("found_in_lib", "")
        ok = r.get("interceptable")
        err = r.get("intercept_error", "")
        if addr is None:
            lines.append(f"  {sym:20s} → NOT FOUND (null address)")
        elif ok is True:
            lines.append(f"  {sym:20s} → {addr} ({lib}) ✓ interceptable")
            interceptable_addrs.append(f"ptr('{addr}')  // {sym}")
        else:
            lines.append(f"  {sym:20s} → {addr} ({lib}) ✗ {err}")

    if interceptable_addrs:
        lines.append("\nInterceptable addresses (use in Interceptor.attach):")
        lines.extend(f"  {a}" for a in interceptable_addrs)

    not_found = [r["symbol"] for r in results if not r.get("resolved_addr")]
    if not_found:
        lines.append(
            f"\nSymbols not found: {not_found}\n"
            "Tip: for syscall wrappers try '__kill', '__tgkill', or search /proc/<pid>/maps "
            "for the libc base and add the syscall offset manually."
        )

    return "\n".join(lines)


def tool_run_frida_script(
    ctx: ToolContext,
    script_js: str,
    rationale: str,
    iteration: int,
    extend_heuristic_base: bool = False,
    spawn_gated: bool = False,
) -> str:
    """Ejecuta un script Frida y retorna el resultado como JSON."""
    if spawn_gated:
        console.print(f"[cyan][agent][/cyan]   [spawn-gated] {rationale}")
        result: FridaRunResult = _run_frida_spawngated(ctx, script_js, iteration)
        ctx.frida_run_history.append(result)
        return json.dumps(result.to_dict(), indent=2)

    final_js = script_js
    if extend_heuristic_base and ctx.heuristic_script:
        base = ctx.heuristic_script
        final_js = base.rstrip() + "\n\n// ── Hooks adicionales del agente ────────────────\n" + script_js
        console.print(f"[dim]  {t('tools_run_script_combined', base=len(base), ext=len(script_js))}[/dim]")
    console.print(f"[cyan][agent][/cyan]   {t('tools_run_script_executing', rationale=rationale)}")
    result = ctx.on_frida_run(final_js, rationale, iteration)
    ctx.frida_run_history.append(result)
    return json.dumps(result.to_dict(), indent=2)


def tool_probe_security_violations(ctx: ToolContext, duration_seconds: int = 15) -> str:
    """
    Hookea los efectos terminales de una detección de seguridad (System.exit,
    finishAffinity, AlertDialog.setCancelable(false), Process.killProcess) y captura
    el stack trace en el momento en que se invocan.

    Filtra los frames del paquete de la app para devolver solo la cadena de llamadas
    relevante — independientemente de los nombres de método.
    """
    safe_pkg = ctx.package.replace("'", "\\'")
    script = f"""
Java.perform(function() {{
    var _PKG_PREFIX = '{safe_pkg}';
    var _violations = [];

    function _captureStack(trigger) {{
        try {{
            var frames = [];
            var st = Java.use('java.lang.Thread').currentThread().getStackTrace();
            for (var i = 0; i < st.length; i++) {{
                var f = st[i];
                var cls = f.getClassName();
                // Solo frames del paquete de la app — descartar framework
                if (cls.indexOf(_PKG_PREFIX) === 0 ||
                    (!cls.startsWith('android.') && !cls.startsWith('java.') &&
                     !cls.startsWith('kotlin.') && !cls.startsWith('com.android.') &&
                     !cls.startsWith('dalvik.') && !cls.startsWith('sun.') &&
                     cls.indexOf('.') !== -1 && cls.indexOf(_PKG_PREFIX.split('.')[0]) === 0)) {{
                    frames.push(cls + '.' + f.getMethodName() + '(' + f.getFileName() + ':' + f.getLineNumber() + ')');
                }}
            }}
            var entry = {{ trigger: trigger, stack: frames }};
            _violations.push(entry);
            console.log('[probe] ' + JSON.stringify(entry));
        }} catch(e) {{
            console.log('[probe_err] ' + trigger + ': ' + e);
        }}
    }}

    // 1. System.exit() — cierre forzado más común
    try {{
        var System = Java.use('java.lang.System');
        System.exit.overload('int').implementation = function(code) {{
            _captureStack('System.exit(' + code + ')');
            // No llamar original — queremos que la app siga corriendo para más info
        }};
        console.log('[probe] hooked System.exit');
    }} catch(e) {{}}

    // 2. Process.killProcess() — alternativa nativa
    try {{
        var Process = Java.use('android.os.Process');
        Process.killProcess.overload('int').implementation = function(pid) {{
            _captureStack('Process.killProcess(' + pid + ')');
        }};
        console.log('[probe] hooked Process.killProcess');
    }} catch(e) {{}}

    // 3. Activity.finishAffinity() — cierre suave de toda la task
    try {{
        var Activity = Java.use('android.app.Activity');
        Activity.finishAffinity.implementation = function() {{
            _captureStack('Activity.finishAffinity');
        }};
        console.log('[probe] hooked Activity.finishAffinity');
    }} catch(e) {{}}

    // 4. Activity.finish() — cierre de activity individual
    try {{
        var ActivityF = Java.use('android.app.Activity');
        var origFinish = ActivityF.finish.overload();
        ActivityF.finish.overload().implementation = function() {{
            _captureStack('Activity.finish');
            return origFinish.call(this);
        }};
        console.log('[probe] hooked Activity.finish');
    }} catch(e) {{}}

    // 5. AlertDialog.Builder.setCancelable(false) — señal de dialog bloqueante
    try {{
        var Builder = Java.use('android.app.AlertDialog$Builder');
        var origSC = Builder.setCancelable.overload('boolean');
        Builder.setCancelable.overload('boolean').implementation = function(cancelable) {{
            if (!cancelable) _captureStack('AlertDialog.setCancelable(false)');
            return origSC.call(this, cancelable);
        }};
        console.log('[probe] hooked AlertDialog.setCancelable');
    }} catch(e) {{}}
}});
"""
    console.print(f"[dim]  [aipwn] Probing security violations for {ctx.package} ({duration_seconds}s)...[/dim]")
    output = _run_frida_query(ctx, script, timeout=duration_seconds + 5)

    violations: list[dict] = []
    for line in output.splitlines():
        if "[probe] {" in line:
            idx = line.index("[probe] ") + len("[probe] ")
            try:
                violations.append(json.loads(line[idx:]))
            except json.JSONDecodeError:
                pass

    if not violations:
        return json.dumps({
            "violations_found": 0,
            "message": "No se detectaron llamadas de cierre/bloqueo durante la observación. "
                       "La app puede necesitar más tiempo o el bloqueo ocurre antes del attach.",
            "raw_output": output[:500],
        }, indent=2)

    # Deduplicar por trigger+primer frame de la app
    seen: set[str] = set()
    unique: list[dict] = []
    for v in violations:
        key = v["trigger"] + (v["stack"][0] if v["stack"] else "")
        if key not in seen:
            seen.add(key)
            unique.append(v)

    return json.dumps({
        "violations_found": len(unique),
        "message": (
            "Stack traces capturados en el momento del bloqueo. "
            "El primer frame del stack es la clase/método que llamó al cierre. "
            "Hookea esa clase y método para bypasear la protección."
        ),
        "violations": unique,
    }, indent=2)


def tool_take_screenshot(ctx: ToolContext) -> str:
    """
    Captura la pantalla actual del dispositivo via ADB y devuelve la imagen
    como PNG codificado en base64. El agente puede usarla para ver qué hay
    en la pantalla — dialogs de bloqueo, pantallas de error, flujos de login.

    NOTA: el contenido de la imagen se inyecta como mensaje multimodal separado
    en el historial, no aquí. Este JSON es solo el marcador de resultado.
    """
    adb_cmd = ["adb"]
    if ctx.serial:
        adb_cmd += ["-s", ctx.serial]
    adb_cmd += ["exec-out", "screencap", "-p"]

    try:
        result = subprocess.run(
            adb_cmd,
            capture_output=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "ADB screencap timed out after 20s"})
    except FileNotFoundError:
        return json.dumps({"error": "adb not found in PATH"})

    if result.returncode != 0 or not result.stdout:
        stderr = result.stderr.decode(errors="replace")[:300]
        return json.dumps({"error": f"screencap failed (rc={result.returncode}): {stderr}"})

    png_bytes = result.stdout
    # Sanity check: PNG magic bytes
    if png_bytes[:4] != b'\x89PNG':
        return json.dumps({
            "error": "screencap output is not a valid PNG (possible ADB CRLF issue)",
            "first_bytes_hex": png_bytes[:8].hex(),
        })

    # Reducir tamaño antes de encodear: redimensionar a max 720px ancho + JPEG q75
    # Un PNG de emulador 1080p ~500KB → ~50KB JPEG, ahorrando ~10x en tokens.
    black_screen_warning = False
    try:
        from PIL import Image, ImageStat
        import io as _io
        img = Image.open(_io.BytesIO(png_bytes)).convert("L")  # grayscale — color irrelevante para análisis de UI

        # Detectar pantalla negra por FLAG_SECURE u otro motivo (>90% píxeles muy oscuros)
        stat = ImageStat.Stat(img)
        mean_brightness = stat.mean[0]  # 0=negro, 255=blanco
        if mean_brightness < 12:
            black_screen_warning = True

        max_width = 720
        if img.width > max_width:
            ratio = max_width / img.width
            img = img.resize((max_width, int(img.height * ratio)), Image.LANCZOS)
        buf = _io.BytesIO()
        img.save(buf, format="JPEG", quality=75, optimize=True)
        final_bytes = buf.getvalue()
        img_format = "jpeg"
    except Exception:
        # Fallback: mandar PNG original si Pillow falla por cualquier razón
        final_bytes = png_bytes
        img_format = "png"

    b64 = base64.b64encode(final_bytes).decode()
    size_kb = len(final_bytes) // 1024

    # Guardar el PNG original (full-color, sin reducir) a disco para el reporte.
    # El b64 que va al LLM es el JPEG reducido/grayscale; el disco guarda la calidad real.
    saved_path = ""
    try:
        import datetime as _dt
        ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        ss_dir = Path("reports") / ctx.package
        ss_dir.mkdir(parents=True, exist_ok=True)
        ss_path = ss_dir / f"bypass_screenshot_{ts}.png"
        ss_path.write_bytes(png_bytes)
        saved_path = str(ss_path)
    except Exception:
        pass

    console.print(f"[dim]  [aipwn] {t('aipwn_screenshot_capturing', size_kb=size_kb)}[/dim]")

    # Devolvemos el b64 en el JSON para que frida_agent.py lo inyecte como
    # mensaje multimodal en el historial de conversación.
    result: dict = {
        "status": "captured",
        "size_kb": size_kb,
        "img_format": img_format,
        "screenshot_b64": b64,
        "screenshot_path": saved_path,
    }
    if black_screen_warning:
        result["black_screen_warning"] = True
    return json.dumps(result)


def tool_sniff_network_calls(ctx: ToolContext, duration_seconds: int = 15) -> str:
    """Hook OkHttp3 + HttpsURLConnection y loguea requests/responses en vivo."""
    script = """
Java.perform(function() {
    try {
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {
            var req = this.request();
            console.log('[net] --> ' + req.method() + ' ' + req.url());
            var resp = this.execute();
            console.log('[net] <-- ' + resp.code() + ' ' + req.url());
            return resp;
        };
    } catch(e) {}
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            console.log('[net] openConnection: ' + this.toString());
            return this.openConnection();
        };
    } catch(e) {}
    console.log('[net] hooks installed');
});
"""
    duration = max(5, min(duration_seconds, 30))
    raw = _run_frida_query(ctx, script, timeout=duration)
    lines = [l for l in raw.splitlines() if '[net]' in l]
    if not lines:
        return f"No network calls intercepted in {duration}s.\nRaw (last 20 lines):\n" + "\n".join(raw.splitlines()[-20:])
    return f"{len(lines)} network event(s) in {duration}s:\n" + "\n".join(lines[:100])


# JS de la API de resolución de símbolos compartida por capture_traffic e
# intercept_and_modify -- Module.findExportByName/getExportByName (forma
# estática de dos argumentos) fue ELIMINADA en Frida 17, ver
# tool_resolve_native_symbol más arriba para el hallazgo completo. Toda tool
# nueva que necesite resolver símbolos nativos debe usar esto, nunca la forma vieja.
_JS_FIND_EXPORT_HELPER = """
    function findExport(libName, symbolName) {
        if (!libName) return Module.findGlobalExportByName(symbolName);
        var mod = Process.findModuleByName(libName);
        return mod ? mod.findExportByName(symbolName) : null;
    }
"""

# Librerías candidatas para hooks TLS nativos -- cubre Java clásico (libssl,
# libconscrypt), Flutter (libflutter -- BoringSSL embebido, no libssl.so del
# sistema), y apps con OpenSSL propio empaquetado (libcrypto).
_JS_TLS_CANDIDATE_LIBS = "['libssl.so', 'libboringssl.so', 'libconscrypt_jni.so', 'libflutter.so', 'libcrypto.so']"


def tool_capture_traffic(ctx: ToolContext, duration_seconds: int = 20, filter: str = "") -> str:
    """
    Captura pasiva de tráfico HTTP(S) en dos capas simultáneas:
      - Java/OkHttp: método, URL, headers y body COMPLETOS de request y
        response (peekBody -- no consume el stream real, seguro para la app).
      - Nativo (SSL_write/SSL_read sobre libssl/libboringssl/libconscrypt/
        libflutter/libcrypto): captura el texto plano ANTES de cifrar /
        DESPUÉS de descifrar -- necesario para apps Flutter, que no pasan
        por el stack Java de red (por eso sniff_network_calls no las ve).
        Reenganchado en dlopen/android_dlopen_ext porque libflutter.so suele
        cargar después de que el script arranca.

    No consume slot de run_frida_script (igual que sniff_network_calls).
    Limitación conocida: la captura nativa asume texto/UTF-8 -- payloads
    binarios (protobuf, etc.) pueden salir ilegibles.
    """
    safe_filter = filter.replace("'", "\\'") if filter else ""
    script = f"""
{_JS_FIND_EXPORT_HELPER}
var FILTER = '{safe_filter}';
function matchFilter(s) {{ return !FILTER || s.indexOf(FILTER) !== -1; }}

Java.perform(function() {{
    try {{
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {{
            var req = this.request();
            var url = req.url().toString();
            if (matchFilter(url)) {{
                var reqBody = '';
                try {{
                    var b = req.body();
                    if (b) {{
                        var Buffer = Java.use('okio.Buffer');
                        var buf = Buffer.$new();
                        b.writeTo(buf);
                        reqBody = buf.readUtf8();
                    }}
                }} catch (e) {{}}
                console.log('[CAP-JAVA-REQ] ' + JSON.stringify({{
                    method: req.method(), url: url,
                    headers: req.headers().toString(), body: reqBody.substring(0, 4000),
                }}));
            }}
            var resp = this.execute();
            if (matchFilter(url)) {{
                var respBody = '';
                try {{ respBody = resp.peekBody(8192).string(); }} catch (e) {{}}
                console.log('[CAP-JAVA-RESP] ' + JSON.stringify({{
                    url: url, code: resp.code(),
                    headers: resp.headers().toString(), body: respBody.substring(0, 4000),
                }}));
            }}
            return resp;
        }};
    }} catch (e) {{}}
}});

var hookedTlsLibs = {{}};
function hookTlsLib(libName) {{
    if (hookedTlsLibs[libName]) return;
    var w = findExport(libName, 'SSL_write');
    var r = findExport(libName, 'SSL_read');
    if (!w && !r) return;
    hookedTlsLibs[libName] = true;
    if (w) {{
        Interceptor.attach(w, {{
            onEnter: function (args) {{
                var len = args[2].toInt32();
                if (len > 0 && len < 65536) {{
                    try {{
                        var s = args[1].readUtf8String(len);
                        if (s) console.log('[CAP-TLS-OUT] ' + JSON.stringify({{ lib: libName, len: len, data: s.substring(0, 4000) }}));
                    }} catch (e) {{}}
                }}
            }},
        }});
    }}
    if (r) {{
        Interceptor.attach(r, {{
            onEnter: function (args) {{ this.buf = args[1]; }},
            onLeave: function (retval) {{
                var n = retval.toInt32();
                if (n > 0 && this.buf) {{
                    try {{
                        var s = this.buf.readUtf8String(n);
                        if (s) console.log('[CAP-TLS-IN] ' + JSON.stringify({{ lib: libName, len: n, data: s.substring(0, 4000) }}));
                    }} catch (e) {{}}
                }}
            }},
        }});
    }}
    console.log('[capture] TLS hooked in ' + libName);
}}

{_JS_TLS_CANDIDATE_LIBS}.forEach(function (n) {{
    if (Process.findModuleByName(n)) hookTlsLib(n);
}});

var dlopenPtr = findExport(null, 'android_dlopen_ext') || findExport(null, 'dlopen');
if (dlopenPtr) {{
    Interceptor.attach(dlopenPtr, {{
        onEnter: function (args) {{ try {{ this.path = args[0].readCString(); }} catch (e) {{}} }},
        onLeave: function (retval) {{
            if (this.path && /ssl|boring|conscrypt|flutter|crypto/i.test(this.path)) {{
                hookTlsLib(this.path.split('/').pop());
            }}
        }},
    }});
}}

console.log('[capture] hooks installed');
"""
    duration = max(5, min(duration_seconds, 60))
    raw = _run_frida_query(ctx, script, timeout=duration)

    events: list[dict] = []
    for marker, kind in (
        ("[CAP-JAVA-REQ] ", "java_request"), ("[CAP-JAVA-RESP] ", "java_response"),
        ("[CAP-TLS-OUT] ", "tls_out"), ("[CAP-TLS-IN] ", "tls_in"),
    ):
        for line in raw.splitlines():
            if marker in line:
                try:
                    payload = json.loads(line.split(marker, 1)[1])
                    payload["kind"] = kind
                    events.append(payload)
                except (json.JSONDecodeError, IndexError):
                    pass

    if not events:
        return (
            f"No traffic captured in {duration}s (Java or native).\n"
            f"Raw (last 20 lines):\n" + "\n".join(raw.splitlines()[-20:])
        )
    return json.dumps({"duration_seconds": duration, "event_count": len(events), "events": events[:100]}, indent=2)


def tool_intercept_and_modify(
    ctx: ToolContext, rules: list, duration_seconds: int = 30, frida_iteration: int = 1,
) -> str:
    """
    MITM activo a nivel proceso: aplica reglas de log/block/replace sobre
    tráfico Java/OkHttp y nativo (SSL_write/SSL_read), en vivo, mientras la
    app corre. Cada regla es un dict:
        {"match": "<substring de URL/host>", "action": "log"|"block"|
         "replace_request_body"|"replace_response_body"|"set_header",
         "value": "<según la acción>"}

    Consume un slot de run_frida_script (vía ctx.on_frida_run) -- modifica
    comportamiento real de la app, hay que observar el efecto.

    LIMITACIÓN ESTRUCTURAL (documentar al operador si aplica): en el nivel
    nativo, "replace_response_body" en SSL_read solo puede reescribir hasta
    la longitud ORIGINAL del buffer del caller (no se puede crecer una
    respuesta ya cifrada más allá de lo que el caller reservó) -- para
    reemplazos que crecen el tamaño, usar el nivel Java/OkHttp en su lugar
    (ahí sí se puede devolver un ResponseBody completamente nuevo).
    """
    rules_json = json.dumps(rules)
    script = f"""
{_JS_FIND_EXPORT_HELPER}
var RULES = {rules_json};
function findRule(url) {{
    for (var i = 0; i < RULES.length; i++) {{
        if (!RULES[i].match || url.indexOf(RULES[i].match) !== -1) return RULES[i];
    }}
    return null;
}}

Java.perform(function () {{
    try {{
        var RealCall = Java.use('okhttp3.RealCall');
        var ResponseBody = Java.use('okhttp3.ResponseBody');
        var MediaType = Java.use('okhttp3.MediaType');
        RealCall.execute.implementation = function () {{
            var req = this.request();
            var url = req.url().toString();
            var rule = findRule(url);
            if (rule && rule.action === 'block') {{
                console.log('[MITM-BLOCK] ' + JSON.stringify({{ url: url }}));
                throw Java.use('java.io.IOException').$new('blocked by intercept_and_modify rule');
            }}
            var resp = this.execute();
            if (!rule) return resp;
            if (rule.action === 'log') {{
                console.log('[MITM-LOG] ' + JSON.stringify({{ url: url, code: resp.code() }}));
            }} else if (rule.action === 'replace_response_body') {{
                var mt = resp.body() ? resp.body().contentType() : null;
                var newBody = ResponseBody.create(mt, rule.value);
                resp = resp.newBuilder().body(newBody).build();
                console.log('[MITM-REPLACED] ' + JSON.stringify({{ url: url, new_body: rule.value.substring(0, 500) }}));
            }} else if (rule.action === 'set_header') {{
                var parts = rule.value.split(':');
                resp = resp.newBuilder().header(parts[0].trim(), parts.slice(1).join(':').trim()).build();
                console.log('[MITM-HEADER] ' + JSON.stringify({{ url: url, header: rule.value }}));
            }}
            return resp;
        }};
    }} catch (e) {{ console.log('[MITM-JAVA-ERROR] ' + e.toString()); }}
}});

var hookedTlsLibs = {{}};
function hookTlsLib(libName) {{
    if (hookedTlsLibs[libName]) return;
    var w = findExport(libName, 'SSL_write');
    var r = findExport(libName, 'SSL_read');
    if (!w && !r) return;
    hookedTlsLibs[libName] = true;
    if (w) {{
        Interceptor.attach(w, {{
            onEnter: function (args) {{
                var len = args[2].toInt32();
                if (len <= 0 || len >= 65536) return;
                try {{
                    var s = args[1].readUtf8String(len);
                    if (!s) return;
                    var rule = findRule(s);
                    if (!rule) return;
                    if (rule.action === 'block') {{
                        console.log('[MITM-TLS-BLOCK] ' + JSON.stringify({{ preview: s.substring(0, 200) }}));
                        args[2] = ptr(0);
                    }} else if (rule.action === 'replace_request_body' && rule.value) {{
                        var buf = Memory.allocUtf8String(rule.value);
                        args[1] = buf;
                        args[2] = ptr(rule.value.length);
                        console.log('[MITM-TLS-REPLACED-OUT] ' + JSON.stringify({{ new_len: rule.value.length }}));
                    }} else {{
                        console.log('[MITM-TLS-LOG-OUT] ' + JSON.stringify({{ preview: s.substring(0, 500) }}));
                    }}
                }} catch (e) {{}}
            }},
        }});
    }}
    if (r) {{
        Interceptor.attach(r, {{
            onEnter: function (args) {{ this.buf = args[1]; this.cap = args[2].toInt32(); }},
            onLeave: function (retval) {{
                var n = retval.toInt32();
                if (n <= 0 || !this.buf) return;
                try {{
                    var s = this.buf.readUtf8String(n);
                    if (!s) return;
                    var rule = findRule(s);
                    if (!rule) return;
                    if (rule.action === 'replace_response_body' && rule.value) {{
                        // Limitación estructural: no se puede exceder this.cap (ver docstring).
                        var truncated = rule.value.substring(0, this.cap);
                        Memory.writeUtf8String(this.buf, truncated);
                        retval.replace(truncated.length);
                        console.log('[MITM-TLS-REPLACED-IN] ' + JSON.stringify({{ requested_len: rule.value.length, applied_len: truncated.length, cap: this.cap }}));
                    }} else {{
                        console.log('[MITM-TLS-LOG-IN] ' + JSON.stringify({{ preview: s.substring(0, 500) }}));
                    }}
                }} catch (e) {{}}
            }},
        }});
    }}
    console.log('[intercept] TLS hooked in ' + libName);
}}

{_JS_TLS_CANDIDATE_LIBS}.forEach(function (n) {{
    if (Process.findModuleByName(n)) hookTlsLib(n);
}});

var dlopenPtr = findExport(null, 'android_dlopen_ext') || findExport(null, 'dlopen');
if (dlopenPtr) {{
    Interceptor.attach(dlopenPtr, {{
        onEnter: function (args) {{ try {{ this.path = args[0].readCString(); }} catch (e) {{}} }},
        onLeave: function (retval) {{
            if (this.path && /ssl|boring|conscrypt|flutter|crypto/i.test(this.path)) {{
                hookTlsLib(this.path.split('/').pop());
            }}
        }},
    }});
}}

console.log('[intercept] hooks installed, ' + RULES.length + ' rule(s) active');
"""
    result = ctx.on_frida_run(script, f"intercept_and_modify with {len(rules)} rule(s)", frida_iteration)
    ctx.frida_run_history.append(result)
    return json.dumps(result.to_dict(), indent=2)


def tool_trace_method_execution(
    ctx: ToolContext,
    target_class: str,
    target_method: str = "",
    duration_seconds: int = 10,
) -> str:
    """
    Usa Frida Stalker (a nivel Java via Method tracing) para registrar qué métodos
    de una clase se ejecutan durante `duration_seconds` segundos.
    No consume slot de run_frida_script.
    """
    safe_class = target_class.replace("'", "\\'")
    safe_method = target_method.replace("'", "\\'") if target_method else ""

    if safe_method:
        hook_body = f"""
        try {{
            var klass = Java.use('{safe_class}');
            var method = klass['{safe_method}'];
            if (method && method.overloads) {{
                method.overloads.forEach(function(overload) {{
                    overload.implementation = function() {{
                        var args = Array.prototype.slice.call(arguments).map(function(a) {{
                            try {{ return JSON.stringify(a); }} catch(e) {{ return String(a); }}
                        }});
                        console.log('[trace] {safe_class}.{safe_method}(' + args.join(', ') + ')');
                        var ret = overload.apply(this, arguments);
                        console.log('[trace] → ' + JSON.stringify(ret));
                        return ret;
                    }};
                }});
            }}
            console.log('[trace] Hooked {safe_class}.{safe_method}');
        }} catch(e) {{ console.log('[trace] ERROR: ' + e); }}
"""
    else:
        hook_body = f"""
        try {{
            var klass = Java.use('{safe_class}');
            var methods = klass.class.getDeclaredMethods();
            methods.forEach(function(m) {{
                var name = m.getName();
                try {{
                    klass[name].overloads.forEach(function(overload) {{
                        overload.implementation = function() {{
                            var args = Array.prototype.slice.call(arguments).map(function(a) {{
                                try {{ return String(a); }} catch(e) {{ return '?'; }}
                            }});
                            console.log('[trace] {safe_class}.' + name + '(' + args.join(', ') + ')');
                            return overload.apply(this, arguments);
                        }};
                    }});
                }} catch(e) {{}}
            }});
            console.log('[trace] Hooked all methods of {safe_class} (' + methods.length + ' methods)');
        }} catch(e) {{ console.log('[trace] ERROR hooking class: ' + e); }}
"""

    script = f"""
Java.perform(function() {{
    {hook_body}
}});
"""
    duration = max(5, min(duration_seconds, 30))
    raw = _run_frida_query(ctx, script, timeout=duration)

    trace_lines = [l for l in raw.splitlines() if "[trace]" in l]
    if not trace_lines:
        return (
            f"Trace of '{target_class}' ({duration}s): no calls intercepted.\n"
            f"Raw output (last 30 lines):\n" + "\n".join(raw.splitlines()[-30:])
        )
    return (
        f"Trace of '{target_class}' ({duration}s) — {len(trace_lines)} call(s):\n"
        + "\n".join(trace_lines[:200])
    )


# ── Helpers compartidos: APK, signing, disassembly ───────────────────────────

def _find_apk_local(ctx: ToolContext, apk_path: str = "") -> Path | None:
    """Busca el APK localmente: ruta explícita → downloads/<package>/."""
    if apk_path:
        candidate = Path(apk_path)
        if candidate.exists():
            return candidate
    downloads = Path("downloads")
    candidates = list(downloads.rglob(f"*{ctx.package}*.apk")) if downloads.exists() else []
    if candidates:
        return max(candidates, key=lambda p: p.stat().st_mtime)
    return None


def _adb_cmd(ctx: ToolContext) -> list[str]:
    adb = shutil.which("adb") or ""
    if not adb:
        return []
    return [adb] + (["-s", ctx.serial] if ctx.serial else [])


def _find_apksigner() -> str | None:
    if shutil.which("apksigner"):
        return shutil.which("apksigner")
    android_home = (
        os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or ""
    )
    if android_home:
        build_tools = Path(android_home) / "build-tools"
        if build_tools.exists():
            for v in sorted(build_tools.iterdir(), reverse=True):
                candidate = v / "apksigner"
                if candidate.exists():
                    return str(candidate)
    return None


def _find_zipalign() -> str | None:
    if shutil.which("zipalign"):
        return shutil.which("zipalign")
    android_home = (
        os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or ""
    )
    if android_home:
        build_tools = Path(android_home) / "build-tools"
        if build_tools.exists():
            for v in sorted(build_tools.iterdir(), reverse=True):
                candidate = v / "zipalign"
                if candidate.exists():
                    return str(candidate)
    return None


def _ensure_debug_keystore() -> Path:
    """Crea ~/.android/debug.keystore si no existe y retorna su ruta."""
    keystore = Path.home() / ".android" / "debug.keystore"
    if keystore.exists():
        return keystore
    keystore.parent.mkdir(parents=True, exist_ok=True)
    keytool = shutil.which("keytool")
    if not keytool:
        raise FileNotFoundError("keytool not found — install JDK")
    subprocess.run(
        [
            keytool, "-genkey", "-v",
            "-keystore", str(keystore),
            "-alias", "androiddebugkey",
            "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000",
            "-storepass", "android", "-keypass", "android",
            "-dname", "CN=Android Debug,O=Android,C=US",
        ],
        capture_output=True, check=True, timeout=30,
    )
    return keystore


def _sign_and_install_apk(ctx: ToolContext, unsigned_apk: Path) -> str:
    """
    Firma el APK con apksigner o jarsigner + keytool y lo instala en el dispositivo.
    Retorna un string de resultado (éxito o error).
    """
    import zipfile as _zf

    adb_base = _adb_cmd(ctx)
    if not adb_base:
        return f"Patched APK at {unsigned_apk} but adb not found — install manually."

    # ── Zipalign (opcional pero recomendado) ──
    zipalign = _find_zipalign()
    aligned_apk = unsigned_apk.parent / (unsigned_apk.stem + "_aligned.apk")
    if zipalign:
        subprocess.run(
            [zipalign, "-f", "-p", "4", str(unsigned_apk), str(aligned_apk)],
            capture_output=True, timeout=60,
        )
        if not aligned_apk.exists():
            aligned_apk = unsigned_apk
    else:
        aligned_apk = unsigned_apk

    # ── Firma ──
    signed_apk = unsigned_apk.parent / (unsigned_apk.stem + "_signed.apk")
    apksigner = _find_apksigner()

    if apksigner:
        try:
            keystore = _ensure_debug_keystore()
        except Exception as e:
            return f"ERROR generating debug keystore: {e}"
        r = subprocess.run(
            [
                apksigner, "sign",
                "--ks", str(keystore),
                "--ks-key-alias", "androiddebugkey",
                "--ks-pass", "pass:android",
                "--key-pass", "pass:android",
                "--out", str(signed_apk),
                str(aligned_apk),
            ],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return f"apksigner failed:\n{r.stdout}\n{r.stderr}"
    else:
        jarsigner = shutil.which("jarsigner")
        if not jarsigner:
            return (
                "ERROR: No signing tool found. Install apksigner (Android SDK build-tools) "
                "or jarsigner (JDK)."
            )
        try:
            keystore = _ensure_debug_keystore()
        except Exception as e:
            return f"ERROR generating debug keystore: {e}"
        import shutil as _sh
        _sh.copy2(aligned_apk, signed_apk)
        r = subprocess.run(
            [
                jarsigner,
                "-sigalg", "SHA256withRSA",
                "-digestalg", "SHA-256",
                "-keystore", str(keystore),
                "-storepass", "android",
                "-keypass", "android",
                str(signed_apk),
                "androiddebugkey",
            ],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return f"jarsigner failed:\n{r.stdout}\n{r.stderr}"

    # ── Instalación ──
    console.print(f"[cyan][patch][/cyan] Installing {signed_apk}...")
    install = subprocess.run(
        adb_base + ["install", "-r", "-d", str(signed_apk)],
        capture_output=True, text=True, timeout=120,
    )
    if install.returncode != 0 or "Failure" in install.stdout:
        return (
            f"APK signed but install failed:\n{install.stdout}\n{install.stderr}\n"
            f"Signed APK at: {signed_apk}"
        )
    return f"Installed OK — {signed_apk}"


def _find_and_extract_so(
    ctx: ToolContext, lib_name: str, dest_dir: Path
) -> tuple[Path | None, Path | None, str]:
    """
    Busca lib_name en TODOS los APKs en downloads/<package>/ (base + splits).
    Prefiere arm64-v8a. Retorna (so_path, apk_path, zip_inner_path) o (None, None, error_str).
    """
    import zipfile as _zf

    pkg_dir = Path("downloads") / ctx.package
    if not pkg_dir.exists():
        return None, None, (
            f"downloads/{ctx.package}/ not found. "
            "Call pull_apk_from_device first — it pulls base.apk AND all split APKs."
        )

    # Ordenar: splits con "arm64" primero (más probable que contengan .so nativos)
    apk_files = sorted(
        pkg_dir.glob("*.apk"),
        key=lambda p: (0 if "arm64" in p.name else 1 if "base" not in p.name else 2),
    )
    if not apk_files:
        return None, None, (
            f"No APK files found in downloads/{ctx.package}/. "
            "Call pull_apk_from_device first."
        )

    checked: list[str] = []
    for apk in apk_files:
        try:
            with _zf.ZipFile(apk, "r") as zf:
                lib_entries = [n for n in zf.namelist() if n.endswith(lib_name)]
                if not lib_entries:
                    checked.append(apk.name)
                    continue
                preferred = [p for p in lib_entries if "arm64" in p]
                zip_path = preferred[0] if preferred else lib_entries[0]
                zf.extract(zip_path, dest_dir)
                return dest_dir / zip_path, apk, zip_path
        except Exception as e:
            checked.append(f"{apk.name} (error: {e})")

    available: list[str] = []
    for apk in apk_files:
        try:
            with _zf.ZipFile(apk, "r") as zf:
                available += [
                    f"{apk.name}::{n}"
                    for n in zf.namelist()
                    if n.startswith("lib/") and n.endswith(".so")
                ]
        except Exception:
            pass

    return None, None, (
        f"{lib_name} not found in {len(checked)} APK(s): {', '.join(checked)}\n"
        "Available .so files:\n" + "\n".join(available[:40])
    )


# ── Nuevas herramientas ───────────────────────────────────────────────────────

def tool_get_apk_signature(ctx: ToolContext) -> str:
    """
    Extrae la firma del APK original (antes de reempaquetar) para usarla
    en hooks de PackageManager.getPackageInfo que spoofean la firma.
    """
    pkg_dir = Path("downloads") / ctx.package
    apk_candidates = sorted(pkg_dir.glob("base.apk")) + sorted(pkg_dir.glob("*.apk"))
    # preferir base.apk
    apk_path: Path | None = None
    for c in apk_candidates:
        if c.exists():
            apk_path = c
            break

    if apk_path is None:
        return json.dumps({
            "error": (
                f"No APK found in downloads/{ctx.package}/. "
                "Call pull_apk_from_device first."
            )
        })

    result: dict = {"apk": apk_path.name}

    # ── 1. Extraer META-INF/*.RSA / *.DSA / *.EC → bytes de firma DER ────────
    sig_bytes: bytes | None = None
    try:
        with _zf.ZipFile(apk_path, "r") as zf:
            sig_entries = [
                n for n in zf.namelist()
                if re.match(r"META-INF/[^/]+\.(RSA|DSA|EC)$", n, re.IGNORECASE)
            ]
            if sig_entries:
                raw_pkcs7 = zf.read(sig_entries[0])
                result["pkcs7_entry"] = sig_entries[0]
                # Los primeros bytes del PKCS#7 SignedData — extraer el cert DER
                # El Signature de Android es el DER del X.509 cert dentro del PKCS#7
                # Búsqueda del OID SEQUENCE 0x30 0x82 del cert embebido
                # Para usos prácticos, el raw PKCS#7 completo es lo que Android
                # usa como Signature bytes en getPackageInfo(GET_SIGNATURES)
                sig_bytes = raw_pkcs7
                result["signature_hex"] = raw_pkcs7.hex()
                result["signature_length"] = len(raw_pkcs7)
    except Exception as e:
        result["pkcs7_error"] = str(e)

    # ── 2. apksigner / keytool para fingerprint legible ───────────────────────
    apksigner = shutil.which("apksigner")
    keytool = shutil.which("keytool")

    if apksigner:
        try:
            r = subprocess.run(
                [apksigner, "verify", "--print-certs", str(apk_path)],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                result["apksigner_output"] = r.stdout.strip()[:2000]
            else:
                result["apksigner_error"] = r.stderr.strip()[:500]
        except Exception as e:
            result["apksigner_error"] = str(e)
    elif keytool:
        try:
            r = subprocess.run(
                [keytool, "-printcert", "-jarfile", str(apk_path)],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                result["keytool_output"] = r.stdout.strip()[:2000]
            else:
                result["keytool_error"] = r.stderr.strip()[:500]
        except Exception as e:
            result["keytool_error"] = str(e)
    else:
        result["cert_tool_warning"] = "apksigner and keytool not found — only raw hex available"

    # ── 3. SHA-256 del bloque de firma (lo que DexGuard suele comparar) ───────
    if sig_bytes:
        import hashlib
        result["sha256_fingerprint"] = hashlib.sha256(sig_bytes).hexdigest()
        result["frida_hook_hint"] = (
            "In your Frida script, use these bytes to spoof PackageManager.getPackageInfo:\n"
            "  var sigBytes = " + json.dumps(list(sig_bytes[:256])) + (
                "  /* truncated — use full signature_hex */" if len(sig_bytes) > 256 else ""
            ) + ";\n"
            "  var Signature = Java.use('android.content.pm.Signature');\n"
            "  var spoofedSig = Signature.$new(sigBytes);\n"
            "  // In getPackageInfo hook: result.signatures.value = [spoofedSig];"
        )

    console.print(f"[dim]  [tools] APK signature extracted from {apk_path.name}[/dim]")
    return json.dumps(result, indent=2)


def tool_pull_apk_from_device(ctx: ToolContext) -> str:
    """
    Extrae TODOS los APKs del paquete (base + splits) vía adb pull.
    Guarda en downloads/<package>/. Splits como split_config.arm64_v8a.apk
    contienen librerías nativas que no están en base.apk.
    """
    adb_base = _adb_cmd(ctx)
    if not adb_base:
        return "ERROR: adb not found in PATH"

    # Obtener la ruta del APK base para derivar el directorio del paquete
    r = subprocess.run(
        adb_base + ["shell", "pm", "path", ctx.package],
        capture_output=True, text=True, timeout=15,
    )
    if r.returncode != 0 or "package:" not in r.stdout:
        return (
            f"ERROR: Package '{ctx.package}' not found on device.\n"
            f"{r.stdout.strip()}\n{r.stderr.strip()}"
        )

    # pm path puede devolver múltiples líneas (base + splits en Android 12+)
    # Tomar solo la primera (base.apk) para derivar el directorio
    first_line = r.stdout.strip().splitlines()[0]
    base_device_path = first_line.split("package:")[-1].strip()
    apk_dir = base_device_path.rsplit("/", 1)[0]  # /data/app/pe.io-XXXX/

    # Listar todos los APKs en ese directorio
    ls_r = subprocess.run(
        adb_base + ["shell", f"ls {apk_dir}"],
        capture_output=True, text=True, timeout=15,
    )
    apk_files = [f.strip() for f in ls_r.stdout.splitlines() if f.strip().endswith(".apk")]
    if not apk_files:
        # Fallback: solo el base
        apk_files = [base_device_path.rsplit("/", 1)[1]]

    dest_dir = Path("downloads") / ctx.package
    dest_dir.mkdir(parents=True, exist_ok=True)

    pulled: list[str] = []
    failed: list[str] = []
    for apk_file in apk_files:
        device_apk = f"{apk_dir}/{apk_file}"
        local_apk = dest_dir / apk_file
        console.print(f"[cyan][pull-apk][/cyan] {apk_file} ...")
        pull = subprocess.run(
            adb_base + ["pull", device_apk, str(local_apk)],
            capture_output=True, text=True, timeout=180,
        )
        if pull.returncode == 0:
            size_kb = local_apk.stat().st_size // 1024
            pulled.append(f"  {apk_file} ({size_kb} KB)")
        else:
            failed.append(f"  {apk_file}: {pull.stderr.strip()[:100]}")

    lines = [
        f"SUCCESS: Pulled {len(pulled)}/{len(apk_files)} APK(s) from {apk_dir}:",
    ]
    lines.extend(pulled)
    if failed:
        lines.append("Failed:")
        lines.extend(failed)
    lines.append(
        f"\nAPKs saved to: {dest_dir}/\n"
        "disassemble_native_lib and patch_native_lib now search across ALL splits automatically."
    )
    return "\n".join(lines)


def _find_objdump() -> str | None:
    """Devuelve el primer objdump disponible que soporte ELF ARM64."""
    return (
        shutil.which("aarch64-linux-gnu-objdump")
        or shutil.which("llvm-objdump")
        or shutil.which("objdump")  # macOS LLVM objdump también soporta ELF
    )


def _resolve_symbol_va(so_path: Path, symbol_name: str) -> tuple[int, int] | None:
    """
    Busca symbol_name en la tabla de símbolos dinámicos de la .so.
    Devuelve (virtual_address, size_bytes) o None si no se encuentra.
    Intenta coincidencia exacta primero, luego substring.
    """
    r2 = shutil.which("r2") or shutil.which("radare2")
    objdump = _find_objdump()

    lines: list[str] = []

    if objdump:
        r = subprocess.run(
            [objdump, "-T", str(so_path)],
            capture_output=True, text=True, timeout=30,
        )
        lines = r.stdout.splitlines()
    elif r2:
        r = subprocess.run(
            [r2, "-q", "-c", "isq", str(so_path)],
            capture_output=True, text=True, timeout=30,
        )
        # r2 isq: index offset size bind type name
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and symbol_name in parts[-1]:
                try:
                    return int(parts[1], 16), 0
                except ValueError:
                    pass
        return None

    # Parsear salida de objdump -T
    # Formato: <va_hex> [flags] [type] <section> <size_hex> [lib] <name>
    # Ejemplo: 000007dc g    DF .text  00000048              Java_com_example_check
    exact: tuple[int, int] | None = None
    partial: tuple[int, int] | None = None

    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[-1]
        # Saltar entradas sin dirección útil
        try:
            va = int(parts[0], 16)
        except ValueError:
            continue
        if va == 0:
            continue
        # Intentar extraer size (columna 4 si hay suficientes campos)
        size = 0
        if len(parts) >= 5:
            try:
                size = int(parts[4], 16)
            except ValueError:
                pass

        if name == symbol_name:
            exact = (va, size)
            break
        if symbol_name.lower() in name.lower() and partial is None:
            partial = (va, size)

    return exact or partial


def tool_strings_native_lib(
    ctx: ToolContext,
    lib_name: str,
    min_length: int = 6,
    filter_keyword: str = "",
) -> str:
    """
    Extrae strings legibles de una .so escaneando todos los bytes del archivo
    (equivalente al comando `strings`). Útil para localizar mensajes RASP,
    URLs, hashes de certificados o nombres de clase sin necesidad de desensamblar.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        so_path, found_apk, zip_path = _find_and_extract_so(ctx, lib_name, Path(tmpdir))
        if so_path is None:
            return f"ERROR: {zip_path}"

        data = so_path.read_bytes()

    strings_found: list[str] = []
    current: list[str] = []

    for byte in data:
        if 0x20 <= byte < 0x7F or byte in (0x09,):  # printable ASCII + tab
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                s = "".join(current).strip()
                if s:
                    strings_found.append(s)
            current = []
    if len(current) >= min_length:
        s = "".join(current).strip()
        if s:
            strings_found.append(s)

    if filter_keyword:
        kw = filter_keyword.lower()
        strings_found = [s for s in strings_found if kw in s.lower()]

    if not strings_found:
        msg = f"No strings of length ≥{min_length} found"
        if filter_keyword:
            msg += f" matching '{filter_keyword}'"
        return msg + f" in {lib_name}"

    header = (
        f"Strings in {found_apk.name}::{zip_path} "
        f"(min_length={min_length}"
        + (f", filter='{filter_keyword}'" if filter_keyword else "")
        + f"): {len(strings_found)} found\n{'─'*60}\n"
    )
    shown = strings_found[:500]
    body = "\n".join(shown)
    if len(strings_found) > 500:
        body += f"\n... ({len(strings_found) - 500} more strings, use filter_keyword to narrow down)"
    return (header + body)[:10_000]


def tool_disassemble_native_lib(
    ctx: ToolContext,
    lib_name: str,
    offset: int = 0,
    num_instructions: int = 40,
    symbol_name: str = "",
) -> str:
    """
    Busca lib_name en todos los APKs del paquete (base + splits) y lo desensambla.
    Acepta symbol_name (resuelto automáticamente via tabla de símbolos) o
    un offset/dirección virtual directa.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        so_path, found_apk, zip_path = _find_and_extract_so(ctx, lib_name, Path(tmpdir))
        if so_path is None:
            return f"ERROR: {zip_path}"

        # ── Resolver dirección de inicio ──────────────────────────────────
        resolved_sym: str = ""
        sym_size: int = 0

        if symbol_name:
            result_sym = _resolve_symbol_va(so_path, symbol_name)
            if result_sym is None:
                return (
                    f"ERROR: Symbol '{symbol_name}' not found in dynamic symbol table of {lib_name}.\n"
                    "Use enumerate_native_exports to list available exported symbols, "
                    "or provide an explicit offset."
                )
            addr, sym_size = result_sym
            resolved_sym = symbol_name
        elif offset > 0:
            addr = offset
        else:
            return (
                "ERROR: Provide either symbol_name (e.g. 'Java_com_example_check') "
                "or offset (e.g. 0x3b1210)."
            )

        # Si conocemos el tamaño del símbolo, calcular num_instructions automáticamente
        if sym_size > 0:
            num_instructions = max(num_instructions, sym_size // 4)
            num_instructions = min(num_instructions, 200)  # cap de seguridad

        # ── Desensamblar ──────────────────────────────────────────────────
        r2 = shutil.which("r2") or shutil.which("radare2")
        objdump = _find_objdump()

        if r2:
            cmd = [r2, "-A", "-q", "-c", f"pd {num_instructions} @ {addr}", str(so_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = (result.stdout + result.stderr).strip()
        elif objdump:
            stop = addr + num_instructions * 4  # ARM64: 4 bytes/instr
            cmd = [
                objdump, "-d",
                f"--start-address=0x{addr:x}",
                f"--stop-address=0x{stop:x}",
                str(so_path),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout.strip()
        else:
            return (
                "ERROR: No disassembler found.\n"
                "Install radare2: sudo apt install radare2\n"
                "Or binutils:     sudo apt install binutils-aarch64-linux-gnu"
            )

        if not output:
            return (
                f"No disassembly at 0x{addr:x}. "
                "The address may be in a data/BSS section or out of range."
                + (f" Symbol '{resolved_sym}' resolved to VA 0x{addr:x}." if resolved_sym else "")
            )

        sym_label = f" (symbol: {resolved_sym})" if resolved_sym else ""
        header = (
            f"Source: {found_apk.name}::{zip_path} @ 0x{addr:x}{sym_label} "
            f"({num_instructions} instrs)\n{'─'*60}\n"
        )
        return header + output[:8000]


def tool_patch_native_lib(
    ctx: ToolContext,
    lib_name: str,
    patches: list[dict],
    rationale: str = "",
) -> str:
    """
    Busca lib_name en todos los splits del paquete, parchea bytes en la .so,
    reempaqueta el split correspondiente, firma e instala.
    patches: [{"offset": int, "hex_bytes": "c0035fd6"}, ...]
    """
    import zipfile as _zf

    # ── 1. Encontrar la .so en cualquiera de los splits ──
    with tempfile.TemporaryDirectory() as _tmp:
        _so, apk, zip_path = _find_and_extract_so(ctx, lib_name, Path(_tmp))
        if _so is None:
            return f"ERROR: {zip_path}"  # contiene el mensaje de error

    # Leer los bytes de la .so directamente del APK que la contiene
    with _zf.ZipFile(apk, "r") as zf:
        so_bytes = bytearray(zf.read(zip_path))
        orig_info = zf.getinfo(zip_path)

    # ── 2. Aplicar parches ──
    applied: list[str] = []
    for patch in patches:
        off = patch["offset"]
        new_bytes = bytes.fromhex(patch["hex_bytes"].replace(" ", ""))
        original_hex = so_bytes[off : off + len(new_bytes)].hex()
        so_bytes[off : off + len(new_bytes)] = new_bytes
        applied.append(
            f"  0x{off:08x}: {original_hex} → {patch['hex_bytes']}  "
            f"({len(new_bytes)} bytes)"
        )

    # ── 3. Reconstruir APK con la .so parcheada ──
    work_dir = Path(tempfile.mkdtemp(prefix="nutcracker_patch_"))
    patched_apk = work_dir / f"{ctx.package}_patched.apk"

    with _zf.ZipFile(apk, "r") as zin, _zf.ZipFile(patched_apk, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == zip_path:
                # Preservar método de compresión original (.so suelen ser ZIP_STORED)
                item_out = _zf.ZipInfo(item.filename)
                item_out.compress_type = orig_info.compress_type
                item_out.external_attr = orig_info.external_attr
                zout.writestr(item_out, bytes(so_bytes))
            else:
                zout.writestr(item, data)

    console.print(
        f"[cyan][patch-native][/cyan] {lib_name}: {len(patches)} patch(es) applied → "
        f"signing & installing..."
    )
    if rationale:
        console.print(f"[dim]Rationale: {rationale}[/dim]")

    install_result = _sign_and_install_apk(ctx, patched_apk)

    patch_summary = "\n".join(applied)
    if install_result.startswith("Installed OK"):
        return (
            f"SUCCESS: {lib_name} patched and installed.\n"
            f"Patches applied:\n{patch_summary}\n"
            f"Next run_frida_script calls will use the patched APK."
        )
    return (
        f"Patches applied to {lib_name}:\n{patch_summary}\n"
        f"Install result: {install_result}"
    )


def tool_relaunch_with_gadget(
    ctx: ToolContext,
    apk_path: str = "",
) -> str:
    """
    Reempaqueta el APK con Frida Gadget embebido, lo reinstala y relanza la app.
    Requiere `apk-mitm` o `objection` en PATH.
    """
    import shutil as _shutil

    # 1. Encontrar el APK (local primero; si no, intentar pull automático del dispositivo)
    apk = _find_apk_local(ctx, apk_path)

    if apk is None:
        console.print(
            "[yellow][gadget][/yellow] APK not found locally — attempting adb pull from device..."
        )
        pull_result = tool_pull_apk_from_device(ctx)
        if "SUCCESS" not in pull_result:
            return (
                f"ERROR: No APK found locally and adb pull failed.\n"
                f"{pull_result}\n\n"
                "Options:\n"
                "  1. Call pull_apk_from_device manually to diagnose the adb error.\n"
                "  2. Provide the apk_path parameter explicitly.\n"
                "  3. Download the APK from a market manually into downloads/<package>/."
            )
        apk = _find_apk_local(ctx)

    # 2. Elegir herramienta de patcheo
    apk_mitm = _shutil.which("apk-mitm")
    objection = _shutil.which("objection")

    if not apk_mitm and not objection:
        return (
            "ERROR: Neither apk-mitm nor objection found in PATH. "
            "Install one: `npm install -g apk-mitm` or `pip install objection`"
        )

    console.print(f"[cyan][gadget][/cyan] Patching {apk} with Frida Gadget...")

    patched_apk: Path | None = None

    if apk_mitm:
        # apk-mitm output: <name>-patched.apk en el mismo dir
        result = subprocess.run(
            [apk_mitm, str(apk)],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode != 0:
            return f"apk-mitm failed:\n{result.stdout[-2000:]}\n{result.stderr[-1000:]}"
        # Buscar el APK patcheado
        stem = apk.stem
        patched_candidates = list(apk.parent.glob(f"{stem}*patched*.apk"))
        if patched_candidates:
            patched_apk = patched_candidates[0]
    else:
        # objection patchapk
        result = subprocess.run(
            [objection, "patchapk", "-s", str(apk)],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode != 0:
            return f"objection patchapk failed:\n{result.stdout[-2000:]}\n{result.stderr[-1000:]}"
        patched_apk = apk.parent / (apk.stem + ".objection.apk")

    if patched_apk is None or not patched_apk.exists():
        return f"Patching succeeded but patched APK not found. Check output: {result.stdout[-1000:]}"

    # 3. Instalar en dispositivo
    adb = _shutil.which("adb")
    if not adb:
        return f"Patched APK at {patched_apk} but adb not found — install manually."

    adb_cmd = [adb] + (["-s", ctx.serial] if ctx.serial else [])
    console.print(f"[cyan][gadget][/cyan] Installing {patched_apk}...")
    install = subprocess.run(
        adb_cmd + ["install", "-r", "-d", str(patched_apk)],
        capture_output=True, text=True, timeout=120,
    )
    if install.returncode != 0 or "Failure" in install.stdout:
        return (
            f"APK patched OK but install failed:\n{install.stdout}\n{install.stderr}\n"
            "Try: adb install -r -d <patched_apk>"
        )

    console.print(f"[green][gadget][/green] Gadget APK installed. App will pause at startup — Frida will auto-attach.")

    # Actualizar ctx para que futuros run_frida_script usen --gadget
    ctx.use_gadget = True  # type: ignore[attr-defined]

    return (
        f"SUCCESS: APK repackaged with Frida Gadget and installed.\n"
        f"Patched APK: {patched_apk}\n"
        f"Next run_frida_script calls will attach via Gadget (no frida-server needed).\n"
        f"Note: the app will freeze at startup until Frida attaches — this is expected."
    )


def tool_get_frida_output_history(
    ctx: ToolContext,
    run_index: int = -1,
    n_lines: int | None = None,
) -> str:
    """Devuelve el output completo (stdout + logcat) de una ejecución Frida previa."""
    if not ctx.frida_run_history:
        return "No Frida runs recorded yet."
    try:
        run = ctx.frida_run_history[run_index]
    except IndexError:
        return f"ERROR: run_index {run_index} out of range (total runs: {len(ctx.frida_run_history)})"

    full_output = run.output
    full_logcat = run.logcat

    if n_lines is not None:
        full_output = "\n".join(full_output.splitlines()[-n_lines:])
        full_logcat = "\n".join(full_logcat.splitlines()[-n_lines:])

    total_runs = len(ctx.frida_run_history)
    actual_index = run_index if run_index >= 0 else total_runs + run_index
    return (
        f"=== Frida run {actual_index + 1}/{total_runs} (iteration {run.iteration}) ===\n"
        f"success={run.success}  crashed={run.app_crashed}  running={run.app_running}\n"
        f"\n--- stdout ---\n{full_output}\n"
        f"\n--- logcat ---\n{full_logcat}"
    )


def tool_report_success(
    ctx: ToolContext,
    script_js: str,
    explanation: str,
) -> tuple[str, Path]:
    """Guarda el script final en disco y retorna la ruta."""
    ctx.scripts_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"bypass_{ctx.package}_{ts}_agent.js"
    out_path = ctx.scripts_dir / filename
    out_path.write_text(script_js)
    console.print(f"[green][aipwn][/green] {t('tools_script_saved', path=out_path)}")
    return t('tools_success_saved', path=out_path), out_path


def tool_report_failure(ctx: ToolContext, reason: str) -> str:
    """Registra el fallo del agente."""
    console.print(f"[red][aipwn][/red] {t('tools_failure_reported', reason=reason)}")
    return t('tools_failure_recorded', reason=reason)


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch_tool(
    ctx: ToolContext,
    name: str,
    arguments: dict[str, Any],
    frida_iteration: int,
) -> tuple[str, Any]:
    """
    Ejecuta la herramienta `name` con `arguments` y retorna (result_str, extra).
    `extra` es Path cuando name=report_success, None en los demás casos.

    FIX (encontrado en vivo, 2026-08-03): si el LLM devuelve JSON truncado para
    el tool call (típicamente por quedarse sin `max_tokens` a mitad de generar
    un script_js largo), LLMClient._do_completion ya lo detecta y cae a
    ``arguments = {}`` -- pero antes de este fix, cada handler de acá abajo
    accedía a sus argumentos requeridos con `arguments["clave"]` directo, así
    que un dict vacío tumbaba TODO el proceso con un KeyError sin manejar
    (visto en vivo con run_frida_script/script_js, pero el mismo patrón
    afecta a cualquier otra herramienta). En vez de parchear cada handler
    individualmente, se envuelve el dispatch completo: un KeyError acá se
    convierte en un resultado de herramienta con error, que el LLM ve y puede
    reintentar (mismo mecanismo que ya usa "ERROR: herramienta desconocida"),
    en vez de crashear la sesión de aipwn entera.
    """
    extra = None

    try:
        return _dispatch_tool_inner(ctx, name, arguments, frida_iteration)
    except KeyError as exc:
        missing = exc.args[0] if exc.args else "?"
        return (
            f"ERROR: falta el argumento requerido '{missing}' para la herramienta "
            f"'{name}'. Tu respuesta anterior probablemente se truncó (sin espacio "
            f"para terminar el JSON del tool call, revisá max_tokens en config.yaml "
            f"si el script era largo) -- reintentá la llamada completa, con un "
            f"script más corto o dividido en varias llamadas si hace falta.",
            None,
        )


def _dispatch_tool_inner(
    ctx: ToolContext,
    name: str,
    arguments: dict[str, Any],
    frida_iteration: int,
) -> tuple[str, Any]:
    extra = None

    if name == "read_decompiled_class":
        result = tool_read_decompiled_class(ctx, arguments["class_name"])

    elif name == "search_in_decompiled":
        result = tool_search_in_decompiled(
            ctx,
            arguments["pattern"],
            max_results=int(arguments.get("max_results", 30)),
        )

    elif name == "list_classes_matching":
        result = tool_list_classes_matching(ctx, arguments["keyword"])

    elif name == "enumerate_runtime_classes":
        result = tool_enumerate_runtime_classes(ctx, arguments["pattern"])

    elif name == "get_class_methods":
        result = tool_get_class_methods(ctx, arguments["class_name"])

    elif name == "get_heuristic_bypass_script":
        result = tool_get_heuristic_bypass_script(ctx)

    elif name == "get_loaded_native_libs":
        result = tool_get_loaded_native_libs(ctx)

    elif name == "enumerate_native_exports":
        result = tool_enumerate_native_exports(
            ctx,
            arguments["lib_name"],
            arguments.get("pattern", ""),
        )

    elif name == "get_certificate_pins":
        result = tool_get_certificate_pins(ctx)

    elif name == "get_app_analysis":
        result = tool_get_app_analysis(ctx)

    elif name == "resolve_native_symbol":
        result = tool_resolve_native_symbol(
            ctx,
            symbols=arguments["symbols"],
            lib_name=arguments.get("lib_name", ""),
        )

    elif name == "run_frida_script":
        result = tool_run_frida_script(
            ctx,
            arguments["script_js"],
            arguments.get("rationale", ""),
            frida_iteration,
            extend_heuristic_base=bool(arguments.get("extend_heuristic_base", False)),
            spawn_gated=bool(arguments.get("spawn_gated", False)),
        )

    elif name == "take_screenshot":
        result = tool_take_screenshot(ctx)

    elif name == "probe_security_violations":
        result = tool_probe_security_violations(
            ctx,
            duration_seconds=int(arguments.get("duration_seconds", 15)),
        )

    elif name == "sniff_network_calls":
        result = tool_sniff_network_calls(
            ctx,
            duration_seconds=int(arguments.get("duration_seconds", 15)),
        )

    elif name == "capture_traffic":
        result = tool_capture_traffic(
            ctx,
            duration_seconds=int(arguments.get("duration_seconds", 20)),
            filter=arguments.get("filter", ""),
        )

    elif name == "intercept_and_modify":
        result = tool_intercept_and_modify(
            ctx,
            rules=arguments["rules"],
            duration_seconds=int(arguments.get("duration_seconds", 30)),
            frida_iteration=frida_iteration,
        )

    elif name == "trace_method_execution":
        result = tool_trace_method_execution(
            ctx,
            target_class=arguments["target_class"],
            target_method=arguments.get("target_method", ""),
            duration_seconds=int(arguments.get("duration_seconds", 10)),
        )

    elif name == "pull_apk_from_device":
        result = tool_pull_apk_from_device(ctx)

    elif name == "strings_native_lib":
        result = tool_strings_native_lib(
            ctx,
            lib_name=arguments["lib_name"],
            min_length=int(arguments.get("min_length", 6)),
            filter_keyword=arguments.get("filter_keyword", ""),
        )

    elif name == "disassemble_native_lib":
        result = tool_disassemble_native_lib(
            ctx,
            lib_name=arguments["lib_name"],
            offset=int(arguments.get("offset", 0)),
            num_instructions=int(arguments.get("num_instructions", 40)),
            symbol_name=arguments.get("symbol_name", ""),
        )

    elif name == "patch_native_lib":
        result = tool_patch_native_lib(
            ctx,
            lib_name=arguments["lib_name"],
            patches=arguments["patches"],
            rationale=arguments.get("rationale", ""),
        )

    elif name == "relaunch_with_gadget":
        result = tool_relaunch_with_gadget(
            ctx,
            apk_path=arguments.get("apk_path", ""),
        )

    elif name == "get_frida_output_history":
        result = tool_get_frida_output_history(
            ctx,
            run_index=int(arguments.get("run_index", -1)),
            n_lines=int(arguments["n_lines"]) if "n_lines" in arguments else None,
        )

    elif name == "report_success":
        if not arguments.get("script_js"):
            return "ERROR: script_js is required — include the full working Frida script content.", None
        result, extra = tool_report_success(
            ctx,
            arguments["script_js"],
            arguments.get("explanation", ""),
        )

    elif name == "get_apk_signature":
        result = tool_get_apk_signature(ctx)

    elif name == "report_failure":
        result = tool_report_failure(ctx, arguments["reason"])

    else:
        result = f"ERROR: Herramienta desconocida '{name}'"

    return result, extra
