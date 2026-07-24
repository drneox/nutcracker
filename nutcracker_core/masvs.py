"""Módulo MASVS v2.1 — mapeo de hallazgos de nutcracker a OWASP MASVS + MASWE + CWE.

Genera un MASVSReport con:
  - Estado de cada uno de los 24 controles MASVS v2.1 oficiales (pass / fail /
    bypass / no_protection / not_tested)
  - Puntuación 0-100 y grado A-F
  - Lista de hallazgos por control, incluyendo su(s) debilidad(es) MASWE y CWE

Fuente de verdad para los 24 controles y las 119 debilidades MASWE: extraídas
directamente de mas.owasp.org/MASVS/ y github.com/OWASP/maswe (Fase 2 del
plan, 2026-07-24) — no inventadas. MASWE_CATALOG guarda el catálogo completo;
RULE_TO_MASWE solo mapea el subconjunto que las reglas de nutcracker cubren
hoy con confianza razonable.

Uso:
    from nutcracker_core.masvs import build_masvs_report
    report = build_masvs_report(analysis_result, scan_result)
    report.to_dict()  # → listo para serializar en el JSON de salida
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .analyzer import AnalysisResult
    from .vuln_scanner import ScanResult
    from .manifest_analyzer import ManifestAnalysisResult


# ── Definición de los 24 controles MASVS v2.1 oficiales ──────────────────────
# Paráfrasis en español del "statement" oficial de cada control
# (mas.owasp.org/MASVS/controls/<ID>/). Los 15 que ya existían en versiones
# previas de este módulo se revisaron y corrigieron contra el texto oficial;
# ver notas "FIX" en el historial de plan.md Fase 2 para el detalle de qué
# cambió y por qué.

MASVS_CONTROLS: dict[str, str] = {
    # STORAGE — almacenamiento seguro de datos sensibles (data-at-rest)
    "MASVS-STORAGE-1": "La app almacena de forma segura los datos sensibles, sin importar la ubicación (privada o pública)",
    "MASVS-STORAGE-2": "La app evita la fuga no intencional de datos sensibles (por ejemplo vía backups o logs)",
    # CRYPTO
    "MASVS-CRYPTO-1":  "La app usa criptografía fuerte y actual según las mejores prácticas de la industria",
    "MASVS-CRYPTO-2":  "La app gestiona las claves criptográficas (generación, almacenamiento, rotación) según las mejores prácticas",
    # AUTH
    "MASVS-AUTH-1":    "La app usa protocolos de autenticación y autorización seguros y sigue las mejores prácticas relevantes",
    "MASVS-AUTH-2":    "La app realiza la autenticación local (biometría, PIN) de forma segura según las mejores prácticas de la plataforma",
    "MASVS-AUTH-3":    "La app protege las operaciones sensibles con autenticación adicional (step-up)",
    # NETWORK
    "MASVS-NETWORK-1": "La app protege todo el tráfico de red según las mejores prácticas actuales (TLS, validación de certificados)",
    "MASVS-NETWORK-2": "La app implementa identity pinning (certificate/public key pinning) para los endpoints bajo control del desarrollador",
    # PLATFORM
    "MASVS-PLATFORM-1": "La app usa los mecanismos de IPC de forma segura (intents, deep links, componentes exportados)",
    "MASVS-PLATFORM-2": "La app usa WebViews de forma segura (sin JS innecesario, sin acceso a archivos, sin puentes JS expuestos)",
    "MASVS-PLATFORM-3": "La app usa la interfaz de usuario de forma segura (evita fugas vía capturas de pantalla, clipboard, etc.)",
    # CODE
    "MASVS-CODE-1":    "La app requiere una versión de plataforma actualizada",
    "MASVS-CODE-2":    "La app tiene un mecanismo para forzar actualizaciones ante vulnerabilidades críticas",
    "MASVS-CODE-3":    "La app solo usa componentes de software sin vulnerabilidades conocidas",
    "MASVS-CODE-4":    "La app valida y sanitiza toda entrada no confiable (SQL, IPC, deserialización, comandos)",
    # RESILIENCE — resiliencia ante ingeniería inversa y manipulación
    "MASVS-RESILIENCE-1": "La app valida la integridad de la plataforma (detecta dispositivos rooteados/comprometidos)",
    "MASVS-RESILIENCE-2": "La app implementa mecanismos anti-tampering (verifica firma del paquete, integridad de DEX/código nativo/recursos)",
    "MASVS-RESILIENCE-3": "La app implementa mecanismos anti-análisis-estático (ofuscación de código, recursos y strings)",
    "MASVS-RESILIENCE-4": "La app implementa técnicas anti-análisis-dinámico (detección de debugger, Frida, hooking)",
    # PRIVACY
    "MASVS-PRIVACY-1": "La app minimiza el acceso a datos y recursos sensibles (principio de mínimo privilegio en permisos)",
    "MASVS-PRIVACY-2": "La app evita la identificación del usuario (anonimización/pseudonimización)",
    "MASVS-PRIVACY-3": "La app es transparente sobre la recolección y uso de datos",
    "MASVS-PRIVACY-4": "La app ofrece al usuario control sobre sus datos",
}


# ── Catálogo MASWE (OWASP Mobile App Security Weakness Enumeration) ──────────
# Las 119 debilidades oficiales (github.com/OWASP/maswe, fetched 2026-07-24),
# id → título. RULE_TO_MASWE abajo solo usa el subconjunto mapeado a reglas
# existentes; el resto queda disponible como referencia (p.ej. para el gap
# report de docs/owasp-mas-coverage.md en Fase 2.3).
MASWE_CATALOG: dict[str, str] = {
    "MASWE-0001": "Insertion of Sensitive Data into Logs",
    "MASWE-0002": "Sensitive Data Stored With Insufficient Access Restrictions in Internal Locations",
    "MASWE-0003": "Backup Unencrypted",
    "MASWE-0004": "Sensitive Data Not Excluded From Backup",
    "MASWE-0005": "API Keys Hardcoded in the App Package",
    "MASWE-0006": "Sensitive Data Stored Unencrypted in Private Storage Locations",
    "MASWE-0007": "Sensitive Data Stored Unencrypted in Shared Storage Requiring No User Interaction",
    "MASWE-0008": "Missing Device Secure Lock Verification Implementation",
    "MASWE-0009": "Improper Cryptographic Key Generation",
    "MASWE-0010": "Improper Cryptographic Key Derivation",
    "MASWE-0011": "Cryptographic Key Rotation Not Implemented",
    "MASWE-0012": "Insecure or Wrong Usage of Cryptographic Key",
    "MASWE-0013": "Hardcoded Cryptographic Keys in Use",
    "MASWE-0014": "Cryptographic Keys Not Properly Protected at Rest",
    "MASWE-0015": "Deprecated Android KeyStore Implementations",
    "MASWE-0016": "Unsafe Handling of Imported Cryptographic Keys",
    "MASWE-0017": "Cryptographic Keys Not Properly Protected on Export",
    "MASWE-0018": "Cryptographic Keys Access Not Restricted",
    "MASWE-0019": "Risky Cryptography Implementations",
    "MASWE-0020": "Improper Encryption",
    "MASWE-0021": "Improper Hashing",
    "MASWE-0022": "Predictable Initialization Vectors (IVs)",
    "MASWE-0023": "Risky Padding",
    "MASWE-0024": "Improper Use of Message Authentication Code (MAC)",
    "MASWE-0025": "Improper Generation of Cryptographic Signatures",
    "MASWE-0026": "Improper Verification of Cryptographic Signature",
    "MASWE-0027": "Improper Random Number Generation",
    "MASWE-0028": "MFA Implementation Best Practices Not Followed",
    "MASWE-0029": "Step-Up Authentication Not Implemented After Login",
    "MASWE-0030": "Re-Authenticates Not Triggered On Contextual State Changes",
    "MASWE-0031": "Insecure use of Android Protected Confirmation",
    "MASWE-0032": "Platform-provided Authentication APIs Not Used",
    "MASWE-0033": "Authentication or Authorization Protocol Security Best Practices Not Followed",
    "MASWE-0034": "Insecure Implementation of Confirm Credentials",
    "MASWE-0035": "Passwordless Authentication Not Implemented",
    "MASWE-0036": "Authentication Material Stored Unencrypted on the Device",
    "MASWE-0037": "Authentication Material Sent over Insecure Connections",
    "MASWE-0038": "Authentication Tokens Not Validated",
    "MASWE-0039": "Shared Web Credentials and Website-association Not Implemented",
    "MASWE-0040": "Insecure Authentication in WebViews",
    "MASWE-0041": "Authentication Enforced Only Locally Instead of on the Server-side",
    "MASWE-0042": "Authorization Enforced Only Locally Instead of on the Server-side",
    "MASWE-0043": "App Custom PIN Not Bound to Platform KeyStore",
    "MASWE-0044": "Biometric Authentication Can Be Bypassed",
    "MASWE-0045": "Fallback to Non-biometric Credentials Allowed for Sensitive Transactions",
    "MASWE-0046": "Crypto Keys Not Invalidated on New Biometric Enrollment",
    "MASWE-0047": "Insecure Identity Pinning",
    "MASWE-0048": "Insecure Machine-to-Machine Communication",
    "MASWE-0049": "Proven Networking APIs Not used",
    "MASWE-0050": "Cleartext Traffic",
    "MASWE-0051": "Unprotected Open Ports",
    "MASWE-0052": "Insecure Certificate Validation",
    "MASWE-0053": "Sensitive Data Leaked via the User Interface",
    "MASWE-0054": "Sensitive Data Leaked via Notifications",
    "MASWE-0055": "Sensitive Data Leaked via Screenshots or Screen Recordings",
    "MASWE-0056": "Tapjacking Attacks",
    "MASWE-0057": "StrandHogg Attack / Task Affinity Vulnerability",
    "MASWE-0058": "Insecure Deep Links",
    "MASWE-0059": "Use Of Unauthenticated Platform IPC",
    "MASWE-0060": "Insecure Use of UIActivity",
    "MASWE-0061": "Insecure Use of App Extensions",
    "MASWE-0062": "Insecure Services",
    "MASWE-0063": "Insecure Broadcast Receivers",
    "MASWE-0064": "Insecure Content Providers",
    "MASWE-0065": "Sensitive Data Permanently Shared with Other Apps",
    "MASWE-0066": "Insecure Intents",
    "MASWE-0067": "Debuggable Flag Not Disabled",
    "MASWE-0068": "JavaScript Bridges in WebViews",
    "MASWE-0069": "WebViews Allows Access to Local Resources",
    "MASWE-0070": "JavaScript Loaded from Untrusted Sources",
    "MASWE-0071": "WebViews Loading Content from Untrusted Sources",
    "MASWE-0072": "Universal XSS",
    "MASWE-0073": "Insecure WebResourceResponse Implementations",
    "MASWE-0074": "Web Content Debugging Enabled",
    "MASWE-0075": "Enforced Updating Not Implemented",
    "MASWE-0076": "Dependencies with Known Vulnerabilities",
    "MASWE-0077": "Running on a recent Platform Version Not Ensured",
    "MASWE-0078": "Latest Platform Version Not Targeted",
    "MASWE-0079": "Unsafe Handling of Data from the Network",
    "MASWE-0080": "Unsafe Handling of Data from Backups",
    "MASWE-0081": "Unsafe Handling Of Data From External Interfaces",
    "MASWE-0082": "Unsafe Handling of Data From Local Storage",
    "MASWE-0083": "Unsafe Handling of Data From The User Interface",
    "MASWE-0084": "Unsafe Handling of Data from IPC",
    "MASWE-0085": "Unsafe Dynamic Code Loading",
    "MASWE-0086": "SQL Injection",
    "MASWE-0087": "Insecure Parsing and Escaping",
    "MASWE-0088": "Insecure Object Deserialization",
    "MASWE-0089": "Code Obfuscation Not Implemented",
    "MASWE-0090": "Resource Obfuscation Not Implemented",
    "MASWE-0091": "Anti-Deobfuscation Techniques Not Implemented",
    "MASWE-0092": "Static Analysis Tools Not Prevented",
    "MASWE-0093": "Debugging Symbols Not Removed",
    "MASWE-0094": "Non-Production Resources Not Removed",
    "MASWE-0095": "Code That Disables Security Controls Not Removed",
    "MASWE-0096": "Data Sent Unencrypted Over Encrypted Connections",
    "MASWE-0097": "Root/Jailbreak Detection Not Implemented",
    "MASWE-0098": "App Virtualization Environment Detection Not Implemented",
    "MASWE-0099": "Emulator Detection Not Implemented",
    "MASWE-0100": "Device Attestation Not Implemented",
    "MASWE-0101": "Debugger Detection Not Implemented",
    "MASWE-0102": "Dynamic Analysis Tools Detection Not Implemented",
    "MASWE-0103": "RASP Techniques Not Implemented",
    "MASWE-0104": "App Integrity Not Verified",
    "MASWE-0105": "Integrity of App Resources Not Verified",
    "MASWE-0106": "Official Store Verification Not Implemented",
    "MASWE-0107": "Runtime Code Integrity Not Verified",
    "MASWE-0108": "Sensitive Data in Network Traffic",
    "MASWE-0109": "Lack of Anonymization or Pseudonymisation Measures",
    "MASWE-0110": "Use of Unique Identifiers for User Tracking",
    "MASWE-0111": "Inadequate Privacy Policy",
    "MASWE-0112": "Inadequate Data Collection Declarations",
    "MASWE-0113": "Lack of Proper Data Management Controls",
    "MASWE-0114": "Inadequate Data Visibility Controls",
    "MASWE-0115": "Inadequate or Ambiguous User Consent Mechanisms",
    "MASWE-0116": "Compiler-Provided Security Features Not Used",
    "MASWE-0117": "Inadequate Permission Management",
    "MASWE-0118": "Sensitive Data Not Removed After Use",
    "MASWE-0119": "Insecure Activities",
}


# ── Mapeo reglas vuln_scanner/native_scanner → MASVS + MASWE + CWE ──────────
# FIX (Fase 2, 2026-07-24) respecto a versiones previas de este módulo:
#   - AUTH001 (token en logs) y DBG002/DBG003 (logs con datos sensibles):
#     estaban en MASVS-CODE-2/AUTH-2, cuyo texto oficial no habla de logs.
#     MASWE-0001 ("Insertion of Sensitive Data into Logs") está catalogada
#     oficialmente bajo MASVS-STORAGE → movidas a MASVS-STORAGE-2, que
#     además menciona "logs" explícitamente en su texto oficial.
#   - INFO001 (android:debuggable=true): MASWE-0067 está catalogada bajo
#     MASVS-RESILIENCE, no CODE → movida de CODE-2 a MASVS-RESILIENCE-4
#     (coincide con el texto oficial de R4: "anti-dynamic-analysis techniques").
#   - EXTRA001 (permisos peligrosos): movida de PLATFORM-1 a PRIVACY-1
#     ("minimiza acceso a datos y recursos sensibles"), que es el control
#     real cuyo texto describe exactamente esto; MASWE-0117 confirma la
#     categorización oficial bajo PRIVACY.
RULE_TO_MASVS: dict[str, list[str]] = {
    "HC001":     ["MASVS-STORAGE-2"],
    "HC002":     ["MASVS-STORAGE-2"],
    "HC003":     ["MASVS-STORAGE-2"],
    "HC004":     ["MASVS-STORAGE-2"],
    "HC005":     ["MASVS-STORAGE-2"],
    "HC006":     ["MASVS-CRYPTO-1"],
    "HC007":     ["MASVS-STORAGE-2"],
    "HC008":     ["MASVS-STORAGE-2", "MASVS-NETWORK-1"],
    "ST001":     ["MASVS-STORAGE-1"],
    "ST002":     ["MASVS-STORAGE-1"],
    "ST003":     ["MASVS-STORAGE-1"],
    "ST004":     ["MASVS-STORAGE-1"],
    "ST005":     ["MASVS-PLATFORM-3"],
    "ST006":     ["MASVS-STORAGE-2"],
    "NET001":    ["MASVS-NETWORK-1"],
    "NET002":    ["MASVS-NETWORK-1"],
    "NET003":    ["MASVS-NETWORK-1"],
    "NET004":    ["MASVS-NETWORK-1"],
    "NET005":    ["MASVS-NETWORK-2"],
    "NET006":    ["MASVS-NETWORK-1", "MASVS-PLATFORM-2"],
    "AUTH001":   ["MASVS-STORAGE-2"],                       # FIX: era AUTH-2
    "CRYPTO001": ["MASVS-CRYPTO-1"],
    "CRYPTO002": ["MASVS-CRYPTO-1"],
    "CRYPTO003": ["MASVS-CRYPTO-1"],
    "CRYPTO004": ["MASVS-CRYPTO-1"],
    "CRYPTO005": ["MASVS-CRYPTO-1"],
    "CRYPTO006": ["MASVS-CRYPTO-1"],
    "COMP001":   ["MASVS-PLATFORM-2"],
    "COMP002":   ["MASVS-PLATFORM-2"],
    "COMP003":   ["MASVS-PLATFORM-2"],
    "COMP004":   ["MASVS-PLATFORM-1"],
    "COMP005":   ["MASVS-PLATFORM-2"],
    "COMP006":   ["MASVS-PLATFORM-1"],  # Activity exported sin permission
    "COMP007":   ["MASVS-PLATFORM-1"],  # Service exported sin permission
    "COMP008":   ["MASVS-PLATFORM-1"],  # ContentProvider exported sin permission — antes sin mapear
    "INFO001":   ["MASVS-RESILIENCE-4"],  # FIX: era CODE-2 — debuggable=true
    "INJ001":    ["MASVS-CODE-4"],
    "INJ002":    ["MASVS-CODE-4"],
    "INJ003":    ["MASVS-CODE-4"],
    "INJ004":    ["MASVS-PLATFORM-1"],
    "DBG001":    ["MASVS-RESILIENCE-2"],  # FIX: era CODE-2 — código solo-debug que puede desactivar controles
    "DBG002":    ["MASVS-STORAGE-2"],     # FIX: era CODE-2 — log con datos sensibles
    "DBG003":    ["MASVS-STORAGE-2"],     # FIX: era CODE-2 — printStackTrace expone info en logs
    "OBF001":    ["MASVS-RESILIENCE-3"],
    "DESER001":  ["MASVS-CODE-4"],
    "EXTRA001":  ["MASVS-PRIVACY-1"],     # FIX: era PLATFORM-1 — permisos peligrosos
    # ── Reglas nativas (native_scanner) ──────────────────────────────────────
    "NAT001":    ["MASVS-CODE-4"],
    "NAT002":    ["MASVS-CODE-4"],
    "NAT003":    ["MASVS-RESILIENCE-4"],  # FIX: era RESILIENCE-2 — anti-debug es anti-dynamic-analysis
    "NAT004":    ["MASVS-STORAGE-2"],
    "NAT005":    ["MASVS-NETWORK-1"],
    "NAT006":    ["MASVS-RESILIENCE-1"],
    "NAT007":    ["MASVS-NETWORK-1", "MASVS-NETWORK-2"],
    "NAT008":    ["MASVS-CRYPTO-1"],
}

# MASWE: solo se listan las reglas donde hay una debilidad MASWE con
# correspondencia semántica clara y verificable en MASWE_CATALOG. Reglas sin
# entrada aquí no tienen (todavía) un mapeo MASWE de confianza suficiente.
RULE_TO_MASWE: dict[str, list[str]] = {
    "HC001":     ["MASWE-0005"],   # API Keys Hardcoded in the App Package
    "HC002":     ["MASWE-0002"],
    "HC003":     ["MASWE-0013"],   # Hardcoded Cryptographic Keys in Use
    "HC004":     ["MASWE-0005"],
    "HC005":     ["MASWE-0005"],
    "HC006":     ["MASWE-0013"],
    "ST001":     ["MASWE-0006"],   # Sensitive Data Stored Unencrypted in Private Storage
    "ST002":     ["MASWE-0002"],
    "ST003":     ["MASWE-0007"],   # ...Unencrypted in Shared Storage
    "ST004":     ["MASWE-0006"],
    "ST005":     ["MASWE-0053"],   # Sensitive Data Leaked via the UI
    "NET001":    ["MASWE-0050"],   # Cleartext Traffic
    "NET002":    ["MASWE-0052"],   # Insecure Certificate Validation
    "NET003":    ["MASWE-0052"],
    "NET005":    ["MASWE-0047"],   # Insecure Identity Pinning
    "NET006":    ["MASWE-0052"],
    "AUTH001":   ["MASWE-0001"],   # Insertion of Sensitive Data into Logs
    "CRYPTO001": ["MASWE-0021"],   # Improper Hashing (MD5)
    "CRYPTO002": ["MASWE-0021"],   # Improper Hashing (SHA-1)
    "CRYPTO003": ["MASWE-0020"],   # Improper Encryption (DES/3DES)
    "CRYPTO004": ["MASWE-0020"],   # Improper Encryption (AES/ECB)
    "CRYPTO005": ["MASWE-0022"],   # Predictable IVs
    "CRYPTO006": ["MASWE-0027"],   # Improper Random Number Generation
    "COMP001":   ["MASWE-0072"],   # Universal XSS
    "COMP002":   ["MASWE-0069"],   # WebViews Allows Access to Local Resources
    "COMP003":   ["MASWE-0068"],   # JavaScript Bridges in WebViews
    "COMP004":   ["MASWE-0063"],   # Insecure Broadcast Receivers
    "COMP005":   ["MASWE-0072"],
    "COMP006":   ["MASWE-0119"],   # Insecure Activities
    "COMP007":   ["MASWE-0062"],   # Insecure Services
    "COMP008":   ["MASWE-0064"],   # Insecure Content Providers
    "INFO001":   ["MASWE-0067"],   # Debuggable Flag Not Disabled
    "INJ001":    ["MASWE-0086"],   # SQL Injection
    "INJ002":    ["MASWE-0081"],   # Unsafe Handling Of Data From External Interfaces
    "INJ003":    ["MASWE-0081"],
    "INJ004":    ["MASWE-0058"],   # Insecure Deep Links
    "DBG001":    ["MASWE-0095"],   # Code That Disables Security Controls Not Removed
    "DBG002":    ["MASWE-0001"],
    "DBG003":    ["MASWE-0001"],
    "DESER001":  ["MASWE-0088"],   # Insecure Object Deserialization
    "EXTRA001":  ["MASWE-0117"],   # Inadequate Permission Management
    "NAT003":    ["MASWE-0101"],   # Debugger Detection Not Implemented
    "NAT004":    ["MASWE-0002"],
    "NAT005":    ["MASWE-0052"],
    "NAT007":    ["MASWE-0047"],
    "NAT008":    ["MASWE-0020", "MASWE-0021"],
}

# CWE: solo los well-established, sin ambigüedad (misma prudencia que MASWE).
RULE_TO_CWE: dict[str, list[str]] = {
    "HC001":     ["CWE-798"],   # Use of Hard-coded Credentials
    "HC002":     ["CWE-798"],
    "HC003":     ["CWE-798", "CWE-321"],
    "HC004":     ["CWE-798"],
    "HC005":     ["CWE-798"],
    "HC006":     ["CWE-321"],   # Use of Hard-coded Cryptographic Key
    "ST001":     ["CWE-312"],   # Cleartext Storage of Sensitive Information
    "ST002":     ["CWE-732"],   # Incorrect Permission Assignment
    "ST003":     ["CWE-922"],   # Insecure Storage of Sensitive Information
    "ST004":     ["CWE-312"],
    "NET001":    ["CWE-319"],   # Cleartext Transmission of Sensitive Information
    "NET002":    ["CWE-295"],   # Improper Certificate Validation
    "NET003":    ["CWE-295"],
    "NET004":    ["CWE-327"],   # Broken/Risky Cryptographic Algorithm
    "NET006":    ["CWE-295"],
    "AUTH001":   ["CWE-532"],   # Insertion of Sensitive Information into Log File
    "CRYPTO001": ["CWE-328"],   # Use of Weak Hash
    "CRYPTO002": ["CWE-328"],
    "CRYPTO003": ["CWE-327"],
    "CRYPTO004": ["CWE-327"],
    "CRYPTO005": ["CWE-329"],   # Not Using a Random IV with CBC Mode
    "CRYPTO006": ["CWE-330"],   # Use of Insufficiently Random Values
    "COMP001":   ["CWE-79"],
    "COMP002":   ["CWE-200"],
    "COMP003":   ["CWE-749"],   # Exposed Dangerous Method or Function
    "COMP004":   ["CWE-925"],   # Improper Verification of Intent by Broadcast Receiver
    "COMP005":   ["CWE-79"],
    "COMP006":   ["CWE-926"],   # Improper Export of Android Application Components
    "COMP007":   ["CWE-926"],
    "COMP008":   ["CWE-926"],
    "INFO001":   ["CWE-489"],   # Active Debug Code
    "INJ001":    ["CWE-89"],
    "INJ002":    ["CWE-22"],    # Path Traversal
    "INJ003":    ["CWE-78"],    # OS Command Injection
    "INJ004":    ["CWE-926"],
    "DBG001":    ["CWE-489"],
    "DBG002":    ["CWE-532"],
    "DBG003":    ["CWE-209"],   # Generation of Error Message Containing Sensitive Information
    "DESER001":  ["CWE-502"],   # Deserialization of Untrusted Data
    "EXTRA001":  ["CWE-250"],   # Execution with Unnecessary Privileges
    "NAT001":    ["CWE-120"],   # Buffer Copy without Checking Size of Input
    "NAT002":    ["CWE-78"],
    "NAT004":    ["CWE-798"],
    "NAT005":    ["CWE-295"],
    "NAT008":    ["CWE-327"],
}

# ── Peso base de cada categoría ───────────────────────────────────────────────
# Nota: informativo/documental únicamente — build_masvs_report() usa
# penalizaciones planas desde 100 (_SEVERITY_PENALTY / _NO_PROTECT_PENALTY /
# _BYPASS_PENALTY), no una suma ponderada por categoría.

# ── Mapeo detectores → MASVS ──────────────────────────────────────────────────
# FIX (Fase 2): "APK signature verification" estaba en RESILIENCE-4; el texto
# oficial de RESILIENCE-2 menciona literalmente "checking the application
# package signature" → movida a RESILIENCE-2. La detección de Frida (dentro
# de "Anti Magisk / SuperSU / KernelSU / Frida") es anti-dynamic-analysis
# (RESILIENCE-4), no anti-tampering (RESILIENCE-2) → se añadió RESILIENCE-4.
DETECTOR_TO_MASVS: dict[str, list[str]] = {
    # Claves = detector.name tal como están definidas en cada clase detector
    "Known anti-root libraries":                 ["MASVS-RESILIENCE-1"],
    "SafetyNet / Play Integrity API":            ["MASVS-RESILIENCE-1"],
    "Manual root checks":                        ["MASVS-RESILIENCE-1"],
    "Anti Magisk / SuperSU / KernelSU / Frida":  ["MASVS-RESILIENCE-1", "MASVS-RESILIENCE-4"],
    "DexGuardDetector":                          ["MASVS-RESILIENCE-2", "MASVS-RESILIENCE-3",
                                                  "MASVS-RESILIENCE-4"],
    "AppDome":                                   ["MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2",
                                                  "MASVS-RESILIENCE-3", "MASVS-RESILIENCE-4"],
    "APK signature verification":               ["MASVS-RESILIENCE-2"],  # FIX: era RESILIENCE-4
    "Certificate pinning":                       ["MASVS-NETWORK-2"],
}

# Detectores que son "solo positivos": si no detectan nada no implica fallo,
# el control queda not_tested (no se flipa a no_protection).
_POSITIVE_ONLY_DETECTORS: frozenset[str] = frozenset({
    "Certificate pinning",
})

# ── Mapeo misconfigs del manifest → MASVS ────────────────────────────────────
# Cada entrada: (fragmento del título de Misconfiguration, [control_ids]).
# El fragmento se busca como substring en misconfig.title (no solo prefijo),
# para soportar títulos con contenido dinámico al inicio (p.ej. "3 high-risk
# permission(s)").
MISCONFIG_TO_MASVS: list[tuple[str, list[str]]] = [
    # ── These titles are the same in both languages ───────────────────────────
    ('android:debuggable="true"',               ["MASVS-RESILIENCE-4"]),  # FIX: era CODE-2
    ('android:allowBackup="true"',              ["MASVS-STORAGE-2"]),     # FIX: era STORAGE-1
    ('android:usesCleartextTraffic="true"',     ["MASVS-NETWORK-1"]),
    ('AWS Access Key',                          ["MASVS-STORAGE-2"]),
    ('Firebase Realtime DB URL',                ["MASVS-STORAGE-2"]),
    ('Firebase API Key',                        ["MASVS-STORAGE-2"]),
    ('Google Maps API Key',                     ["MASVS-STORAGE-2"]),
    # ── Nuevas coberturas reales (antes sin mapear) ────────────────────────────
    ('Low targetSdkVersion (',                  ["MASVS-CODE-1"]),
    ('targetSdkVersion bajo (',                 ["MASVS-CODE-1"]),
    ('high-risk permission(s)',                 ["MASVS-PRIVACY-1"]),
    ('permiso(s) de alto riesgo',                ["MASVS-PRIVACY-1"]),
    ('No certificate pinning in Network Security Config', ["MASVS-NETWORK-2"]),
    ('Sin certificate pinning en Network Security Config', ["MASVS-NETWORK-2"]),
    # ── Spanish ───────────────────────────────────────────────────────────────
    ('Sin android:networkSecurityConfig',       ["MASVS-NETWORK-1"]),
    ('Sin Network Security Config y cleartext', ["MASVS-NETWORK-1"]),
    ('Confía en CAs del usuario',          ["MASVS-NETWORK-2"]),
    ('Cleartext permitido para dominio',        ["MASVS-NETWORK-1"]),
    ('<activity> exportado sin permiso',        ["MASVS-PLATFORM-1"]),
    ('<service> exportado sin permiso',         ["MASVS-PLATFORM-1"]),
    ('<receiver> exportado sin permiso',        ["MASVS-PLATFORM-1"]),
    ('<provider> exportado sin permiso',        ["MASVS-PLATFORM-1"]),
    ('API Key hardcodeada',                     ["MASVS-STORAGE-2"]),
    ('JWT Token hardcodeado',                   ["MASVS-STORAGE-2"]),     # FIX: quitado AUTH-2 (no aplica)
    ('IP privada hardcodeada',                  ["MASVS-NETWORK-1"]),
    ('Posible contraseña hardcodeada',     ["MASVS-STORAGE-2"]),
    # ── English ───────────────────────────────────────────────────────────────
    ('No android:networkSecurityConfig',        ["MASVS-NETWORK-1"]),
    ('No Network Security Config and cleartext',["MASVS-NETWORK-1"]),
    ('Trusts user CAs',                         ["MASVS-NETWORK-2"]),
    ('Cleartext allowed for domain',            ["MASVS-NETWORK-1"]),
    ('<activity> exported without permission',  ["MASVS-PLATFORM-1"]),
    ('<service> exported without permission',   ["MASVS-PLATFORM-1"]),
    ('<receiver> exported without permission',  ["MASVS-PLATFORM-1"]),
    ('<provider> exported without permission',  ["MASVS-PLATFORM-1"]),
    ('Hardcoded API Key',                       ["MASVS-STORAGE-2"]),
    ('Hardcoded JWT Token',                     ["MASVS-STORAGE-2"]),     # FIX: quitado AUTH-2
    ('Hardcoded Private IP',                    ["MASVS-NETWORK-1"]),
    ('Possible hardcoded password',             ["MASVS-STORAGE-2"]),
]

# ── Parámetros de penalización ────────────────────────────────────────────────

_SEVERITY_PENALTY: dict[str, int] = {
    "critical": 8,
    "high":     5,
    "medium":   3,
    "low":      1,
    "info":     0,
}
# Penalización por control individual sin protección detectada (suma = peso categoría RESILIENCE = 20)
_NO_PROTECT_PENALTY: dict[str, int] = {
    "MASVS-RESILIENCE-1": 5,
    "MASVS-RESILIENCE-2": 5,
    "MASVS-RESILIENCE-3": 5,
    "MASVS-RESILIENCE-4": 5,
}

# Penalización por control individual cuando el bypass está confirmado (Frida/FART)
_BYPASS_PENALTY: dict[str, int] = {
    "MASVS-RESILIENCE-1": 4,
    "MASVS-RESILIENCE-2": 4,
    "MASVS-RESILIENCE-3": 4,
    "MASVS-RESILIENCE-4": 3,
}

_MAX_PENALTY_PER_CTRL  = 20   # tope de penalización por control (aplica solo a hallazgos vuln_scanner)


# ── Dataclasses del reporte ───────────────────────────────────────────────────

@dataclass
class MASVSControlResult:
    """Estado de un control MASVS individual."""
    control_id: str
    description: str
    # pass | fail | bypass | no_protection | not_tested
    status: str
    penalty: int
    finding_count: int
    # IDs de reglas del vuln_scanner que apuntan a este control
    finding_rule_ids: list[str] = field(default_factory=list)
    # Nombres de detectores del analyzer que cubren este control
    detector_names: list[str] = field(default_factory=list)
    # Títulos cortos de misconfigs del manifest que afectan este control
    misconfig_titles: list[str] = field(default_factory=list)
    # Debilidades MASWE y CWE agregadas de las reglas que dispararon este control
    maswe_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "control_id":       self.control_id,
            "description":      self.description,
            "status":           self.status,
            "penalty":          self.penalty,
            "finding_count":    self.finding_count,
            "finding_rule_ids": self.finding_rule_ids,
            "detector_names":   self.detector_names,
            "misconfig_titles": self.misconfig_titles,
            "maswe_ids":        self.maswe_ids,
            "cwe_ids":          self.cwe_ids,
        }


@dataclass
class MASVSReport:
    """Reporte completo de cumplimiento MASVS v2.1."""
    controls: list[MASVSControlResult]
    score: int          # 0-100
    grade: str          # A / B / C / D / F
    bypass_confirmed: bool
    total_findings: int

    @property
    def failed_controls(self) -> list[MASVSControlResult]:
        return [c for c in self.controls if c.status not in ("pass", "not_tested")]

    @property
    def passed_controls(self) -> list[MASVSControlResult]:
        return [c for c in self.controls if c.status == "pass"]

    def to_dict(self) -> dict:
        status_counts: dict[str, int] = {}
        for c in self.controls:
            status_counts[c.status] = status_counts.get(c.status, 0) + 1
        return {
            "score":            self.score,
            "grade":            self.grade,
            "bypass_confirmed": self.bypass_confirmed,
            "total_findings":   self.total_findings,
            "summary": {
                "pass":          status_counts.get("pass", 0),
                "fail":          status_counts.get("fail", 0),
                "bypass":        status_counts.get("bypass", 0),
                "no_protection": status_counts.get("no_protection", 0),
                "not_tested":    status_counts.get("not_tested", 0),
            },
            "controls": [c.to_dict() for c in self.controls],
        }


# ── Constructor del reporte ───────────────────────────────────────────────────

def build_masvs_report(
    analysis: "AnalysisResult",
    scan: "ScanResult | None" = None,
    manifest: "ManifestAnalysisResult | None" = None,
) -> MASVSReport:
    """
    Construye un MASVSReport cruzando AnalysisResult (detectors) + ScanResult (vuln_scanner)
    + ManifestAnalysisResult (misconfigs).

    Algoritmo de puntuación:
      - Arranca en 100 puntos.
      - Cada hallazgo de vuln_scanner descuenta según severidad (máx. _MAX_PENALTY_PER_CTRL
        por control para no hundir un solo control con muchos hallazgos).
      - Control de resilience sin protección detectada: descuento específico por control
        (_NO_PROTECT_PENALTY[cid], por defecto 5 pts).
      - Bypass confirmado (Frida/FART extrajo DEX): descuento específico por control
        (_BYPASS_PENALTY[cid], por defecto 4 pts).
      - Score final = max(0, 100 - suma_de_penalizaciones).

    Grados:
      A (90-100) · B (75-89) · C (50-74) · D (25-49) · F (0-24)
    """

    # 1. Inicializar todos los controles como not_tested
    control_map: dict[str, MASVSControlResult] = {
        cid: MASVSControlResult(
            control_id=cid,
            description=desc,
            status="not_tested",
            penalty=0,
            finding_count=0,
        )
        for cid, desc in MASVS_CONTROLS.items()
    }

    # Controles que pueden ser evaluados por el vuln_scanner (tienen reglas mapeadas)
    _scanner_evaluable: set[str] = {cid for cids in RULE_TO_MASVS.values() for cid in cids}

    # 2. Procesar hallazgos del vuln_scanner
    total_findings = 0
    if scan is not None:
        sev_order = ["critical", "high", "medium", "low", "info"]

        # Agrupar por rule_id para penalizar por grupo, no por hallazgo individual
        findings_by_rule: dict[str, list] = {}
        for f in scan.findings:
            findings_by_rule.setdefault(f.rule_id, []).append(f)

        for rule_id, findings in findings_by_rule.items():
            masvs_ids = RULE_TO_MASVS.get(rule_id, [])
            if not masvs_ids:
                continue

            total_findings += len(findings)

            # Severidad máxima del grupo
            worst_idx = min(
                (sev_order.index(f.severity) for f in findings if f.severity in sev_order),
                default=len(sev_order) - 1,
            )
            penalty_per = _SEVERITY_PENALTY.get(sev_order[worst_idx], 0)

            maswe_ids = RULE_TO_MASWE.get(rule_id, [])
            cwe_ids = RULE_TO_CWE.get(rule_id, [])

            for cid in masvs_ids:
                ctrl = control_map.get(cid)
                if ctrl is None:
                    continue
                ctrl.status = "fail"
                ctrl.finding_count += len(findings)
                if rule_id not in ctrl.finding_rule_ids:
                    ctrl.finding_rule_ids.append(rule_id)
                for mid in maswe_ids:
                    if mid not in ctrl.maswe_ids:
                        ctrl.maswe_ids.append(mid)
                for cwe in cwe_ids:
                    if cwe not in ctrl.cwe_ids:
                        ctrl.cwe_ids.append(cwe)
                ctrl.penalty = min(
                    ctrl.penalty + penalty_per * len(findings),
                    _MAX_PENALTY_PER_CTRL,
                )

        # 2b. Si el scanner corrió y no encontró nada para un control evaluable → pass
        # Excluir controles RESILIENCE y NETWORK-2: requieren confirmación positiva del detector
        _no_autopass = frozenset({"MASVS-NETWORK-2"})
        for cid, ctrl in control_map.items():
            if cid in _scanner_evaluable and ctrl.status == "not_tested":
                if not cid.startswith("MASVS-RESILIENCE") and cid not in _no_autopass:
                    ctrl.status = "pass"

    # 2c. Procesar misconfigurations del manifest
    if manifest is not None:
        for misconfig in manifest.misconfigurations:
            masvs_ids: list[str] = []
            for title_fragment, cids in MISCONFIG_TO_MASVS:
                if title_fragment in misconfig.title:
                    masvs_ids = cids
                    break
            if not masvs_ids:
                continue
            penalty = _SEVERITY_PENALTY.get(misconfig.severity, 0)
            for cid in masvs_ids:
                ctrl = control_map.get(cid)
                if ctrl is None:
                    continue
                ctrl.status = "fail"
                ctrl.finding_count += 1
                ctrl.penalty = min(ctrl.penalty + penalty, _MAX_PENALTY_PER_CTRL)
                short_title = misconfig.title[:30]
                if short_title not in ctrl.misconfig_titles:
                    ctrl.misconfig_titles.append(short_title)

    # 3. Procesar detecciones del analyzer (resilience)
    for det in analysis.results:
        masvs_ids = DETECTOR_TO_MASVS.get(det.name, [])
        if not masvs_ids:
            continue

        for cid in masvs_ids:
            ctrl = control_map.get(cid)
            if ctrl is None:
                continue

            if det.name not in ctrl.detector_names:
                ctrl.detector_names.append(det.name)

            if det.detected:
                # Protección presente → pass (solo si no hay un fail de vuln_scanner)
                if ctrl.status in ("not_tested", "no_protection"):
                    ctrl.status = "pass"
                    ctrl.penalty = 0
            else:
                # Sin protección para este control de resiliencia
                # Los detectores "solo positivos" no implican fallo si no detectan nada
                if ctrl.status in ("not_tested",) and det.name not in _POSITIVE_ONLY_DETECTORS:
                    ctrl.status = "no_protection"
                    ctrl.penalty = _NO_PROTECT_PENALTY.get(cid, 5)

    # 4. Aplicar bypass si la protección fue rota en runtime.
    # ROADMAP "Differentiate runtime bypass vs DEX extraction": protection_broken
    # exige dex_count > 0 (extracción exitosa), pero el plugin aipwn puede
    # confirmar un bypass runtime real (report_success del FridaAgent) sin
    # llegar a volcar DEX — igual debe reflejarse aquí.
    bypass_confirmed = analysis.protection_broken or analysis.aipwn_bypass_confirmed
    if bypass_confirmed:
        for cid, ctrl in control_map.items():
            if not cid.startswith("MASVS-RESILIENCE"):
                continue
            if ctrl.status in ("pass", "no_protection", "fail"):
                ctrl.status = "bypass"
                ctrl.penalty = _BYPASS_PENALTY.get(cid, 4)

    # 5. Calcular puntuación final
    total_penalty = sum(c.penalty for c in control_map.values())
    score = max(0, 100 - total_penalty)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 25:
        grade = "D"
    else:
        grade = "F"

    return MASVSReport(
        controls=list(control_map.values()),
        score=score,
        grade=grade,
        bypass_confirmed=bypass_confirmed,
        total_findings=total_findings,
    )
