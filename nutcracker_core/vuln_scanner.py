"""
Scanner de vulnerabilidades sobre código decompilado (Java/Kotlin/Smali).

Analiza los archivos fuente generados por jadx o apktool buscando patrones
conocidos de vulnerabilidades Android (OWASP Mobile Top 10).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class VulnFinding:
    """Una vulnerabilidad encontrada en el código fuente."""
    rule_id: str
    title: str
    severity: str          # critical / high / medium / low / info
    category: str          # OWASP M-number o categoría propia
    file: Path
    line: int
    matched_text: str
    description: str
    recommendation: str

    def relative_path(self, base: Path) -> str:
        try:
            return str(self.file.relative_to(base))
        except ValueError:
            return str(self.file)


@dataclass
class VulnRule:
    """Regla de detección basada en regex."""
    rule_id: str
    title: str
    severity: str
    category: str
    pattern: re.Pattern
    description: str
    recommendation: str
    # Si se especifica, solo aplica a archivos cuyo path contenga este substring
    file_filter: str | None = None
    # Líneas a ignorar si contienen alguno de estos strings (reduce falsos positivos)
    ignore_if_contains: list[str] = field(default_factory=list)


# ── Reglas de detección ───────────────────────────────────────────────────────

RULES: list[VulnRule] = [

    # ── M1: Credenciales / Secretos hardcodeados ──────────────────────────────
    VulnRule(
        rule_id="HC001",
        title="API key hardcodeada",
        severity="high",
        category="M1 - Credenciales",
        pattern=re.compile(
            r'(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*["\'][A-Za-z0-9/+_\-]{16,}["\']'
        ),
        description="Clave de API embebida directamente en el código fuente.",
        recommendation="Almacenar credenciales en el servidor o usar Android Keystore.",
    ),
    VulnRule(
        rule_id="HC002",
        title="Contraseña hardcodeada",
        severity="critical",
        category="M1 - Credenciales",
        pattern=re.compile(
            r'(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*["\'][^"\']{6,}["\']'
        ),
        description="Contraseña o secreto embebido en el código.",
        recommendation="Nunca almacenar credenciales en el código. Usar un gestor de secretos.",
        ignore_if_contains=[
            "TODO", "example", "test", "placeholder", "your_", "<", "xxx",
            # Reducir FP: toString()/debug strings que concatenan campos con "token" en el nombre
            "return \"", "+ this.", "+ self.", ".toString()",
            # Constantes que son nombres de claves, no valores secretos
            "PREFS_", "_PREFS", "KEY_", "EXTRA_", "_ACTION",
            "INTENT_", "_FILENAME", "_STATUS", "_TYPE", "_NAME",
            "KEYBOARD_TYPE", "com.google.", "com.facebook.", "com.onesignal.",
            "com.ownid.", "_TAG",
            # FP: valores que son nombres de acciones/paquetes (contienen puntos)
            # p.ej. ACCESS_TOKEN = "com.huawei.hms.account.getAssistToken"
            # FP: valores que son el mismo nombre de la constante (ACCESS_TOKEN = "ACCESSTOKEN")
            # → detectados por el patrón de valor == nombre-de-var en mayúsculas
            # FP: valores que son patrones regex o mensajes de error
            "INVALID_", "invalid null", "invalid.",
        ],
    ),
    VulnRule(
        rule_id="HC003",
        title="Clave privada / certificado embebido",
        severity="critical",
        category="M1 - Credenciales",
        pattern=re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
        description="Clave privada RSA/EC embebida en el código.",
        recommendation="Las claves privadas nunca deben incluirse en el APK.",
    ),
    VulnRule(
        rule_id="HC004",
        title="Firebase / Google credentials hardcodeadas",
        severity="high",
        category="M1 - Credenciales",
        pattern=re.compile(
            r'(?i)(AIza[0-9A-Za-z\-_]{35}|AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})'
        ),
        description="Google API key (AIza...) o FCM server key encontrada en el código.",
        recommendation="Restringir la API key en Google Cloud Console y no embebir en el APK.",
    ),
    VulnRule(
        rule_id="HC005",
        title="AWS credentials hardcodeadas",
        severity="critical",
        category="M1 - Credenciales",
        pattern=re.compile(r'(?i)(AKIA|AIPA|ASIA)[0-9A-Z]{16}'),
        description="AWS Access Key ID encontrada en el código.",
        recommendation="Revocar la clave inmediatamente y nunca incluir credenciales AWS en el APK.",
    ),
    VulnRule(
        rule_id="HC006",
        title="Clave/IV criptografica hardcodeada",
        severity="high",
        category="M1 - Credenciales",
        pattern=re.compile(
            # Requiere que aes/cipher/crypto/encrypt/decrypt/secret sean tokens completos
            # en el nombre de variable (delimitados por _ o CamelCase).
            # "iv" requiere delimitador _ para evitar FP con "activity", "native", "received", etc.
            r'(?i)\b(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?'
            r'(?:String|java\.lang\.String|char\[\]|byte\[\])\s+'
            r'[A-Za-z0-9_]*(?:aes|(?:_|^)iv(?:_|\b)|cipher|crypto|encrypt|decrypt|'
            r'secret_?key)[A-Za-z0-9_]*\s*='
            r'\s*["\'][^"\']{6,}["\']'
        ),
        description="Material criptografico (key/iv/aes) embebido como constante en el código.",
        recommendation="Generar y gestionar claves/IV de forma segura (Keystore/KMS) y no hardcodearlas.",
        ignore_if_contains=[
            "example", "test", "placeholder", "dummy", "sample", "your_",
            # Reducir FP: constantes de framework/SDK que no son material cripto
            "ACTIVITY", "activity", "_ACTION", "_STATUS", "_STATE",
            "_OP", "_TAG", "_NAME", "_MESSAGE", "_FILE", "_MARKER",
            "_HEADER", "_VERSION", "_SDK", "_RECEIVER", "_PROFILE",
            "NATIVE", "DELIVERED", "RECEIVED", "PRIMITIVE",
            # FP: nombres de cipher suites / algoritmos, no claves reales
            # p.ej. CIPHER_ALGORITHM = "AES/CBC/NoPadding", RSA_CIPHER = "RSA/ECB/PKCS1Padding"
            "/NoPadding", "/PKCS1Padding", "/PKCS5Padding", "NoPadding",
            # FP: nombres de cipher suites TLS/PBE
            "SSL_NULL", "PBEWITH", "KEYTRIPLEDES", "Twofish",
            # FP: OIDs (2.16.840.x.x)
            "2.16.840.",
            # FP: kernel crypto API ("cmac(aes)", "xcbc(aes)", "rfc4106(gcm(aes))")
            "cmac(", "xcbc(", "gcm(", "cbc(", "ctr(", "rfc",
            # FP: constantes de seguridad de capas inferiores (Bluetooth, IPSec)
            "Insufficient", "cipher_suite", "encryptedStorage",
            "encryptionAlgorithm", "inBandCrypto",
        ],
    ),
    VulnRule(
        rule_id="HC007",
        title="URL de producción/API hardcodeada",
        severity="medium",
        category="M1 - Credenciales",
        pattern=re.compile(
            r'(?i)(?:public\s+)?(?:static\s+)?(?:final\s+)?(?:String|java\.lang\.String)\s+'
            r'[A-Za-z0-9_]*(?:URL|HOST|ENDPOINT|BASE|SERVER|BACKEND|SERVICE)[A-Za-z0-9_]*'
            r'\s*=\s*"(https?://[^"]{8,})"'
        ),
        description="URL de producción o endpoint de API expuesta como constante en el código.",
        recommendation=(
            "Centralizar URLs en configuración remota. "
            "URLs de producción expuestas revelan la superficie de ataque de la API."
        ),
        ignore_if_contains=[
            "localhost", "127.0.0.1", "10.0.", "192.168.", "example.com",
            "schemas.android.com", "www.w3.org", "xmlpull.org",
            "schema.org", "xml.org",
        ],
    ),
    VulnRule(
        rule_id="HC008",
        title="URL de servicio tercero (KYC/Auth/Pagos) hardcodeada",
        severity="high",
        category="M1 - Credenciales",
        pattern=re.compile(
            r'(?i)(?:public\s+)?(?:static\s+)?(?:final\s+)?(?:String|java\.lang\.String)\s+'
            r'\w+\s*=\s*"(https?://[^"]*'
            r'(?:incode|incodesmile|onfido|jumio|veriff|sumsub'
            r'|auth0|okta|cognito|keycloak'
            r'|stripe|adyen|mercadopago|checkout\.com'
            r'|plaid|belvo|salt\.edge|openbanking'
            r')[^"]*)"'
        ),
        description=(
            "URL de servicio crítico (KYC, autenticación o pagos) hardcodeada. "
            "Combinada con API keys expuestas, permite interacción directa con el servicio."
        ),
        recommendation=(
            "Nunca exponer URLs de servicios de identidad, pagos o autenticación en el APK. "
            "Proxy todas las llamadas a través del backend propio."
        ),
    ),

    # ── M2: Almacenamiento inseguro ───────────────────────────────────────────
    VulnRule(
        rule_id="ST001",
        title="SharedPreferences sin cifrado",
        severity="medium",
        category="M2 - Almacenamiento inseguro",
        pattern=re.compile(
            r'getSharedPreferences\s*\(|\.edit\s*\(\s*\)\s*\.put(String|Int|Boolean|Float|Long)\s*\('
        ),
        description="Uso de SharedPreferences sin cifrado. Los datos son accesibles en dispositivos rooteados.",
        recommendation="Usar EncryptedSharedPreferences de androidx.security.crypto.",
    ),
    VulnRule(
        rule_id="ST002",
        title="Escritura de archivo world-readable/world-writable",
        severity="high",
        category="M2 - Almacenamiento inseguro",
        pattern=re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'),
        description="Archivo creado con permisos accesibles por otras apps.",
        recommendation="Usar MODE_PRIVATE para archivos de la aplicación.",
    ),
    VulnRule(
        rule_id="ST003",
        title="Datos sensibles en almacenamiento externo",
        severity="high",
        category="M2 - Almacenamiento inseguro",
        pattern=re.compile(r'getExternalStorage|getExternalFilesDir|Environment\.getExternalStorageDirectory'),
        description="Escritura de datos en almacenamiento externo (SD card), accesible sin permisos.",
        recommendation="Almacenar datos sensibles solo en almacenamiento interno.",
    ),
    VulnRule(
        rule_id="ST004",
        title="Base de datos SQLite sin cifrado",
        severity="medium",
        category="M2 - Almacenamiento inseguro",
        pattern=re.compile(r'openOrCreateDatabase|SQLiteOpenHelper|Room\.databaseBuilder'),
        description="Base de datos SQLite sin cifrado, accesible en dispositivos rooteados.",
        recommendation="Usar SQLCipher o Room con EncryptedDatabase para datos sensibles.",
    ),

    # ── M3: Comunicación insegura ─────────────────────────────────────────────
    VulnRule(
        rule_id="NET001",
        title="URL HTTP (sin TLS)",
        severity="high",
        category="M3 - Comunicación insegura",
        pattern=re.compile(r'["\']http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|schema|example)[\w.]'),
        description="Comunicación HTTP en texto claro. Susceptible a ataques MITM.",
        recommendation="Usar HTTPS en todas las comunicaciones de red.",
    ),
    VulnRule(
        rule_id="NET002",
        title="Validación SSL deshabilitada (TrustManager permisivo)",
        severity="critical",
        category="M3 - Comunicación insegura",
        pattern=re.compile(
            r'(checkClientTrusted|checkServerTrusted)\s*\([^)]*\)\s*\{?\s*\}|'
            r'getAcceptedIssuers\s*\(\s*\)\s*\{?\s*return\s+null|'
            r'ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier'
        ),
        description="TrustManager que acepta cualquier certificado SSL. Vulnerable a MITM total.",
        recommendation="Implementar Certificate Pinning o usar el TrustManager del sistema.",
    ),
    VulnRule(
        rule_id="NET003",
        title="Certificate pinning deshabilitado (OkHttp)",
        severity="high",
        category="M3 - Comunicación insegura",
        pattern=re.compile(r'hostnameVerifier\s*\{[^}]*true\s*\}|\.build\(\).*hostnameVerifier'),
        description="HostnameVerifier que devuelve true sin verificar el certificado.",
        recommendation="Implementar validación correcta del hostname.",
    ),

    # ── M4: Autenticación insegura ────────────────────────────────────────────
    VulnRule(
        rule_id="AUTH001",
        title="Token/sesión en logs",
        severity="high",
        category="M4 - Autenticación insegura",
        pattern=re.compile(
            # Requiere que token/session/auth/jwt/bearer aparezcan como palabras
            # completas (delimitadas) para evitar FP con "CameraSession", "keylines", etc.
            r'(?i)Log\.[dDiIeEwWvV]\s*\([^,]+,\s*[^)]*'
            r'(?:(?:^|[\s"\+\(\.,])(?:token|auth|bearer|jwt)(?:[\s"\+\)\.,;]|$)|'
            r'(?:session[_\s]?(?:id|token|key|expire|cookie)))[^)]*\)'
        ),
        description="Posible token de autenticación enviado a los logs del sistema.",
        recommendation="Nunca loguear tokens, sesiones o datos de autenticación.",
        ignore_if_contains=[
            # Framework tags comunes que no son leaks de auth
            "CameraSession", "CameraView", "BiometricPrompt", "BiometricFragment",
            "BiometricManager", "FragmentManager", "CoordinatorLayout",
            "MotionController", "ExifInterface", "MediaMetadata",
            "NotificationManager", "DiskLruCacheWrapper", "SourceGenerator",
            "ActivityResultRegistry", "CancelSignalProvider",
            "PhenotypeClientHelper", "Gservices",
        ],
    ),

    # ── M5: Criptografía débil ────────────────────────────────────────────────
    VulnRule(
        rule_id="CRYPTO001",
        title="Algoritmo MD5 en uso",
        severity="medium",
        category="M5 - Criptografía débil",
        pattern=re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']'),
        description="MD5 es criptográficamente roto. No apto para hashing de contraseñas o integridad.",
        recommendation="Usar SHA-256 o superior. Para contraseñas, usar BCrypt/Argon2.",
    ),
    VulnRule(
        rule_id="CRYPTO002",
        title="Algoritmo SHA-1 en uso",
        severity="low",
        category="M5 - Criptografía débil",
        pattern=re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']'),
        description="SHA-1 está deprecado para uso criptográfico.",
        recommendation="Usar SHA-256 o superior.",
    ),
    VulnRule(
        rule_id="CRYPTO003",
        title="DES / 3DES en uso",
        severity="high",
        category="M5 - Criptografía débil",
        pattern=re.compile(r'Cipher\.getInstance\s*\(\s*["\']DES|["\']DESede'),
        description="DES y 3DES son algoritmos débiles con claves cortas.",
        recommendation="Usar AES-256-GCM.",
    ),
    VulnRule(
        rule_id="CRYPTO004",
        title="AES en modo ECB",
        severity="high",
        category="M5 - Criptografía débil",
        pattern=re.compile(r'Cipher\.getInstance\s*\(\s*["\']AES/ECB|["\']AES["\']'),
        description="El modo ECB no oculta patrones en los datos cifrados.",
        recommendation="Usar AES/GCM/NoPadding con IV aleatorio.",
    ),
    VulnRule(
        rule_id="CRYPTO005",
        title="IV estático o hardcodeado",
        severity="high",
        category="M5 - Criptografía débil",
        pattern=re.compile(
            r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{|'
            r'IvParameterSpec\s*\(\s*["\'][^"\']{8,}["\']\.getBytes'
        ),
        description="Vector de inicialización (IV) estático. Reutilizar IV anula la seguridad del cifrado.",
        recommendation="Generar un IV aleatorio con SecureRandom para cada operación de cifrado.",
    ),
    VulnRule(
        rule_id="CRYPTO006",
        title="java.util.Random en lugar de SecureRandom",
        severity="medium",
        category="M5 - Criptografía débil",
        pattern=re.compile(r'new\s+Random\s*\(\s*\)|Random\s+\w+\s*=\s*new\s+Random'),
        description="java.util.Random es predecible. No apto para uso criptográfico.",
        recommendation="Usar java.security.SecureRandom para valores criptográficos.",
        ignore_if_contains=["SecureRandom", "//", "test", "mock"],
    ),

    # ── M6: Autorización insegura ─────────────────────────────────────────────
    VulnRule(
        rule_id="COMP001",
        title="WebView con JavaScript habilitado",
        severity="medium",
        category="M6 - Componentes inseguros",
        pattern=re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)'),
        description="JavaScript habilitado en WebView. Si carga URLs no confiables, puede ejecutar código arbitrario.",
        recommendation="Deshabilitar JavaScript salvo que sea imprescindible. Validar URLs cargadas.",
    ),
    VulnRule(
        rule_id="COMP002",
        title="WebView con acceso a archivos locales",
        severity="high",
        category="M6 - Componentes inseguros",
        pattern=re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)'),
        description="WebView puede acceder al sistema de archivos local.",
        recommendation="Deshabilitar el acceso a archivos locales en WebView.",
    ),
    VulnRule(
        rule_id="COMP003",
        title="addJavascriptInterface expuesto",
        severity="critical",
        category="M6 - Componentes inseguros",
        pattern=re.compile(r'addJavascriptInterface\s*\('),
        description="Interfaz Java expuesta a JavaScript. Antes de API 17, permite ejecución de código arbitrario.",
        recommendation="Usar @JavascriptInterface solo en métodos necesarios y validar la entrada.",
    ),
    VulnRule(
        rule_id="COMP004",
        title="Broadcast receiver sin permisos",
        severity="medium",
        category="M6 - Componentes inseguros",
        pattern=re.compile(r'registerReceiver\s*\([^,]+,\s*new\s+IntentFilter'),
        description="BroadcastReceiver registrado dinámicamente sin restricción de permisos.",
        recommendation="Usar LocalBroadcastManager o especificar permisos en el registro.",
    ),

    # ── M7: Calidad del código ────────────────────────────────────────────────
    VulnRule(
        rule_id="INJ001",
        title="SQL injection potencial (rawQuery concatenado)",
        severity="critical",
        category="M7 - Inyección",
        pattern=re.compile(
            r'rawQuery\s*\(\s*["\'][^"\']*\+|'
            r'execSQL\s*\(\s*["\'][^"\']*\+'
        ),
        description="Consulta SQL construida con concatenación de strings. Susceptible a SQL injection.",
        recommendation="Usar queries parametrizadas con selectionArgs o PreparedStatement.",
    ),
    VulnRule(
        rule_id="INJ002",
        title="Path traversal potencial",
        severity="high",
        category="M7 - Inyección",
        pattern=re.compile(r'new\s+File\s*\(\s*\w+\s*\+|new\s+File\s*\([^,)]*getIntent\(\)'),
        description="Ruta de archivo construida con input del usuario o de un Intent.",
        recommendation="Validar y canonicalizar rutas de archivo antes de usarlas.",
    ),

    # ── M8: Manipulación de código ────────────────────────────────────────────
    VulnRule(
        rule_id="DBG001",
        title="Modo debug habilitado en código",
        severity="medium",
        category="M8 - Manipulación de código",
        pattern=re.compile(r'BuildConfig\.DEBUG\s*==\s*true|if\s*\(\s*BuildConfig\.DEBUG\s*\)'),
        description="Bloques de código que solo se ejecutan en debug pueden incluir lógica insegura.",
        recommendation="Revisar qué código se ejecuta solo en debug y asegurarse de no exponer datos sensibles.",
    ),
    VulnRule(
        rule_id="DBG002",
        title="Log con datos sensibles",
        severity="medium",
        category="M8 - Manipulación de código",
        pattern=re.compile(
            r'(?i)Log\.[dDiIeEwWvV]\s*\([^,]+,\s*[^)]*(?:password|credit|card|cvv|ssn|secret|pin\b)[^)]*\)'
        ),
        description="Posibles datos sensibles enviados a Logcat.",
        recommendation="Eliminar logs con información sensible antes de publicar.",
    ),
    VulnRule(
        rule_id="DBG003",
        title="printStackTrace() en producción",
        severity="low",
        category="M8 - Manipulación de código",
        pattern=re.compile(r'\.printStackTrace\s*\(\s*\)'),
        description="printStackTrace() expone detalles de implementación interna en los logs.",
        recommendation="Usar un logger con nivel de control (Timber, SLF4J) que pueda desactivarse.",
    ),

    # ── M9: Ingeniería inversa ────────────────────────────────────────────────
    VulnRule(
        rule_id="OBF001",
        title="Reflexión dinámica (posible evasión de análisis)",
        severity="info",
        category="M9 - Ingeniería inversa",
        pattern=re.compile(r'Class\.forName\s*\(|getDeclaredMethod\s*\(|invoke\s*\('),
        description="Uso de reflexión Java. Puede usarse para cargar código dinámicamente.",
        recommendation="Auditar el uso de reflexión para asegurarse de que no carga código externo.",
    ),

    # ── M7: Inyección adicional ───────────────────────────────────────────────
    VulnRule(
        rule_id="INJ003",
        title="Ejecución de comandos del sistema (Runtime.exec)",
        severity="critical",
        category="M7 - Inyección",
        pattern=re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\('),
        description="La app ejecuta comandos del sistema operativo. Si el input no está validado, "
                    "puede derivar en inyección de comandos.",
        recommendation="Evitar Runtime.exec(). Si es necesario, validar y sanitizar toda entrada "
                       "antes de incluirla en el comando.",
    ),
    VulnRule(
        rule_id="INJ004",
        title="Deep link / Intent sin validación de origen",
        severity="high",
        category="M7 - Inyección",
        pattern=re.compile(
            r'getIntent\(\)\.(getStringExtra|getData|getDataString)\s*\(.*?\)\s*;'
            r'|Uri\.parse\s*\(\s*getIntent\(\)'
        ),
        description="Datos extraídos de un Intent sin validación del origen. "
                    "Un deep link malicioso podría inyectar valores inesperados.",
        recommendation="Validar el scheme, host y parámetros del Intent antes de usarlos. "
                       "Restringir las actividades exportadas con android:exported=false.",
    ),

    # ── M2: Almacenamiento inseguro adicional ─────────────────────────────────
    VulnRule(
        rule_id="ST005",
        title="Datos sensibles en el Clipboard",
        severity="medium",
        category="M2 - Almacenamiento inseguro",
        pattern=re.compile(
            r'ClipboardManager|ClipData\.newPlainText\s*\('
        ),
        description="La app copia datos al portapapeles. Otras apps pueden leer el clipboard "
                    "en versiones de Android anteriores a 10.",
        recommendation="Evitar copiar datos sensibles al clipboard. En Android ≥10, "
                       "limpiar el clipboard tras el uso.",
    ),
    VulnRule(
        rule_id="ST006",
        title="Firebase Realtime Database referencia abierta",
        severity="high",
        category="M2 - Almacenamiento inseguro",
        pattern=re.compile(
            r'FirebaseDatabase\.getInstance\(\)'
            r'|com\.google\.firebase\.database\.FirebaseDatabase'
        ),
        description="La app usa Firebase Realtime Database. Si las reglas de seguridad permiten "
                    "lectura/escritura pública, los datos quedan expuestos.",
        recommendation="Revisar las Firebase Security Rules. Nunca usar "
                       '\'".read": true\' o \'".write": true\' en producción.',
    ),

    # ── M8: Deserialización insegura ──────────────────────────────────────────
    VulnRule(
        rule_id="DESER001",
        title="Deserialización Java nativa (ObjectInputStream)",
        severity="high",
        category="M8 - Manipulación de código",
        pattern=re.compile(r'ObjectInputStream\s*\(|readObject\s*\(\s*\)'),
        description="Deserialización Java nativa. Si el stream proviene de una fuente no confiable, "
                    "puede derivar en ejecución de código arbitrario.",
        recommendation="Evitar la deserialización Java nativa. Usar JSON/Protobuf con validación "
                       "de esquema. Si es imprescindible, implementar un ObjectInputFilter.",
    ),

    # ── M3: Comunicación insegura adicional ───────────────────────────────────
    VulnRule(
        rule_id="NET004",
        title="SSLv3 / TLSv1.0 explícito",
        severity="high",
        category="M3 - Comunicación insegura",
        pattern=re.compile(r'SSLContext\.getInstance\s*\(\s*["\'](?:SSL|SSLv3|TLSv1|TLSv1\.0)["\']'),
        description="Uso explícito de SSL 3.0 o TLS 1.0, protocolos con vulnerabilidades conocidas "
                    "(POODLE, BEAST).",
        recommendation="Usar TLSv1.2 o TLSv1.3 únicamente.",
    ),
    VulnRule(
        rule_id="NET005",
        title="OkHttp sin Certificate Pinner",
        severity="medium",
        category="M3 - Comunicación insegura",
        pattern=re.compile(r'new\s+OkHttpClient\.Builder\s*\(\s*\)'),
        description="Cliente OkHttp construido sin CertificatePinner. No hay defensa adicional "
                    "contra ataques MITM si el certificado del servidor cambia.",
        recommendation="Configurar CertificatePinner con los hashes SHA-256 del certificado "
                       "del servidor.",
        ignore_if_contains=["certificatePinner", "CertificatePinner"],
    ),

    # ── M10: Funcionalidad extra ──────────────────────────────────────────────
    VulnRule(
        rule_id="EXTRA001",
        title="Permisos peligrosos en uso",
        severity="info",
        category="M10 - Funcionalidad extra",
        pattern=re.compile(
            r'Manifest\.permission\.(READ_CONTACTS|READ_CALL_LOG|SEND_SMS|'
            r'ACCESS_FINE_LOCATION|RECORD_AUDIO|READ_EXTERNAL_STORAGE|CAMERA)'
        ),
        description="Uso de permisos considerados peligrosos por Android.",
        recommendation="Verificar que cada permiso es estrictamente necesario y está justificado.",
    ),
]


# ── Scanner ────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    base_dir: Path
    findings: list[VulnFinding]
    files_scanned: int
    scanner_engine: str = "regex"  # "semgrep" | "regex" — motor de vulns
    leak_engine: str = ""          # "apkleaks+gitleaks+native" — motor de leaks

    @property
    def by_severity(self) -> dict[str, list[VulnFinding]]:
        order = ["critical", "high", "medium", "low", "info"]
        result: dict[str, list[VulnFinding]] = {s: [] for s in order}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


def scan_directory(
    source_dir: Path,
    rules: list[VulnRule] | None = None,
    progress_callback=None,
) -> ScanResult:
    """
    Escanea todos los archivos .java/.kt/.smali en source_dir.

    Args:
        source_dir: Directorio con código decompilado.
        rules: Lista de reglas a aplicar (None = todas).
        progress_callback: Función llamada con (mensaje: str) para progreso.

    Returns:
        ScanResult con todos los hallazgos.
    """
    if rules is None:
        rules = RULES

    extensions = {".java", ".kt", ".smali", ".xml"}
    findings: list[VulnFinding] = []
    files_scanned = 0

    # Segmentos de path que corresponden a código del SO/SDK/librerías de terceros
    # bundleadas en el APK. No son código de la app — excluir para evitar FP masivos.
    SKIP_PATH_SEGMENTS: tuple[str, ...] = (
        # Android SDK stubs y fuentes del framework
        "sources/android/",
        "sources/java/",
        "android/org/conscrypt/",
        "android/net/wifi/",
        "android/system/virtualmachine/",
        # Bluetooth/WiFi/IPSec del framework
        "sources/android/bluetooth/",
        "sources/android/media/",
        "sources/android/net/",
        "wifi/hotspot2/",
        "ipsec/ike/",
        "net/ipsec/",
        # Java/JDK stubs
        "sun/security/",
        "java/security/",
        # Crypto: Bouncy Castle internals
        "jcajce/provider/",
        "provider/keystore/p008bc/",
        # Apache XML / OkHttp AOSP
        "apache/xalan/",
        "com/android/okhttp/",
        # WiFi aware / Conscrypt
        "net/wifi/aware/",
        # Huawei HMS (SDK de terceros — no es código de la app)
        "api/entity/common/CommonConstant",
        "api/entity/account/AccountNaming",
    )

    source_files = [
        p for p in source_dir.rglob("*")
        if p.is_file() and p.suffix in extensions
        and not any(seg in str(p).replace("\\", "/") for seg in SKIP_PATH_SEGMENTS)
    ]

    for file_path in source_files:
        if progress_callback:
            progress_callback(f"Escaneando {file_path.name}...")

        try:
            content_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        files_scanned += 1

        for rule in rules:
            # Filtro por tipo de archivo
            if rule.file_filter and rule.file_filter not in str(file_path):
                continue

            for lineno, line in enumerate(content_lines, start=1):
                # Ignorar líneas con falsos positivos comunes
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                if any(ign.lower() in line.lower() for ign in rule.ignore_if_contains):
                    continue

                match = rule.pattern.search(line)
                if match:
                    findings.append(VulnFinding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        file=file_path,
                        line=lineno,
                        matched_text=line.strip()[:120],
                        description=rule.description,
                        recommendation=rule.recommendation,
                    ))

    return ScanResult(base_dir=source_dir, findings=findings, files_scanned=files_scanned, scanner_engine="regex")


# ── Scanner con semgrep ────────────────────────────────────────────────────────

def scan_with_semgrep(
    source_dir: Path,
    semgrep_config: str = "p/android p/owasp-top-ten p/secrets",
    progress_callback=None,
) -> ScanResult:
    """
    Escanea source_dir usando semgrep.

    Requiere semgrep instalado:  pip install semgrep  o  brew install semgrep

    Args:
        source_dir: Directorio con código fuente a escanear.
        semgrep_config: Uno o más tokens de configuración separados por espacio
                        (ej. "p/android p/owasp-top-ten").
        progress_callback: Función(str) para mensajes de progreso.

    Returns:
        ScanResult con los hallazgos de semgrep convertidos a VulnFinding.

    Raises:
        RuntimeError: Si semgrep no está instalado o devuelve un error fatal.
    """
    import json
    import shutil
    import subprocess

    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        raise RuntimeError(
            "semgrep no está instalado. Instálalo con:  pip install semgrep"
        )

    if progress_callback:
        progress_callback("Ejecutando semgrep (puede tardar unos segundos)...")

    # Soportar ruta local a directorio de reglas o tokens tipo "p/android auto"
    # Una entrada que sea una ruta existente en disco se pasa tal cual (--config ./path/)
    configs_raw = semgrep_config.split()
    configs: list[str] = []
    for token in configs_raw:
        p = Path(token)
        if p.exists():
            configs.append(str(p.resolve()))
        else:
            configs.append(token)

    cmd = [semgrep_bin]
    for cfg in configs:
        cmd += ["--config", cfg]
    # resolve() elimina symlinks (necesario en macOS donde /tmp -> /private/tmp)
    cmd += ["--json", "--quiet", "--no-git-ignore", str(Path(source_dir).resolve())]

    # Desactivar telemetría de semgrep para evitar crash con OpenTelemetry
    # (X509 authenticator: Resource temporarily unavailable)
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off"}

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("semgrep tardó demasiado (>10 min).")

    # semgrep: rc=0 → sin hallazgos, rc=1 → hallazgos encontrados, rc≥2 → error
    if proc.returncode >= 2:
        stderr = proc.stderr.strip()
        raise RuntimeError(f"semgrep falló (rc={proc.returncode}): {stderr[:400]}")

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"semgrep: salida JSON inválida: {exc}") from exc

    _SEV_MAP = {
        "ERROR":   "high",
        "WARNING": "medium",
        "INFO":    "info",
    }
    # CWEs que merecen severity=critical
    _CRITICAL_CWE = {"89", "798", "321", "327", "326", "78", "77"}

    raw_results = data.get("results", [])
    if progress_callback:
        progress_callback(f"Procesando {len(raw_results)} hallazgos de semgrep...")

    findings: list[VulnFinding] = []
    for r in raw_results:
        check_id: str = r.get("check_id", "UNKNOWN")
        path_str: str = r.get("path", "")
        start_line: int = r.get("start", {}).get("line", 0)
        extra: dict = r.get("extra", {})
        msg: str = extra.get("message", "")
        raw_sev: str = extra.get("severity", "WARNING")
        _raw_lines: str = extra.get("lines", "").strip()
        end_line: int = r.get("end", {}).get("line", start_line)
        # semgrep OSS sin login devuelve "requires login" en lugar del snippet
        # → leemos el fragmento directamente del archivo fuente
        if _raw_lines.lower() == "requires login" and path_str and start_line:
            try:
                src_lines = Path(path_str).read_text(errors="replace").splitlines()
                # hasta 5 líneas de contexto (start..end inclusive)
                lo = max(0, start_line - 1)
                hi = min(len(src_lines), end_line)
                matched_lines = "\n".join(src_lines[lo:hi]).strip()
            except Exception:
                matched_lines = ""
        else:
            matched_lines = _raw_lines
        metadata: dict = extra.get("metadata", {})

        severity = _SEV_MAP.get(raw_sev.upper(), "medium")

        # Escalar a critical si el CWE del hallazgo es de alta criticidad
        if severity == "high":
            cwe_list = metadata.get("cwe", [])
            cwe_nums = {str(c).split("-")[-1] for c in cwe_list}
            if cwe_nums & _CRITICAL_CWE:
                severity = "critical"

        # Categoría: preferir OWASP, luego metadata.category, luego check_id prefix
        owasp = metadata.get("owasp", [])
        category = str(owasp[0]) if owasp else metadata.get("category", check_id.split(".")[0])

        # Recomendación
        refs = metadata.get("references", [])
        fix = metadata.get("fix", "")
        recommendation = (
            fix
            or (refs[0] if refs else f"Revisar regla: {check_id}")
        )

        file_path = Path(path_str) if path_str else source_dir

        # Acortar rule_id (puede ser muy largo con namespace semgrep)
        short_id = check_id.rsplit(".", 1)[-1][:15]

        findings.append(VulnFinding(
            rule_id=short_id,
            title=(msg[:80] if msg else check_id),
            severity=severity,
            category=str(category)[:60],
            file=file_path,
            line=start_line,
            matched_text=matched_lines[:120],
            description=msg,
            recommendation=str(recommendation)[:300],
        ))

    stats: dict = data.get("stats", {})
    files_scanned: int = (
        stats.get("total_files", 0)
        or len({r.get("path") for r in raw_results})
    )

    return ScanResult(base_dir=source_dir, findings=findings, files_scanned=files_scanned, scanner_engine="semgrep")


def auto_scan(
    source_dir: Path,
    engine: str = "auto",
    semgrep_config: str = "p/android p/owasp-top-ten p/secrets",
    progress_callback=None,
    apk_path: Path | None = None,
    leak_engine: str = "apk",
) -> ScanResult:
    """
    Punto de entrada unificado: elige semgrep o regex según engine.

    jadx genera dos subdirectorios:
      sources/    → código Java decompilado (semgrep/regex)
      resources/  → AndroidManifest, strings.xml, etc. (scan secretos XML)

    Si source_dir contiene un subdirectorio 'sources/', semgrep solo escanea
    ese subdirectorio para evitar timeouts con los recursos. El scan de secretos
    en XML siempre corre sobre el directorio raíz (sea jadx o no).

    Args:
        source_dir: Directorio raíz de la decompilación (o directorio de código).
        engine: "auto" | "semgrep" | "regex"
        semgrep_config: Config para semgrep.
        progress_callback: Función(str) para mensajes de progreso.
        leak_engine: "apk" | "code" | "both"
    """
    import shutil

    source_dir = Path(source_dir)

    # Si jadx puso el código en sources/, apuntar semgrep/regex solo ahí
    java_dir = source_dir / "sources"
    scan_code_dir = java_dir if java_dir.is_dir() else source_dir

    use_semgrep = False
    if engine == "semgrep":
        use_semgrep = True
    elif engine == "auto":
        use_semgrep = bool(shutil.which("semgrep"))
        if progress_callback:
            status = "semgrep detectado" if use_semgrep else "semgrep no encontrado, usando regex"
            progress_callback(f"Motor de escaneo: {status}")

    leak_engine = str(leak_engine or "apk").strip().lower()
    if leak_engine not in {"apk", "code", "both"}:
        leak_engine = "apk"

    def _apply_apkleaks(scan_result: ScanResult) -> None:
        """Añade hallazgos de apkleaks según leak_engine."""
        if not apk_path or leak_engine == "code":
            return
        al_findings = scan_with_apkleaks(apk_path, progress_callback)
        if al_findings:
            if leak_engine == "apk":
                # Solo APK leaks: quitar HC* de código para evitar duplicados.
                scan_result.findings = [
                    f for f in scan_result.findings if not f.rule_id.startswith("HC")
                ]
            scan_result.findings.extend(al_findings)
            if "apkleaks" not in scan_result.leak_engine:
                scan_result.leak_engine += ("+apkleaks" if scan_result.leak_engine else "apkleaks")

    if use_semgrep:
        semgrep_result = scan_with_semgrep(scan_code_dir, semgrep_config, progress_callback)

        # Si leaks vienen de código (o mixto), añadir un pass regex solo para HC*.
        if leak_engine in {"code", "both"}:
            secret_rules = [r for r in RULES if r.rule_id.startswith("HC")]
            regex_secret_result = scan_directory(
                scan_code_dir,
                rules=secret_rules,
                progress_callback=None,
            )
            if regex_secret_result.findings:
                existing = {
                    (str(f.file), f.line, f.rule_id, f.matched_text)
                    for f in semgrep_result.findings
                }
                for f in regex_secret_result.findings:
                    key = (str(f.file), f.line, f.rule_id, f.matched_text)
                    if key not in existing:
                        semgrep_result.findings.append(f)
                semgrep_result.files_scanned = max(
                    semgrep_result.files_scanned,
                    regex_secret_result.files_scanned,
                )

        # semgrep (mindedsecurity) no cubre secretos en XML de recursos Android.
        # Si no usamos leaks desde APK, hacer pass regex sobre resources/.
        if apk_path and leak_engine in {"apk", "both"}:
            _apply_apkleaks(semgrep_result)
        else:
            xml_findings = _scan_xml_resources_for_secrets(source_dir)
            if xml_findings:
                if progress_callback:
                    progress_callback(f"Secretos en recursos XML: {len(xml_findings)} hallazgo(s)")
                semgrep_result.findings.extend(xml_findings)
                semgrep_result.files_scanned += len({f.file for f in xml_findings})
        return semgrep_result

    result = scan_directory(scan_code_dir, progress_callback=progress_callback)
    if apk_path and leak_engine in {"apk", "both"}:
        _apply_apkleaks(result)
    else:
        # Fallback: secretos en XML vía regex
        xml_findings = _scan_xml_resources_for_secrets(source_dir)
        if xml_findings:
            result.findings.extend(xml_findings)
            result.files_scanned += len({f.file for f in xml_findings})
    return result


# Reglas solo para secretos en XML de recursos Android
_XML_SECRET_RULES: list[VulnRule] = [
    r for r in RULES
    if r.rule_id in {"HC001", "HC002", "HC003", "HC004", "HC005"}
]


def _scan_xml_resources_for_secrets(base_dir: Path) -> list[VulnFinding]:
    """
    Escanea archivos .xml y .properties bajo resources/ o el directorio raíz
    buscando secretos hardcodeados que semgrep no detecta.
    """
    findings: list[VulnFinding] = []

    # Buscar el directorio resources/ relativo a base_dir
    candidates = [
        base_dir / "resources",
        base_dir / "res",
        base_dir,
    ]
    scan_dirs = [d for d in candidates if d.is_dir()]
    if not scan_dirs:
        return findings

    seen_keys: set[tuple[Path, int, str]] = set()

    for scan_dir in scan_dirs:
        for file_path in scan_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in {".xml", ".properties", ".json"}:
                continue

            try:
                content_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for rule in _XML_SECRET_RULES:
                for lineno, line in enumerate(content_lines, start=1):
                    stripped = line.strip()
                    if stripped.startswith("<!--") or stripped.startswith("#"):
                        continue
                    if any(ign.lower() in line.lower() for ign in rule.ignore_if_contains):
                        continue
                    match = rule.pattern.search(line)
                    if match:
                        key = (file_path, lineno, rule.rule_id)
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        findings.append(VulnFinding(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            severity=rule.severity,
                            category=rule.category,
                            file=file_path,
                            line=lineno,
                            matched_text=line.strip()[:120],
                            description=rule.description,
                            recommendation=rule.recommendation,
                        ))

    return findings


# ── Integración con apkleaks ──────────────────────────────────────────────────

# Mapeo de categoría apkleaks → severidad
_APKLEAKS_SEVERITY: dict[str, str] = {
    "RSA_Private_Key": "critical",
    "PGP_private_key_block": "critical",
    "SSH_DSA_Private_Key": "critical",
    "SSH_EC_Private_Key": "critical",
    "Amazon_AWS_Access_Key_ID": "high",
    "AWS_API_Key": "high",
    "GitHub_Access_Token": "high",
    "Stripe_API_Key": "high",
    "Stripe_Restricted_API_Key": "high",
    "PayPal_Braintree_Access_Token": "high",
    "Heroku_API_Key": "high",
    "Twilio_API_Key": "high",
    "Firebase": "high",
    "Google_API_Key": "high",
    "Google_Cloud_Platform_Service_Account": "high",
    "Google_OAuth_Access_Token": "high",
    "Slack_Token": "high",
    "Slack_Webhook": "high",
    "MailChimp_API_Key": "high",
    "Mailgun_API_Key": "high",
    "Picatic_API_Key": "high",
    "Square_Access_Token": "high",
    "Square_OAuth_Secret": "high",
    "Facebook_Access_Token": "high",
    "Facebook_Secret_Key": "high",
    "Twitter_Secret_Key": "high",
    "Twitter_Access_Token": "high",
    "Twitter_OAuth": "high",
    "Authorization_Basic": "high",
    "Authorization_Bearer": "high",
    "JSON_Web_Token": "high",
    "Password_in_URL": "high",
    "Basic_Auth_Credentials": "high",
    "Cloudinary_Basic_Auth": "high",
    "Artifactory_API_Token": "medium",
    "Artifactory_Password": "medium",
    "Generic_API_Key": "medium",
    "Generic_Secret": "medium",
    "Amazon_AWS_S3_Bucket": "medium",
    "Google_Cloud_Platform_OAuth": "medium",
    "Facebook_ClientID": "low",
    "Facebook_OAuth": "low",
    "Twitter_ClientID": "low",
    "GitHub": "low",
    "Discord_BOT_Token": "medium",
    "IP_Address": "info",
    "Mac_Address": "info",
    "Mailto": "info",
    "LinkFinder": "info",
    "DEFCON_CTF_Flag": "info",
    "HackerOne_CTF_Flag": "info",
    "HackTheBox_CTF_Flag": "info",
    "TryHackMe_CTF_Flag": "info",
}


def scan_with_apkleaks(
    apk_path: Path,
    progress_callback=None,
) -> list[VulnFinding]:
    """
    Ejecuta apkleaks sobre el APK original y convierte sus hallazgos a VulnFinding.
    Requiere apkleaks instalado (pip install apkleaks).
    Devuelve lista vacía si apkleaks no está disponible o falla.
    """
    import json as _json
    import shutil
    import subprocess
    import tempfile

    def _parse_plain_output(raw_text: str) -> dict[str, list[str]]:
        """Parsea salida estilo texto de apkleaks: [Categoria] y lineas '- valor'."""
        parsed: dict[str, list[str]] = {}
        current: str | None = None
        for line in raw_text.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("[") and s.endswith("]") and len(s) > 2:
                current = s[1:-1].strip()
                if current:
                    parsed.setdefault(current, [])
                continue
            if current and s.startswith("- "):
                value = s[2:].strip()
                if value:
                    parsed[current].append(value)
        return parsed

    apkleaks_bin = shutil.which("apkleaks")
    if not apkleaks_bin:
        if progress_callback:
            progress_callback("apkleaks no encontrado — omitiendo scan de secretos con apkleaks")
        return []

    if progress_callback:
        progress_callback("Escaneando secretos con apkleaks...")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    try:
        proc = subprocess.run(
            [apkleaks_bin, "-f", str(apk_path), "-o", out_path, "--json"],
            capture_output=True,
            text=True,
            timeout=240,
        )
        if proc.returncode not in (0, 1):
            if progress_callback:
                progress_callback(f"apkleaks terminó con rc={proc.returncode}")
            return []

        raw = Path(out_path).read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            return []

        data: dict[str, object]
        try:
            decoded = _json.loads(raw)
            if isinstance(decoded, dict):
                data = decoded
            else:
                data = {"results": []}
        except _json.JSONDecodeError:
            plain = _parse_plain_output(raw)
            data = {
                "results": [
                    {"name": name, "matches": values}
                    for name, values in plain.items()
                ]
            }
    except subprocess.TimeoutExpired:
        if progress_callback:
            progress_callback("apkleaks timeout (>240s), omitiendo")
        return []
    except OSError:
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)

    findings: list[VulnFinding] = []
    for entry in data.get("results", []):
        name: str = entry.get("name", "Unknown")
        matches: list[str] = entry.get("matches", [])
        severity = _APKLEAKS_SEVERITY.get(name, "medium")
        # Omitir categorías de solo info (IP, URLs, etc.) — demasiado ruido
        if severity == "info":
            continue
        if name == "LinkFinder":
            continue
        for match in matches:
            # ── Filtro de falsos positivos conocidos de apkleaks ──────────
            if _is_apkleaks_false_positive(name, match):
                continue
            findings.append(VulnFinding(
                rule_id=f"AL-{name[:20]}",
                title=name.replace("_", " "),
                severity=severity,
                category="M1 - Credenciales",
                file=apk_path,
                line=0,
                matched_text=match[:120],
                description=f"Secreto o credencial detectada por apkleaks: {name}.",
                recommendation="Eliminar credenciales del código. Usar variables de entorno o un gestor de secretos.",
            ))

    if progress_callback:
        pre_count = sum(len(e.get("matches", [])) for e in data.get("results", []))
        if pre_count != len(findings):
            progress_callback(
                f"apkleaks: {len(findings)} secreto(s) tras filtrar "
                f"{pre_count - len(findings)} falso(s) positivo(s)"
            )
        elif findings:
            progress_callback(f"apkleaks: {len(findings)} secreto(s) encontrado(s)")

    return findings


# ── Filtro de falsos positivos de apkleaks ────────────────────────────────────

# Patrones de valores que apkleaks reporta pero NO son secretos reales
_APKLEAKS_FP_PATTERNS: list[re.Pattern] = [
    # "version=X.Y.Z" matcheado como JWT (es metadata de librerías GMS)
    re.compile(r'^(?:version|common_client|googleid_client|image_client|review_client)=[\d.]+'),
    # "basic constraint(s)" matcheado como Authorization Basic (es parte de X.509 certs)
    re.compile(r'^basic\s+constraint'),
    # Números de versión sueltos que no son tokens
    re.compile(r'^[\d.]+$'),
]

# Categorías de apkleaks con alta tasa de FP en APKs Android normales
_APKLEAKS_NOISY_CATEGORIES: dict[str, re.Pattern] = {
    # JSON_Web_Token: apkleaks matchea "key=value" de metadata GMS como JWT
    "JSON_Web_Token": re.compile(
        r'^(?:version|common_client|googleid_client|image_client|review_client)='
        r'|^[\w._]+=[\d.]+$'
    ),
    # Authorization_Basic: matchea "basic constraint" de certificados X.509
    "Authorization_Basic": re.compile(
        r'basic\s+constraint|BasicConstraints'
    ),
    # Facebook_Secret_Key: FACEBOOK_SIGNATURE es la firma pública del SDK, no un secreto
    "Facebook_Secret_Key": re.compile(
        r'FACEBOOK_SIGNATURE\s*='
    ),
}


def _is_apkleaks_false_positive(category: str, match_text: str) -> bool:
    """Devuelve True si el hallazgo de apkleaks es un falso positivo conocido."""
    text = match_text.strip()

    # Filtros genéricos (aplican a cualquier categoría)
    for fp_pattern in _APKLEAKS_FP_PATTERNS:
        if fp_pattern.search(text):
            return True

    # Filtros por categoría
    cat_pattern = _APKLEAKS_NOISY_CATEGORIES.get(category)
    if cat_pattern and cat_pattern.search(text):
        return True

    return False


# ── Gitleaks scanner ──────────────────────────────────────────────────────────

# Reglas de gitleaks cuyo hallazgo se considera critical (claves privadas, AWS, etc.)
_GITLEAKS_CRITICAL_RULES: set[str] = {
    "private-key",
    "aws-access-token",
    "aws-secret-access-key",
    "github-pat",
    "github-fine-grained-pat",
    "gitlab-pat",
    "stripe-access-token",
    "twilio-api-key",
    "generic-api-key",
}


def scan_with_gitleaks(
    source_dir: Path,
    progress_callback=None,
) -> list[VulnFinding]:
    """
    Ejecuta gitleaks sobre un directorio de código decompilado y convierte
    sus hallazgos a VulnFinding.
    Requiere gitleaks instalado (brew install gitleaks).
    Devuelve lista vacía si gitleaks no está disponible o falla.
    """
    import json as _json
    import shutil
    import subprocess
    import tempfile

    gitleaks_bin = shutil.which("gitleaks")
    if not gitleaks_bin:
        if progress_callback:
            progress_callback("gitleaks no encontrado — omitiendo scan")
        return []

    if progress_callback:
        progress_callback("Escaneando secretos con gitleaks...")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    try:
        proc = subprocess.run(
            [
                gitleaks_bin, "detect",
                "--no-git",
                "--no-banner",
                "-s", str(source_dir),
                "-f", "json",
                "-r", out_path,
                "--log-level", "error",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        # rc=0 → sin hallazgos, rc=1 → hallazgos encontrados, ≥2 → error
        if proc.returncode >= 2:
            if progress_callback:
                progress_callback(f"gitleaks terminó con rc={proc.returncode}")
            return []

        raw = Path(out_path).read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            return []

        try:
            items = _json.loads(raw)
        except _json.JSONDecodeError:
            if progress_callback:
                progress_callback("gitleaks: JSON inválido")
            return []

        if not isinstance(items, list):
            return []

    except subprocess.TimeoutExpired:
        if progress_callback:
            progress_callback("gitleaks timeout (>300s), omitiendo")
        return []
    except OSError:
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)

    findings: list[VulnFinding] = []
    for item in items:
        rule_id = item.get("RuleID", "unknown")
        description = item.get("Description", rule_id)
        secret = item.get("Secret", item.get("Match", ""))
        file_path = item.get("File", "")
        start_line = item.get("StartLine", 0)
        entropy = item.get("Entropy", 0.0)

        severity = "critical" if rule_id in _GITLEAKS_CRITICAL_RULES else "high"

        desc_text = f"{description}"
        if entropy:
            desc_text += f" (entropy: {entropy:.2f})"

        findings.append(VulnFinding(
            rule_id=f"GL-{rule_id}",
            title=description,
            severity=severity,
            category="M1 - Credenciales",
            file=Path(file_path),
            line=start_line,
            matched_text=secret[:120] if secret else "",
            description=desc_text,
            recommendation="Eliminar credenciales del código. Usar variables de entorno o un gestor de secretos.",
        ))

    if progress_callback:
        progress_callback(f"gitleaks: {len(findings)} secreto(s) encontrado(s)")

    return findings
