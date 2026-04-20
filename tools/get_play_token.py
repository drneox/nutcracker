#!/usr/bin/env python3
"""
Extrae el AAS token de Google Play desde el emulador Android.
Requiere: emulador corriendo con adb root activo.
"""

import os
import subprocess
import sys
import tempfile
import time

import requests
import yaml

EMULATOR_SERIAL = "emulator-5554"
ACCOUNTS_CE_DB = "/data/system_ce/0/accounts_ce.db"
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

# Cert SHA1 del APK de Google Play (fijo)
VENDING_CERT_SHA1 = "38918a453d07199354f8b19af05ec6562ced5788"


def adb(*args, check=False):
    """Ejecuta un comando adb en el emulador y devuelve stdout."""
    cmd = ["adb", "-s", EMULATOR_SERIAL] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip(), result.returncode


def check_emulator_ready():
    """Verifica que el emulador está corriendo con acceso root."""
    out, rc = adb("get-state")
    if rc != 0 or "device" not in out:
        return False, "El emulador no está disponible en adb"

    out, rc = adb("root")
    if rc != 0:
        return False, f"No se pudo obtener root: {out}"

    out, _ = adb("shell", "whoami")
    if "root" not in out:
        return False, f"adb shell no corre como root (whoami={out})"

    return True, "OK"


def open_add_account_screen():
    """Abre la pantalla de añadir cuenta de Google en el emulador."""
    adb(
        "shell", "am", "start",
        "-n", "com.google.android.gms/.auth.uiflows.signin.SignInActivity",
        "--es", "extra_email", ""
    )


def get_google_account_from_emulator():
    """Lee el email de la cuenta Google en el emulador usando sqlite3."""
    out, rc = adb("shell", "sqlite3", ACCOUNTS_CE_DB,
                  "SELECT name FROM accounts WHERE type='com.google' LIMIT 1;")
    if rc == 0 and out and "@" in out:
        return out.strip()
    return None


def get_master_token(email):
    """Extrae el master token de la DB de cuentas del emulador."""
    # Intento 1: columna 'password' de la tabla accounts
    out, rc = adb("shell", "sqlite3", ACCOUNTS_CE_DB,
                  f"SELECT password FROM accounts WHERE name='{email}' AND type='com.google';")
    if rc == 0 and out and out not in ("", "NULL", "null"):
        return out.strip()

    # Intento 2: tabla authtokens con tipo master_token
    out, rc = adb("shell", "sqlite3", ACCOUNTS_CE_DB,
                  f"SELECT authtoken FROM authtokens "
                  f"WHERE accounts_id=(SELECT _id FROM accounts WHERE name='{email}') "
                  f"AND type='master_token';")
    if rc == 0 and out and out not in ("", "NULL", "null"):
        return out.strip()

    return None


def pull_and_query_db(email):
    """Alternativa: descarga la DB localmente y la consulta con sqlite3 de Python."""
    try:
        import sqlite3 as _sqlite3

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        _, rc = subprocess.run(
            ["adb", "-s", EMULATOR_SERIAL, "pull", ACCOUNTS_CE_DB, tmp_path],
            capture_output=True
        ).returncode, 0

        conn = _sqlite3.connect(tmp_path)
        cur = conn.cursor()

        cur.execute("SELECT password FROM accounts WHERE name=? AND type='com.google'", (email,))
        row = cur.fetchone()
        conn.close()
        os.unlink(tmp_path)

        if row and row[0]:
            return row[0]
    except Exception as e:
        print(f"  [debug] pull_and_query_db: {e}")

    return None


def master_token_to_aas(email, master_token):
    """
    Convierte un master token de Android a un AAS token usando la API de Google.
    El AAS token es el que apkeep acepta con el flag -t.
    """
    url = "https://android.googleapis.com/auth"
    headers = {
        "User-Agent": "GoogleAuth/1.4 (generic_x86 APQ8064; Print/N2G48H)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "Email": email,
        "EncryptedPasswd": master_token,
        "service": "ac2dm",
        "accountType": "HOSTED_OR_GOOGLE",
        "has_permission": "1",
        "add_account": "1",
        "ACCESS_TOKEN": "1",
        "app": "com.google.android.gms",
        "client_sig": VENDING_CERT_SHA1,
        "callerPkg": "com.google.android.gms",
        "callerSig": VENDING_CERT_SHA1,
        "sdk_version": "34",
        "device_country": "us",
        "operatorCountry": "us",
        "lang": "en",
    }

    resp = requests.post(url, headers=headers, data=data, timeout=15)

    token = None
    for line in resp.text.splitlines():
        if line.startswith("Token="):
            token = line[6:].strip()
            break

    if not token:
        print(f"\n  [debug] Respuesta Google:\n{resp.text[:500]}")
        return None

    # Normalizar formato aas_et/
    if not token.startswith("aas_et/"):
        # Algunos tokens son oauth2_4/... → convertir
        if token.startswith("oauth2_4/"):
            token = "aas_et/" + token[9:]
        else:
            token = "aas_et/" + token

    return token


def verify_token_with_apkeep(email, aas_token):
    """Prueba el token descargando metadata de un paquete conocido."""
    print("\nVerificando token con apkeep...")
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            ["apkeep", "-e", email, "-t", aas_token, "--accept-tos",
             "-a", "com.google.android.gm", tmpdir],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 or "Downloading" in result.stdout or "Downloading" in result.stderr:
            return True
        print(f"  apkeep stdout: {result.stdout[:200]}")
        print(f"  apkeep stderr: {result.stderr[:200]}")
        return False


def save_to_config(email, aas_token):
    """Guarda el token AAS en config.yaml."""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}

    if "google_play" not in config:
        config["google_play"] = {}

    config["google_play"]["email"] = email
    config["google_play"]["aas_token"] = aas_token

    with open(CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

    print(f"\n✓ Guardado en {CONFIG_PATH}")


def main():
    print("=" * 55)
    print("  Extractor de AAS token para Google Play (emulador)")
    print("=" * 55)

    # 1. Verificar emulador
    print("\n[1/5] Verificando emulador...")
    ok, msg = check_emulator_ready()
    if not ok:
        print(f"  ✗ {msg}")
        print("\nAsegúrate de que el emulador esté corriendo:")
        print("  ~/Library/Android/sdk/emulator/emulator -avd Pixel_6_API_34 &")
        sys.exit(1)
    print("  ✓ Emulador listo con acceso root")

    # 2. Guiar al usuario para iniciar sesión
    print("\n[2/5] Iniciando pantalla de cuenta en el emulador...")
    open_add_account_screen()
    print("""
  ┌──────────────────────────────────────────────────────────┐
  │  En la ventana del EMULADOR ANDROID:                     │
  │                                                          │
  │  1. Ve a Ajustes → Cuentas → Añadir cuenta              │
  │     (o usa la pantalla que acaba de abrirse)             │
  │  2. Selecciona "Google"                                  │
  │  3. Inicia sesión con: cganozap@gmail.com                │
  │  4. Completa el proceso de autenticación                 │
  │                                                          │
  │  NOTA: puede pedirte verificación en tu teléfono real.   │
  └──────────────────────────────────────────────────────────┘
    """)

    input("  Presiona ENTER cuando hayas terminado de iniciar sesión...")

    # Esperar a que GMS sincronice los tokens
    print("\n  Esperando sincronización de tokens (15s)...")
    time.sleep(15)

    # 3. Obtener cuenta y master token
    print("\n[3/5] Extrayendo cuenta de Google del emulador...")
    email = get_google_account_from_emulator()

    if not email:
        print("  ✗ No se encontró cuenta de Google en el emulador.")
        print("    ¿Completaste el inicio de sesión? Inténtalo de nuevo.")
        sys.exit(1)

    print(f"  ✓ Cuenta: {email}")

    print("\n[4/5] Extrayendo master token...")
    master_token = get_master_token(email)

    if not master_token:
        print("  Intento alternativo: descargando DB localmente...")
        master_token = pull_and_query_db(email)

    if not master_token:
        print("  ✗ No se pudo extraer el master token.")
        print("\n  Posibles causas:")
        print("  - El sistema Android cifró la contraseña (API 34 puede hacer esto)")
        print("  - Los tokens aún no sincronizaron — espera 1 min e intenta de nuevo")
        sys.exit(1)

    display_token = master_token[:20] + "..." if len(master_token) > 20 else master_token
    print(f"  ✓ Master token: {display_token}")

    # 4. Convertir a AAS token
    print("\n[5/5] Convirtiendo a AAS token...")
    aas_token = master_token_to_aas(email, master_token)

    if not aas_token:
        print("  ✗ Error al convertir el token.")
        print("  Puede que el master token requiera re-autenticación.")
        sys.exit(1)

    print(f"  ✓ AAS token: {aas_token[:35]}...")

    # 5. Guardar
    save_to_config(email, aas_token)

    print("\n" + "=" * 55)
    print("  ¡Listo! Token configurado.")
    print("=" * 55)
    print(f"\n  Email: {email}")
    print(f"  Token: {aas_token[:40]}...")
    print("\n  Ahora puedes descargar APKs de Google Play:")
    print("  python nutcracker.py scan com.example.app --source google_play")
    print("  python nutcracker.py scan 'https://play.google.com/store/apps/details?id=com.example.app'")


if __name__ == "__main__":
    main()
