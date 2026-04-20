#!/usr/bin/env python3
"""
Obtiene el AAS Token de Google Play necesario para descargar APKs con apkeep.

Uso:
    python get_token.py

Requiere:
    - Email y App Password en config.yaml
    - apkeep instalado (brew install apkeep)
"""

import subprocess
import sys
from pathlib import Path

import requests
import yaml


CONFIG_PATH = Path(__file__).parent / "config.yaml"


def load_credentials() -> tuple[str, str]:
    if not CONFIG_PATH.exists():
        print("ERROR: No se encontró config.yaml")
        sys.exit(1)

    with CONFIG_PATH.open() as f:
        config = yaml.safe_load(f)

    email = config.get("google_play", {}).get("email", "")
    password = config.get("google_play", {}).get("password", "")

    if not email or not password:
        print("ERROR: Configura google_play.email y google_play.password en config.yaml")
        sys.exit(1)

    return email, password


def get_master_token(email: str, password: str) -> str:
    """
    Obtiene el Master Token de Google mediante el protocolo ClientLogin.
    Las App Passwords funcionan con este protocolo.
    """
    print(f"Autenticando con Google Play como {email}...")

    params = {
        "Email": email,
        "Passwd": password,
        "service": "androidmarket",
        "accountType": "HOSTED_OR_GOOGLE",
        "has_permission": "1",
        "source": "android",
        "androidId": "3d2e2b64db75b4b3",
        "app": "com.android.vending",
        "device_country": "pe",
        "operatorCountry": "pe",
        "lang": "es",
        "sdk_version": "22",
    }

    try:
        response = requests.post(
            "https://android.clients.google.com/auth",
            data=params,
            headers={"Accept-Encoding": ""},
            timeout=30,
        )
    except requests.RequestException as exc:
        print(f"ERROR de red: {exc}")
        sys.exit(1)

    # Parsear respuesta clave=valor
    data: dict[str, str] = {}
    for line in response.text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            data[k.strip()] = v.strip()

    if "Token" in data:
        return data["Token"]

    error = data.get("Error", "desconocido")
    info = data.get("Info", "")
    print(f"\nERROR de autenticación: {error}")
    if info:
        print(f"Info: {info}")
    if error == "NeedsBrowser":
        print(
            "\nGoogle requiere verificación adicional.\n"
            "Sigue estos pasos:\n"
            "  1. Ve a https://accounts.google.com/DisplayUnlockCaptcha\n"
            "  2. Haz clic en 'Continuar'\n"
            "  3. Vuelve a ejecutar este script en los próximos 10 minutos."
        )
    elif error == "BadAuthentication":
        print(
            "\nVerifica que estés usando una App Password (no tu contraseña normal):\n"
            "  https://myaccount.google.com/apppasswords\n"
            "Y que la verificación en dos pasos esté activada en tu cuenta."
        )
    sys.exit(1)


def get_aas_token_via_apkeep(email: str, master_token: str) -> str:
    """
    Usa apkeep con el master token para obtener el AAS token de larga duración.
    apkeep imprime el AAS token en la salida.
    """
    print("Generando AAS token con apkeep...")

    # Usamos un package gratuito para forzar la autenticación
    cmd = [
        "apkeep",
        "-a", "com.google.android.apps.maps",
        "-d", "google-play",
        "-e", email,
        "--oauth-token", master_token,
        "--accept-tos",
        "/tmp/apk_token_probe",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: apkeep tardó demasiado")
        sys.exit(1)
    except FileNotFoundError:
        print("ERROR: apkeep no está instalado. Instálalo con: brew install apkeep")
        sys.exit(1)

    output = result.stdout + result.stderr

    # Buscar el AAS token en la salida
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("aas_et/"):
            return line

    # También puede estar en formato "aas token: aas_et/..."
    for line in output.splitlines():
        if "aas_et/" in line:
            idx = line.index("aas_et/")
            return line[idx:].split()[0]

    print("\nNo se encontró el AAS token en la salida de apkeep.")
    print("Salida de apkeep:")
    print(output[:1000])
    sys.exit(1)


def save_aas_token(aas_token: str) -> None:
    """Guarda el AAS token en config.yaml."""
    with CONFIG_PATH.open() as f:
        content = f.read()

    # Reemplazar o insertar aas_token bajo google_play
    if "aas_token:" in content:
        lines = content.splitlines()
        new_lines = []
        for line in lines:
            if line.strip().startswith("aas_token:") or line.strip().startswith("# aas_token:"):
                new_lines.append(f'  aas_token: "{aas_token}"')
            else:
                new_lines.append(line)
        content = "\n".join(new_lines) + "\n"
    else:
        # Insertar después de la línea del email
        lines = content.splitlines()
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if "email:" in line and "google_play" not in line:
                pass  # siguiente línea podría ser password
            if "password:" in line:
                new_lines.append(f'  aas_token: "{aas_token}"')
        content = "\n".join(new_lines) + "\n"

    with CONFIG_PATH.open("w") as f:
        f.write(content)


def main() -> None:
    print("=== nutcracker — Obtención de AAS Token para Google Play ===\n")

    email, password = load_credentials()
    master_token = get_master_token(email, password)
    print(f"✔ Master token obtenido ({master_token[:12]}...)")

    aas_token = get_aas_token_via_apkeep(email, master_token)
    print(f"✔ AAS token obtenido: {aas_token[:20]}...")

    save_aas_token(aas_token)
    print(f"\n✔ AAS token guardado en config.yaml")
    print("\nAhora puedes descargar desde Google Play:")
    print('  python nutcracker.py scan "<url>" --source google-play')


if __name__ == "__main__":
    main()
