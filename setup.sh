#!/usr/bin/env bash
# setup.sh — Configura el entorno de nutcracker
set -euo pipefail

echo "==> Creando entorno virtual..."
python3 -m venv .venv
source .venv/bin/activate

echo "==> Instalando dependencias Python..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

echo ""
echo "==> Verificando apkeep (necesario para descargar desde Google Play)..."
if command -v apkeep &>/dev/null; then
    echo "    apkeep ya está instalado: $(apkeep --version 2>&1 | head -1)"
else
    echo "    apkeep NO encontrado. Instalando..."
    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &>/dev/null; then
            brew install apkeep
        else
            echo "    Homebrew no encontrado. Descarga apkeep manualmente desde:"
            echo "    https://github.com/EFForg/apkeep/releases"
        fi
    else
        APKEEP_VERSION="0.10.0"
        APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/${APKEEP_VERSION}/apkeep-x86_64-unknown-linux-musl"
        echo "    Descargando apkeep ${APKEEP_VERSION}..."
        curl -fsSL "$APKEEP_URL" -o /usr/local/bin/apkeep
        chmod +x /usr/local/bin/apkeep
        echo "    apkeep instalado en /usr/local/bin/apkeep"
    fi
fi

echo ""
echo "==> ¡Configuración completada!"
echo ""
echo "Activa el entorno virtual con:"
echo "    source .venv/bin/activate"
echo ""
echo "Uso:"
echo "    # Descargar y analizar desde Google Play:"
echo "    python nutcracker.py scan 'https://play.google.com/store/apps/details?id=com.example.app'"
echo ""
echo "    # Analizar una APK local:"
echo "    python nutcracker.py analyze ruta/al/archivo.apk"
echo ""
echo "    # Guardar informe JSON:"
echo "    python nutcracker.py analyze app.apk --report informe.json"
