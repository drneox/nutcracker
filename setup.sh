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
echo ""
echo "==> Verificando desensamblador para libs nativas (.so ARM64)..."
if command -v objdump &>/dev/null || command -v aarch64-linux-gnu-objdump &>/dev/null || command -v r2 &>/dev/null; then
    echo "    OK: desensamblador disponible"
else
    if [[ "$(uname)" == "Linux" ]]; then
        echo "    AVISO: no se encontró objdump ARM64. Instalando binutils-aarch64-linux-gnu..."
        sudo apt-get install -y binutils-aarch64-linux-gnu 2>/dev/null || \
            echo "    No se pudo instalar automáticamente. Ejecuta: sudo apt install binutils-aarch64-linux-gnu"
    else
        echo "    INFO (macOS): objdump del sistema soporta ELF ARM64. OK"
    fi
fi

DASHBOARD_DIR="nutcracker_core/plugins/dashboard"
WEBUSB_DIR="$DASHBOARD_DIR/webusb"

# El plugin dashboard (y aipwn) vive bajo nutcracker_core/plugins/, que el
# .gitignore raíz excluye por completo (regla "plugins/") -- en un checkout
# fresco del repo puede simplemente no estar presente. Todo lo de abajo es
# opcional y se salta en silencio si la carpeta no existe.
if [[ -d "$DASHBOARD_DIR" ]]; then
    echo ""
    echo ""
    echo "==> Instalando dependencias del dashboard web (fastapi/uvicorn/PyAV)..."
    if [[ -f "$DASHBOARD_DIR/requirements.txt" ]]; then
        if pip install -r "$DASHBOARD_DIR/requirements.txt" --quiet; then
            echo "    OK: 'nutcracker dashboard' listo para usar."
        else
            echo "    AVISO: no se pudieron instalar automáticamente. Se reintenta solo (lazy-install)"
            echo "    la primera vez que corras 'nutcracker dashboard' -- ver plugins/__init__.py."
        fi
    fi

    echo ""
    echo "==> Verificando scrcpy (video en vivo del dispositivo en el dashboard, opcional)..."
    if command -v scrcpy &>/dev/null; then
        echo "    OK: $(scrcpy --version 2>&1 | head -1)"
    else
        echo "    scrcpy NO encontrado -- opcional: sin él, la pestaña Dispositivo cae automáticamente"
        echo "    a polling de screenshots (nada se rompe)."
        if [[ "$(uname)" == "Darwin" ]]; then
            command -v brew &>/dev/null && brew install scrcpy || echo "    Instala con: brew install scrcpy"
        elif [[ "$(uname)" == "Linux" ]]; then
            sudo apt-get install -y scrcpy 2>/dev/null || \
                echo "    Instala con: sudo apt install scrcpy (o ver https://github.com/Genymobile/scrcpy)"
        else
            echo "    Windows/WSL: instala scrcpy en Windows y apunta dashboard.scrcpy_path en config.yaml"
            echo "    a su ruta .exe (ver README.md, sección 'Live device video (scrcpy)')."
        fi
    fi

    echo ""
    echo "==> Video USB fluido del dashboard (WebUSB + WebCodecs, app.webadb.com-style)..."
    if [[ ! -d "$WEBUSB_DIR" ]]; then
        echo "    Subproyecto webusb/ no presente en este checkout -- omitiendo (opcional)."
    elif ! command -v npm &>/dev/null; then
        echo "    npm NO encontrado -- opcional, solo habilita el modo de video más fluido (15-30fps,"
        echo "    requiere Chrome/Edge + USB directo). Instala Node.js 20+ y corre:"
        echo "        cd $WEBUSB_DIR && npm install && npm run build"
        echo "    Detalles/troubleshooting (incluye un problema conocido en WSL): $WEBUSB_DIR/README.md"
    elif [[ "$(command -v npm)" == /mnt/c/* || "$(command -v node)" == /mnt/c/* ]]; then
        echo "    AVISO: 'npm'/'node' resuelven al Node de Windows (interop de WSL) -- el build falla"
        echo "    con errores de rutas UNC. Instala Node nativo de Linux (nvm) y reintenta a mano:"
        echo "        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.6/install.sh | bash"
        echo "        nvm install --lts   # y volvé a correr: cd $WEBUSB_DIR && npm install && npm run build"
        echo "    Detalles: $WEBUSB_DIR/README.md"
    else
        echo "    npm detectado, compilando el bundle (puede tardar un minuto)..."
        if (cd "$WEBUSB_DIR" && npm install --silent && npm run build); then
            echo "    OK: bundle generado -- el botón '🔌 USB directo (fluido)' aparecerá en el dashboard."
        else
            echo "    AVISO: el build falló -- opcional, el dashboard sigue funcionando sin él (cae a"
            echo "    scrcpy/polling). Detalles: $WEBUSB_DIR/README.md"
        fi
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
echo ""
echo "    # Levantar el dashboard web (cola + apps + video del dispositivo):"
echo "    python nutcracker.py dashboard"
