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
        # Resuelto en vivo, no fijo a mano -- una versión pineada rompió sola
        # cuando apkeep cortó un major (0.10.0 -> 1.0.0) y borró el asset
        # viejo del release (404). Fallback a un tag conocido si la API de
        # GitHub no responde (rate limit, sin red).
        APKEEP_VERSION="$(curl -fsSL https://api.github.com/repos/EFForg/apkeep/releases/latest \
            | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
        if [[ -z "$APKEEP_VERSION" ]]; then
            APKEEP_VERSION="1.0.0"
            echo "    (no se pudo resolver la última versión vía GitHub API, usando ${APKEEP_VERSION} fijo)"
        fi
        APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/${APKEEP_VERSION}/apkeep-x86_64-unknown-linux-gnu"
        echo "    Descargando apkeep ${APKEEP_VERSION}..."
        if curl -fsSL "$APKEEP_URL" -o /usr/local/bin/apkeep; then
            chmod +x /usr/local/bin/apkeep
            echo "    apkeep instalado en /usr/local/bin/apkeep"
        else
            echo "    AVISO: no se pudo descargar apkeep ${APKEEP_VERSION} (¿cambió el nombre del"
            echo "    asset de nuevo?). Instalalo a mano desde:"
            echo "    https://github.com/EFForg/apkeep/releases"
        fi
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
    echo "==> Instalando dependencias del dashboard web (fastapi/uvicorn)..."
    if [[ -f "$DASHBOARD_DIR/requirements.txt" ]]; then
        if pip install -r "$DASHBOARD_DIR/requirements.txt" --quiet; then
            echo "    OK: 'nutcracker dashboard' listo para usar."
        else
            echo "    AVISO: no se pudieron instalar automáticamente. Se reintenta solo (lazy-install)"
            echo "    la primera vez que corras 'nutcracker dashboard' -- ver plugins/__init__.py."
        fi
    fi

    echo ""
    echo "==> Video USB fluido del dashboard (WebUSB + WebCodecs, único modo -- sin fallback)..."
    # pnpm (no npm): bloquea por defecto los scripts postinstall de las
    # dependencias -- justo el vector de varios ataques de supply-chain
    # recientes en el ecosistema npm. Este proyecto solo aprueba el de
    # esbuild (necesario, baja el binario nativo de la plataforma -- ver
    # webusb/pnpm-workspace.yaml). Se activa vía corepack (viene con Node
    # 16.9+), que además fija la versión exacta via el campo
    # "packageManager" de package.json -- instalación reproducible sin
    # depender de qué pnpm tengas instalado global.
    if [[ ! -d "$WEBUSB_DIR" ]]; then
        echo "    Subproyecto webusb/ no presente en este checkout -- omitiendo (opcional)."
    elif ! command -v node &>/dev/null; then
        echo "    Node.js NO encontrado -- opcional, solo habilita el video en vivo de la pestaña"
        echo "    'Dispositivo' (requiere Chrome/Edge + USB directo). Instala Node.js 20+ (trae"
        echo "    corepack) y corre:"
        echo "        cd $WEBUSB_DIR && corepack enable && pnpm install && pnpm run build"
        echo "    Detalles/troubleshooting (incluye un problema conocido en WSL): $WEBUSB_DIR/README.md"
    elif [[ "$(command -v node)" == /mnt/c/* ]]; then
        echo "    AVISO: 'node' resuelve al Node de Windows (interop de WSL) -- el build falla"
        echo "    con errores de rutas UNC. Instala Node nativo de Linux (nvm) y reintenta a mano:"
        echo "        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.6/install.sh | bash"
        echo "        nvm install --lts   # y volvé a correr:"
        echo "        cd $WEBUSB_DIR && corepack enable && pnpm install && pnpm run build"
        echo "    Detalles: $WEBUSB_DIR/README.md"
    elif ! command -v corepack &>/dev/null; then
        echo "    corepack NO encontrado (viene con Node 16.9+, pero algunos paquetes de distro lo"
        echo "    separan) -- instalalo y reintentá a mano:"
        echo "        npm install -g corepack   # o el paquete 'corepack' de tu distro"
        echo "        cd $WEBUSB_DIR && corepack enable && pnpm install && pnpm run build"
    else
        echo "    Node + corepack detectados, compilando el bundle (puede tardar un minuto)..."
        corepack enable &>/dev/null || true
        if (cd "$WEBUSB_DIR" && pnpm install --silent && pnpm run build); then
            echo "    OK: bundle generado -- el botón '🔌 USB directo (fluido)' aparecerá en el dashboard."
        else
            echo "    AVISO: el build falló -- opcional, el resto del dashboard sigue funcionando sin"
            echo "    el video en vivo. Detalles: $WEBUSB_DIR/README.md"
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
