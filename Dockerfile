FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1

# Herramientas de sistema para nutcracker
RUN apt-get update && apt-get install -y --no-install-recommends \
    adb \
    apktool \
    curl \
    default-jre \
    git \
    jadx \
    unzip \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Dependencias Python del proyecto
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir frida frida-tools frida-dexdump semgrep

# Copiar código al contenedor
COPY . /workspace

# Punto de entrada por defecto (se puede sobreescribir en compose)
CMD ["python", "nutcracker.py", "--help"]
