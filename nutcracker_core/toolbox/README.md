# Toolbox estático (Docker)

Capa de acceso uniforme a herramientas de análisis estático, sandboxeadas en
Docker — inspirado en la arquitectura de auto_pentest: toolbox estático en
contenedor, herramientas dinámicas (adb/frida) en el host hablando con el
dispositivo físico real.

## Por qué esta separación

- **Estático → Docker**: jadx/apktool/radare2/etc. decompilan contenido de
  terceros (APKs de apps reales, potencialmente maliciosos). El contenedor
  aísla cualquier intento de explotar un bug del propio decompilador del
  resto del host. También resuelve el problema de dependencias: no hace
  falta tener cada herramienta instalada localmente (jadx, por ejemplo, no
  está instalado en el entorno de desarrollo original de este proyecto).
- **Dinámico → host**: adb/frida necesitan hablar directo con un dispositivo
  físico conectado al host. Meterlos en un contenedor solo agregaría una capa
  de red/USB que resolver sin ganar aislamiento real — el aislamiento ahí lo
  da tener un dispositivo de pruebas dedicado, no el proceso que lo controla.

## Herramientas incluidas (`docker/Dockerfile.static`)

`aapt`, `aapt2`, `apktool`, `baksmali`, `smali`, `jadx`, `r2` (radare2),
`readelf`, `nm`, `objdump`, `strings`, `blint`, `gitleaks`, `apkid`, `apksigner`,
`apkleaks`.

Todas verificadas respondiendo dentro de la imagen real (`docker run --rm
nutcracker-toolbox-static:latest <tool> --version`), no solo asumidas del
Dockerfile.

## Uso

Opt-in vía `config.yaml`:

```yaml
toolbox:
  enabled: true
  image: 'nutcracker-toolbox-static:latest'   # opcional, este es el default
```

Con `enabled: false` (default), nada cambia — cada módulo sigue invocando
binarios locales vía `shutil.which()` exactamente como antes.

Build manual (opcional -- si no existe, `client.ensure_image()` la construye
sola la primera vez que se necesita):

```bash
docker build -f nutcracker_core/toolbox/docker/Dockerfile.static \
    -t nutcracker-toolbox-static:latest nutcracker_core/toolbox/docker
```

## Integración actual

Por ahora, **solo `decompiler.py`** (jadx/apktool para `decompile()` y
`extract_manifest()`) enruta a través del toolbox cuando está habilitado.
Extender a `native_scanner.py` (nm/objdump/readelf/radare2) o
`leak_scanner.py` (gitleaks) es sencillo con el mismo patrón (`toolbox.run()`
con rutas absolutas), pero no está hecho todavía.

## Diseño del montaje de volumen

`client.run()` monta `Path.cwd()` (el directorio de trabajo del proceso host)
en el contenedor **en la misma ruta absoluta** (`-v {cwd}:{cwd} -w {cwd}`).
Suficiente porque todo el código de nutcracker opera sobre rutas relativas al
proyecto (`./downloads`, `./decompiled`, ...), nunca fuera de él — evita
necesitar lógica de traducción de rutas host↔contenedor.

El contenedor corre con `--user {uid del host}:{gid del host}` (no como
root) -- **encontrado en vivo**: sin esto, todo lo que el contenedor escribe
en el volumen queda con dueño root, y el host ni siquiera puede
sobreescribirlo después (un `apktool --force` en un rerun fallaría).

## Limitación conocida

`apksigner` no tiene un artefacto Maven standalone como `aapt2` -- se extrae
de las build-tools oficiales del SDK vía `sdkmanager` durante el build de la
imagen. Es el único paso no-fatal del Dockerfile: si falla, el build sigue
(con un aviso) y el resto de las herramientas quedan disponibles igual.
