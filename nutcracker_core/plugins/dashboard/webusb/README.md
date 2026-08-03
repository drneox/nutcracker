# WebUSB + WebCodecs — video fluido del dispositivo (Fase 4 del plan)

Este subproyecto es la única parte de `nutcracker` que necesita un toolchain de
Node/JS — el resto del dashboard (Fase 3) es un único `index.html` sin build
step. Existe porque el enfoque de `scrcpy_video.py` (releer un `.mkv` que
scrcpy sigue grabando) está topado en la práctica a ~1.3fps, medido; para
video realmente fluido (15-30fps) el navegador tiene que hablar el protocolo
ADB/scrcpy directo por USB, sin ningún proceso intermedio del lado servidor.

Basado en [Tango](https://github.com/yume-chan/ya-webadb) (antes `ya-webadb`),
la misma librería que usa [app.webadb.com](https://app.webadb.com).

## ✅ Estado de esta copia

Instalado, typechequeado y compilado de verdad (2026-07-27, con Node.js nativo
instalado en WSL para esta sesión — ver sección de fricción más abajo):
- `npm install`: 125 paquetes, sin errores.
- `npm run check` (`tsc --noEmit` contra los `.d.ts` reales): **0 errores** en
  la segunda pasada. La primera pasada encontró 7 desajustes reales de API
  respecto a lo escrito de memoria (firma de `AdbScrcpyClient.start`/
  `pushServer`, `ScrcpyOptionsLatest` necesita `version` como segundo
  argumento, `WebCodecsVideoDecoder` necesita `codec` explícito desde
  `metadata.codec`, `client.videoStream` es un getter que devuelve una
  `Promise | undefined`, no un método) — corregidos leyendo los `.d.ts` reales
  en `node_modules/@yume-chan/*/esm/*.d.ts`, exactamente para eso sirve este
  paso antes de confiar en el código.
- `npm run build`: bundle real de **315.21 KB** + chunk de worker de
  **173.49 KB** (`static/webusb-video.bundle.js` + `static/assets/worker-*.js`)
  — coincide con el orden de magnitud documentado en `plan.md`
  (~290-294KB + ~174KB de worker).
- El `scrcpy-server` real (v3.3.1) queda embebido como data URI dentro del
  bundle — **verificado byte a byte**: los 90.788 bytes decodificados
  coinciden exactamente con `node_modules/@yume-chan/fetch-scrcpy-server/server.bin`.
- El bundle se probó con un `import()` de Node real: exporta `connect` e
  `isSupported` como funciones, y `isSupported()` no lanza fuera de un
  navegador (da `false` limpiamente sin `navigator`).

**Lo que NO se pudo verificar en esta sesión** (sin un navegador real ni un
dispositivo Android conectado disponibles): la conexión WebUSB de punta a
punta contra hardware real — el flujo completo (`requestDevice` → autenticación
→ push del server → stream de video → render en canvas) está escrito según
los tipos reales y pasa el typecheck, pero **no se ejecutó nunca contra un
navegador+teléfono reales** en esta sesión. La sección "Validación en vivo"
de `plan.md` (Fase 4) documenta que una sesión anterior sí lo hizo y encontró
2 bugs reales en el camino (conflicto de exclusividad USB con `adb`, y
`WebGLVideoFrameRenderer` sin fallback) — ambos ya están corregidos en este
código (`adb kill-server` documentado como paso manual necesario,
`WebGLVideoFrameRenderer.isSupported` con fallback a `BitmapVideoFrameRenderer`),
pero no re-confirmados en vivo esta vez.

Si en algún momento algo de esto deja de compilar (los paquetes `@yume-chan/*`
son activamente desarrollados), el flujo de diagnóstico es siempre el mismo:

```bash
npm install
npm run check   # tsc --noEmit contra los tipos reales -- la fuente de verdad
```

Si `@yume-chan/*` cambió su API desde que se escribió esto, `npm run check`
va a señalar exactamente qué import/firma ya no aplica.

## Build

```bash
cd nutcracker_core/plugins/dashboard/webusb
npm install
npm run build
```

Esto produce `../static/webusb-video.bundle.js` (+ un chunk de worker) — el
`scrcpy-server` real queda embebido como data URI dentro del bundle (Vite lo
detecta automáticamente vía el patrón `new URL(..., import.meta.url)` que usa
`@yume-chan/fetch-scrcpy-server`), así que no hay ningún `.bin` suelto que
gestionar aparte.

El `index.html` del dashboard importa el bundle de forma perezosa
(`await import("/static/webusb-video.bundle.js")`) — si nunca corriste el
build, el archivo no existe, el import falla en silencio, y el botón "🔌 USB
directo (fluido)" simplemente no aparece. Cero impacto para quien no usa este
modo.

## Fricción conocida: Node/npm en WSL

Si tu `node`/`npm` en WSL resuelven al `.exe` de Windows vía interop (typico si
solo tenés Node instalado en Windows), `npm install` puede funcionar pero
**`vite build` falla** resolviendo su propio paquete al cruzar el path UNC
(`\\wsl.localhost\...`) — visto en vivo, dos veces, contra hardware real:

```
npm warn cleanup ... EISDIR
... vite build ...
CMD.EXE ... No se permiten rutas UNC
```

**Fix:** instalar un Node.js Linux nativo dentro de WSL (`nvm install node`, o
el tarball de `nodejs.org/dist` sin necesitar root) y usarlo para todo este
toolchain en vez del `node.exe`/`npm.cmd` de Windows. Confirmado que resuelve
el problema de raíz, no un workaround parcial.

## Restricciones reales (no maquilladas)

- **Solo navegadores Chromium** (Chrome/Edge/Opera/Samsung Internet) — WebUSB
  no existe en Firefox ni Safari, en ninguna plataforma. ~76% de soporte
  global. `isSupported()` hace el feature-detect; sin soporte, el botón no
  aparece y el modo `scrcpy_video.py`/polling sigue funcionando igual.
- **Requiere "secure context"**: `http://127.0.0.1`/`http://localhost` cuentan
  como seguros sin TLS, pero exponer el dashboard en la LAN
  (`nutcracker dashboard --host 0.0.0.0`) y acceder por `http://<ip-lan>:puerto`
  desde otra máquina **no** tiene WebUSB disponible sin HTTPS.
- **El teléfono debe estar por USB en la MISMA máquina que el navegador** — a
  diferencia de `scrcpy_video.py` (que puede apuntar a cualquier device
  alcanzable por `adb`, USB o red), WebUSB no puede reclamar un device
  conectado a otra máquina.
- **Conflicto de exclusividad de USB, confirmado en vivo**: mientras `adb`
  (Windows o WSL) tiene el device abierto, WebUSB falla con
  `The device is already in used by another program`. Fix real, no evitable
  desde el código: `adb kill-server` antes de conectar por WebUSB.
- **WebGL puede no estar disponible** (drivers, aceleración de hardware
  deshabilitada, políticas empresariales) — confirmado en vivo en una máquina
  Windows normal, no una VM. `main.ts` usa
  `WebGLVideoFrameRenderer.isSupported` para caer a `BitmapVideoFrameRenderer`
  (canvas 2D + `createImageBitmap`, más lento pero sin dependencia de WebGL)
  en vez de asumir que WebGL siempre funciona.
