/**
 * WebUSB + WebCodecs: video del dispositivo directo por USB, sin proceso
 * servidor de por medio (Fase 4 del plan.md — "video realmente fluido").
 *
 * Cadena real (verificada leyendo los .d.ts reales de los paquetes instalados
 * -- no adivinada de la documentación web, ver README.md de este subproyecto):
 *   AdbDaemonWebUsbDeviceManager.BROWSER.requestDevice()   (o .getDevices())
 *     -> device.connect()
 *     -> AdbDaemonTransport.authenticate({ serial, connection, credentialStore })
 *     -> new Adb(transport)
 *     -> AdbScrcpyClient.pushServer(adb, stream, path)
 *     -> AdbScrcpyClient.start(adb, path, options)
 *     -> (await client.videoStream) -> { stream, metadata }
 *     -> WebCodecsVideoDecoder({ codec: metadata.codec, renderer }) -> <canvas>
 *
 * `@yume-chan/fetch-scrcpy-server` NO es un módulo pre-construido: su
 * `index.js`/`server.bin` los genera el propio paquete la primera vez que se
 * corre `npx fetch-scrcpy-server <version>` (ver package.json de este
 * subproyecto, script "prebuild") -- sin ese paso, este import falla porque
 * los archivos literalmente no existen todavía en node_modules/.
 *
 * Restricciones reales (no ocultar, ver README.md de este subproyecto):
 *   - Solo navegadores Chromium (WebUSB no existe en Firefox/Safari).
 *   - Requiere "secure context" (localhost/127.0.0.1 cuentan, HTTP-LAN no).
 *   - El teléfono debe estar por USB en la MISMA máquina que el navegador.
 *   - Exclusividad de USB: WinUSB permite un solo handle abierto por interfaz,
 *     y adb.exe pide la misma -- `adb kill-server` antes de conectar
 *     (confirmado en vivo, ver plan.md).
 *   - WebGL puede no estar disponible (drivers/políticas) -- fallback real a
 *     BitmapVideoFrameRenderer, no solo teórico (encontrado en vivo contra
 *     hardware real, ver plan.md).
 *
 * Sin control táctil en esta primera versión (control: false) -- solo video.
 */

import { Adb, AdbDaemonTransport } from "@yume-chan/adb";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";
import { AdbDaemonWebUsbDeviceManager } from "@yume-chan/adb-daemon-webusb";
import type { AdbDaemonWebUsbDevice } from "@yume-chan/adb-daemon-webusb";
import { AdbScrcpyClient, AdbScrcpyOptionsLatest } from "@yume-chan/adb-scrcpy";
import { BIN as SERVER_BIN, VERSION as SERVER_VERSION } from "@yume-chan/fetch-scrcpy-server";
import { ScrcpyOptionsLatest } from "@yume-chan/scrcpy";
import {
  BitmapVideoFrameRenderer,
  WebCodecsVideoDecoder,
  WebGLVideoFrameRenderer,
} from "@yume-chan/scrcpy-decoder-webcodecs";
import { ReadableStream as YumeChanReadableStream } from "@yume-chan/stream-extra";

// Re-exportado para que el bundle lo exponga -- ver vite.config.ts (build.lib
// solo preserva exports nombrados alcanzables desde ESTE entry point).
export { RelayClient } from "./relay.js";

// Ruta en el device donde se sube el server.bin (ver AdbScrcpyClient.pushServer
// más abajo) -- nombre propio para no chocar con otras herramientas (scrcpy
// del sistema, ws-scrcpy, etc.) que puedan dejar su propio server ahí.
const SERVER_PATH = "/data/local/tmp/scrcpy-server-nutcracker.jar";

export type StatusCallback = (status: string) => void;

/** Feature-detect: WebUSB + soporte de WebCodecs en este navegador. */
export function isSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    "usb" in navigator &&
    !!AdbDaemonWebUsbDeviceManager.BROWSER &&
    WebCodecsVideoDecoder.isSupported
  );
}

let _credentialStore: AdbWebCredentialStore | null = null;

function credentialStore(): AdbWebCredentialStore {
  if (!_credentialStore) {
    _credentialStore = new AdbWebCredentialStore("nutcracker-dashboard");
  }
  return _credentialStore;
}

/** Sesión viva, para poder cerrarla explícitamente (ver disconnect()). */
interface Session {
  adb: Adb;
  client: AdbScrcpyClient;
  decoder: WebCodecsVideoDecoder;
  abort: AbortController;
}

let _session: Session | null = null;

/** True si hay video corriendo ahora mismo en esta pestaña. */
export function isConnected(): boolean {
  return _session !== null;
}

/**
 * Handle `Adb` (Tango) de la sesión WebUSB activa, o null si no hay ninguna.
 *
 * Expuesto para relay.ts (plan.md: relay "browser-as-bridge" frida/adb hacia
 * un device detrás del navegador) -- reusa la MISMA conexión USB autenticada
 * del video en vez de abrir una segunda (WebUSB es exclusivo por interfaz,
 * ver el comentario de isUsbBusyError() más abajo; dos handles simultáneos
 * se pisarían entre sí).
 */
export function getAdb(): Adb | null {
  return _session?.adb ?? null;
}

function isUsbBusyError(message: string): boolean {
  return /already in used|already open|access denied|in use/i.test(message);
}

function describeError(message: string): string {
  if (isUsbBusyError(message)) {
    return (
      `Error: el dispositivo ya está reclamado por otro programa (adb). ` +
      `Corré "adb kill-server" y reintentá. (${message})`
    );
  }
  return `Error conectando por WebUSB: ${message}`;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Conecta por WebUSB pidiendo al usuario que elija el dispositivo (requiere
 * gesto del usuario: el picker de Chrome no abre sin un click).
 *
 * Devuelve el serial conectado, o null si falló/se canceló. El llamador lo usa
 * para recordar el dispositivo y poder reconectarse solo tras un F5 (ver
 * reconnect()).
 */
export async function connect(
  canvas: HTMLCanvasElement,
  onStatus: StatusCallback,
): Promise<string | null> {
  try {
    if (!isSupported()) {
      onStatus("WebUSB no soportado en este navegador (usa Chrome/Edge/Opera).");
      return null;
    }
    onStatus("Solicitando acceso al dispositivo por USB…");
    const device = await AdbDaemonWebUsbDeviceManager.BROWSER!.requestDevice();
    if (!device) {
      onStatus("Ningún dispositivo seleccionado.");
      return null;
    }
    await startVideo(device, canvas, onStatus);
    return device.serial;
  } catch (err: unknown) {
    // FIX: sin este catch, cualquier fallo de la cadena (el más común y
    // documentado: "device already in used by another program" -- adb tiene
    // el device reclamado, WebUSB necesita acceso exclusivo) quedaba como
    // unhandled promise rejection: la UI se quedaba con el canvas en blanco y
    // CERO mensaje visible -- el error solo aparecía en la consola del
    // navegador, que nadie mira. Reportado como "no se ve nada" pese a que la
    // cadena real sí estaba fallando.
    const message = err instanceof Error ? err.message : String(err);
    onStatus(describeError(message));
    console.error("[nutcracker webusb] connect() falló:", err);
    return null;
  }
}

/**
 * Reconecta sin intervención del usuario, para sobrevivir a un F5.
 *
 * Un reload destruye el contexto JS y con él el handle USB, el decoder y el
 * canvas: la sesión anterior *no* puede seguir viva, no hay API de navegador
 * que lo permita. Lo que sí se conserva es el **permiso** que el usuario ya
 * otorgó a este origen, así que `getDevices()` devuelve el dispositivo sin
 * volver a abrir el picker (que además exigiría un click). Eso convierte el F5
 * de "elegí el device de nuevo y esperá" en "esperá un par de segundos".
 *
 * `serial` acota a qué dispositivo volver si hay varios autorizados; si no se
 * pasa (o ya no está conectado), usa el primero disponible.
 *
 * Reintenta ante "device busy": justo después de un reload, Chrome puede tardar
 * un instante en liberar el handle USB de la sesión anterior, y el primer
 * intento se topa con su propio fantasma.
 */
export async function reconnect(
  canvas: HTMLCanvasElement,
  onStatus: StatusCallback,
  serial?: string | null,
  attempts = 3,
): Promise<string | null> {
  try {
    if (!isSupported()) return null;

    const devices = await AdbDaemonWebUsbDeviceManager.BROWSER!.getDevices();
    if (devices.length === 0) return null; // nunca se autorizó nada: hace falta el botón

    const device = (serial && devices.find((d) => d.serial === serial)) || devices[0];

    for (let attempt = 0; attempt < attempts; attempt++) {
      try {
        onStatus(
          attempt === 0
            ? "Reconectando por USB tras recargar la página…"
            : `Reconectando por USB (intento ${attempt + 1}/${attempts})…`,
        );
        await startVideo(device, canvas, onStatus);
        return device.serial;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        const last = attempt === attempts - 1;
        if (last || !isUsbBusyError(message)) {
          onStatus(describeError(message));
          console.error("[nutcracker webusb] reconnect() falló:", err);
          return null;
        }
        await sleep(600);
      }
    }
    return null;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    onStatus(describeError(message));
    console.error("[nutcracker webusb] reconnect() falló:", err);
    return null;
  }
}

/**
 * Cierra la sesión y suelta el cable USB.
 *
 * Necesario porque el cable es exclusivo: mientras esta pestaña lo tenga, adb
 * no puede usarlo. Sin una forma explícita de soltarlo, la única salida sería
 * cerrar la pestaña.
 */
export async function disconnect(onStatus?: StatusCallback): Promise<void> {
  const session = _session;
  _session = null;
  if (!session) return;
  session.abort.abort();
  // Cada cierre va en su propio try: si el primero falla (device desenchufado
  // en caliente, p.ej.) los siguientes igual tienen que correr, o el handle USB
  // queda tomado y nadie puede volver a conectarse sin recargar.
  try {
    session.decoder.dispose();
  } catch (err) {
    console.warn("[nutcracker webusb] decoder.dispose() falló:", err);
  }
  try {
    await session.client.close();
  } catch (err) {
    console.warn("[nutcracker webusb] client.close() falló:", err);
  }
  try {
    await session.adb.close();
  } catch (err) {
    console.warn("[nutcracker webusb] adb.close() falló:", err);
  }
  onStatus?.("Desconectado — el cable USB queda libre para adb.");
}

/** Cadena común a connect() y reconnect(): de un device ya obtenido al video. */
async function startVideo(
  device: AdbDaemonWebUsbDevice,
  canvas: HTMLCanvasElement,
  onStatus: StatusCallback,
): Promise<void> {
  // Si ya había una sesión en esta pestaña, soltala antes: dos sesiones sobre
  // el mismo cable se pisan (el propio device queda "busy" contra sí mismo).
  await disconnect();

  onStatus("Conectando…");
  const connection = await device.connect();

  onStatus("Autenticando (revisa el teléfono si pide autorizar)…");
  const transport = await AdbDaemonTransport.authenticate({
    serial: device.serial,
    connection,
    credentialStore: credentialStore(),
  });
  const adb = new Adb(transport);

  onStatus("Descargando/enviando scrcpy-server al dispositivo…");
  const serverBuffer = await fetch(SERVER_BIN).then((r) => r.arrayBuffer());
  await AdbScrcpyClient.pushServer(
    adb,
    new YumeChanReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(serverBuffer));
        controller.close();
      },
    }),
    SERVER_PATH,
  );

  onStatus("Arrancando scrcpy en el dispositivo…");
  const options = new AdbScrcpyOptionsLatest(
    new ScrcpyOptionsLatest(
      {
        video: true,
        audio: false,
        control: false, // solo video en esta primera versión, sin control táctil
      },
      SERVER_VERSION,
    ),
  );
  const client = await AdbScrcpyClient.start(adb, SERVER_PATH, options);

  const videoStreamPromise = client.videoStream;
  if (!videoStreamPromise) {
    onStatus("El servidor no devolvió stream de video (¿deshabilitado en options?).");
    await adb.close();
    return;
  }
  const { stream, metadata } = await videoStreamPromise;

  const useWebGL = WebGLVideoFrameRenderer.isSupported;
  onStatus(useWebGL ? "Iniciando decodificación (WebGL)…" : "Iniciando decodificación (canvas 2D, sin WebGL)…");
  const renderer = useWebGL
    ? new WebGLVideoFrameRenderer(canvas)
    : new BitmapVideoFrameRenderer(canvas);
  const decoder = new WebCodecsVideoDecoder({ codec: metadata.codec, renderer });

  const abort = new AbortController();
  _session = { adb, client, decoder, abort };

  stream.pipeTo(decoder.writable, { signal: abort.signal }).catch((err: unknown) => {
    // Un abort es el cierre normal pedido por disconnect(), no un fallo.
    if (abort.signal.aborted) return;
    _session = null;
    onStatus(`Stream de video terminó: ${String(err)}`);
  });

  onStatus("● USB directo (fluido) — conectado");
}
