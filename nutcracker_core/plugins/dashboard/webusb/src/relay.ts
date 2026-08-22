/**
 * Cliente del relay "browser-as-bridge" (plan.md) -- puentea `frida`/`adb`
 * REALES corriendo en el backend (en la nube, o en cualquier máquina que no
 * pueda alcanzar el USB local) hacia el device conectado a ESTE navegador,
 * reusando el mismo handle `Adb` (Tango/ya-webadb) autenticado que ya usa el
 * video WebUSB (ver getAdb() en main.ts).
 *
 * Protocolo con el backend (ver nutcracker_core/plugins/dashboard/relay.py y
 * ws.py::ws_relay -- ESTE archivo es la contraparte de ese diseño, léanse
 * juntos):
 *   - Conexión: WebSocket a /ws/relay/{session_id}. El backend manda primero
 *     {"type":"ready","ports":{"frida":N,"adb":N}} (informativo).
 *   - Control (frames de TEXTO, JSON): el backend anuncia una conexión TCP
 *     local nueva con {"type":"open","tunnel":"frida"|"adb","conn_id":N} --
 *     acá se abre `adb.createSocket("tcp:PORT")` hacia el device y se la
 *     asocia a ese conn_id. {"type":"close","conn_id":N} pide cerrarla.
 *   - Datos (frames BINARIOS): 4 bytes big-endian = conn_id, seguido del
 *     payload -- en ambas direcciones. Necesario porque frida abre varias
 *     conexiones concurrentes contra frida-server, así que hace falta
 *     multiplexar por conn_id dentro de esta única WebSocket.
 *
 * Puertos del lado device (destino de adb.createSocket): 27042 es el default
 * de frida-server (mismo puerto que aparece en `strategies.frida_host` de
 * config.yaml en toda la base); 5555 es donde adbd escucha tras `adb tcpip
 * 5555` -- ambos son convenciones ya usadas en el resto del proyecto, no
 * arbitrarias de este archivo.
 *
 * Estado real de verificación (2026-08-04): el lado backend (relay.py/ws.py)
 * tiene tests reales (loopback TCP + WebSocket real vía TestClient); ESTE
 * archivo compila (`tsc --noEmit`) contra los .d.ts reales de Tango, pero
 * todavía NO se probó contra un device físico -- eso es la verificación
 * pendiente de M1 (ver plan.md).
 */

import type { Adb, AdbSocket } from "@yume-chan/adb";
import type { MaybeConsumable, ReadableStream as YumeChanReadableStreamType } from "@yume-chan/stream-extra";
import { ReadableStream as YumeChanReadableStream } from "@yume-chan/stream-extra";

export type StatusCallback = (status: string) => void;

const DEVICE_PORT_BY_TUNNEL: Record<string, number> = {
  frida: 27042,
  adb: 5555,
};

const HEADER_BYTES = 4;

function packHeader(connId: number): Uint8Array {
  const buf = new Uint8Array(HEADER_BYTES);
  new DataView(buf.buffer).setUint32(0, connId, false); // big-endian, ver relay.py::_HEADER
  return buf;
}

function unpackHeader(frame: ArrayBuffer): { connId: number; payload: Uint8Array } {
  const view = new DataView(frame);
  const connId = view.getUint32(0, false);
  return { connId, payload: new Uint8Array(frame, HEADER_BYTES) };
}

function frameFor(connId: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(HEADER_BYTES + payload.byteLength);
  out.set(packHeader(connId), 0);
  out.set(payload, HEADER_BYTES);
  return out;
}

// Etapas 2-4 del plan (install/pull/screencap, sobre RPC -- ver handleRpcRequest
// más abajo): btoa/atob operan sobre "binary strings" (un char por byte), no
// directo sobre Uint8Array -- de ahí la conversión manual. Troceado en chunks
// para no reventar el límite de argumentos de String.fromCharCode(...arr) con
// archivos grandes (APKs, .so nativos).
const BASE64_CHUNK_SIZE = 0x8000;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += BASE64_CHUNK_SIZE) {
    binary += String.fromCharCode(...bytes.subarray(i, i + BASE64_CHUNK_SIZE));
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Concatena los chunks de un ReadableStream<Uint8Array> completo en memoria
 * -- usado para pull/screencap, donde necesitamos el archivo entero para
 * mandarlo en un solo rpc_response en base64 (ver docstring del módulo:
 * streaming real queda para una etapa futura). */
async function readAllBytes(stream: YumeChanReadableStreamType<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        chunks.push(value);
        total += value.byteLength;
      }
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Stream de un solo chunk -- lo que pide `AdbSync.write({file: ...})` como
 * entrada, ver docstring de handleRpcInstall. */
function singleChunkStream(bytes: Uint8Array): YumeChanReadableStreamType<MaybeConsumable<Uint8Array>> {
  return new YumeChanReadableStream<MaybeConsumable<Uint8Array>>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

interface _TangoChannel {
  kind: "tango";
  connId: number;
  socket: AdbSocket;
  writer: WritableStreamDefaultWriter<MaybeConsumable<Uint8Array>>;
  closed: boolean;
}

/**
 * Canal "frida" -- FIX de diseño (verificado en vivo, 2026-08-04): el túnel
 * TCP crudo original (`adb.createSocket("tcp:27042")`) entrega los bytes
 * perfecto (confirmado byte a byte con instrumentación del lado backend:
 * el GET /ws HTTP/1.1 de 177 bytes que arma `frida` llega intacto), pero la
 * conexión se cierra ~13ms después del handshake -- Tango no sostiene bien
 * una conexión que arranca con un upgrade HTTP/WebSocket. reFrida (la IDE
 * web de referencia) NUNCA pasa por ahí: usa un `WebSocket` nativo del
 * navegador directo a la IP de LAN del device (confirmado en vivo: se
 * mantiene estable, a diferencia de Tango).
 *
 * El problema: `frida` (CLI/bindings) habla su PROPIO protocolo WebSocket a
 * mano sobre bytes crudos -- arma el `GET /ws HTTP/1.1` él mismo y después
 * manda/espera frames WS crudos por el mismo socket TCP. El `WebSocket`
 * nativo del navegador hace su handshake y framing SOLO internamente, no
 * expone bytes crudos. Así que este canal actúa de traductor: recibe los
 * bytes crudos que manda `frida` (que HABLA websocket, pero como bytes),
 * les responde el handshake HTTP a mano (com WebSocket nativo hace el
 * handshake real hacia el device), y de ahí en más traduce cada frame WS
 * entrante (parsearlo, desenmascarar, mandar el payload por el WebSocket
 * nativo) y cada mensaje saliente del WebSocket nativo (re-empaquetarlo como
 * frame WS servidor, sin máscara, y mandarlo como bytes crudos de vuelta).
 *
 * Limitación conocida: no reensambla frames de continuación (fragmentación
 * WS) -- asume que cada mensaje de `frida` llega en un solo frame. Los
 * mensajes de control/RPC de frida son chicos; no se vio fragmentación en
 * las pruebas en vivo, pero queda documentado por si aparece con scripts
 * muy grandes.
 */
interface _FridaWsChannel {
  kind: "frida-ws";
  connId: number;
  ws: WebSocket | null;
  closed: boolean;
  handshakeDone: boolean;
  pendingHandshakeBytes: Uint8Array[];
  frameBuffer: Uint8Array;
}

type _Channel = _TangoChannel | _FridaWsChannel;

// ── Traductor WS crudo <-> WebSocket nativo (RFC 6455, subset) ─────────────

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

async function computeWsAccept(key: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(key + WS_GUID));
  return bytesToBase64(new Uint8Array(digest));
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Índice justo después de "\r\n\r\n" (fin de cabeceras HTTP), o -1 si el
 * buffer todavía no tiene el request completo. */
function findHttpHeaderEnd(buf: Uint8Array): number {
  for (let i = 0; i + 3 < buf.length; i++) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
      return i + 4;
    }
  }
  return -1;
}

function extractHttpHeader(headerText: string, name: string): string | null {
  const match = headerText.match(new RegExp(`^${name}:\\s*(.+)\\r?$`, "im"));
  return match ? match[1].trim() : null;
}

interface _ParsedWsFrame {
  opcode: number;
  payload: Uint8Array;
}

/** Parsea UN frame WS "de cliente" (enmascarado, por spec) desde el inicio
 * de `buf`. Devuelve null si `buf` todavía no tiene un frame completo
 * (esperar más bytes -- ver frameBuffer). No soporta frames >4GiB (de sobra
 * para nada de lo que frida manda acá). */
function parseClientWsFrame(buf: Uint8Array): { frame: _ParsedWsFrame; consumed: number } | null {
  if (buf.length < 2) return null;
  const opcode = buf[0]! & 0x0f;
  const masked = (buf[1]! & 0x80) !== 0;
  let payloadLen = buf[1]! & 0x7f;
  let offset = 2;
  if (payloadLen === 126) {
    if (buf.length < offset + 2) return null;
    payloadLen = (buf[offset]! << 8) | buf[offset + 1]!;
    offset += 2;
  } else if (payloadLen === 127) {
    if (buf.length < offset + 8) return null;
    let len = 0;
    for (let i = 0; i < 8; i++) len = len * 256 + buf[offset + i]!;
    payloadLen = len;
    offset += 8;
  }
  let maskKey: Uint8Array | null = null;
  if (masked) {
    if (buf.length < offset + 4) return null;
    maskKey = buf.subarray(offset, offset + 4);
    offset += 4;
  }
  if (buf.length < offset + payloadLen) return null;
  let payload = buf.subarray(offset, offset + payloadLen);
  if (maskKey) {
    const unmasked = new Uint8Array(payload.length);
    for (let i = 0; i < payload.length; i++) unmasked[i] = payload[i]! ^ maskKey[i % 4]!;
    payload = unmasked;
  }
  return { frame: { opcode, payload }, consumed: offset + payloadLen };
}

/** Construye UN frame WS "de servidor" (sin máscara, por spec) -- lo que
 * `frida` espera recibir de vuelta como si viniera de un frida-server real. */
function buildServerWsFrame(opcode: number, payload: Uint8Array): Uint8Array {
  const len = payload.length;
  let header: number[];
  if (len < 126) {
    header = [0x80 | opcode, len];
  } else if (len < 65536) {
    header = [0x80 | opcode, 126, (len >> 8) & 0xff, len & 0xff];
  } else {
    header = [
      0x80 | opcode, 127, 0, 0, 0, 0,
      (len >>> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff,
    ];
  }
  const out = new Uint8Array(header.length + len);
  out.set(header, 0);
  out.set(payload, header.length);
  return out;
}

const WS_OPCODE_TEXT = 0x1;
const WS_OPCODE_BINARY = 0x2;
const WS_OPCODE_CLOSE = 0x8;
const WS_OPCODE_PING = 0x9;
const WS_OPCODE_PONG = 0xa;

export class RelayClient {
  private ws: WebSocket | null = null;
  private channels = new Map<number, _Channel>();

  /**
   * `fridaWsUrl`: URL del WebSocket nativo hacia frida-server en el device
   * (ej. "ws://192.168.1.42:27042/ws") -- ver docstring de _FridaWsChannel.
   * Requiere que ESTE navegador tenga alcance de RED (no solo USB) al
   * device -- Chrome puede pedir el permiso "Acceso a Red Local" la primera
   * vez. Sin esto seteado, el túnel de "frida" no puede abrirse (el de adb,
   * vía Tango, no lo necesita).
   */
  constructor(
    private readonly adb: Adb,
    private readonly sessionId: string,
    private readonly onStatus: StatusCallback = () => {},
    private readonly fridaWsUrl: string | null = null,
  ) {}

  get connected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  /** Abre la WebSocket hacia /ws/relay/{sessionId} y empieza a atender
   * pedidos de apertura de canal del backend. No bloquea -- resuelve apenas
   * la conexión abre; el primer mensaje "ready" llega async. */
  async start(): Promise<void> {
    if (this.ws) return;
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${location.host}/ws/relay/${encodeURIComponent(this.sessionId)}`;

    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";
      ws.onopen = () => {
        this.ws = ws;
        this.onStatus(`Relay conectado (session=${this.sessionId})`);
        resolve();
      };
      ws.onerror = (ev) => {
        this.onStatus("Error de conexión al relay.");
        reject(ev);
      };
      ws.onmessage = (ev) => this.handleMessage(ev);
      ws.onclose = () => {
        this.onStatus("Relay desconectado.");
        this.ws = null;
        this.closeAllChannels();
      };
    });
  }

  /** Cierra la WebSocket y todos los canales de device abiertos. */
  async stop(): Promise<void> {
    this.ws?.close();
    this.ws = null;
    await this.closeAllChannels();
  }

  private async closeAllChannels(): Promise<void> {
    const channels = [...this.channels.values()];
    this.channels.clear();
    for (const ch of channels) {
      await this.closeChannel(ch, /* notifyBackend */ false);
    }
  }

  private handleMessage(ev: MessageEvent): void {
    if (typeof ev.data === "string") {
      let msg: any;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      void this.handleControl(msg);
      return;
    }
    if (ev.data instanceof ArrayBuffer) {
      void this.handleData(ev.data);
    }
  }

  private async handleControl(msg: {
    type?: string; tunnel?: string; conn_id?: number;
    request_id?: number; op?: string; command?: string;
    apks?: Array<{ name: string; data_b64: string }>; flags?: string[]; multi?: boolean;
    remote_path?: string;
  }): Promise<void> {
    if (msg.type === "ready") {
      // Informativo -- los puertos son del lado backend, no le sirven al
      // navegador para nada (acá solo importa qué "tunnel" pide cada "open").
      return;
    }
    if (msg.type === "open" && msg.tunnel !== undefined && msg.conn_id !== undefined) {
      await this.openChannel(msg.tunnel, msg.conn_id);
      return;
    }
    if (msg.type === "close" && msg.conn_id !== undefined) {
      const ch = this.channels.get(msg.conn_id);
      if (ch) {
        this.channels.delete(msg.conn_id);
        await this.closeChannel(ch, /* notifyBackend */ false);
      }
      return;
    }
    if (msg.type === "rpc_request" && msg.request_id !== undefined) {
      await this.handleRpcRequest(msg.request_id, msg.op, msg);
    }
  }

  /**
   * RPC (shell/install/... -- reemplaza el túnel TCP crudo original para
   * adb: Android bloquea reenviar `tcp:` hacia el propio puerto de control
   * de adbd, confirmado en vivo -- ver relay.py). Se resuelve con los
   * métodos NATIVOS de Tango (`adb.subprocess`), el mismo mecanismo que ya
   * usa scrcpy (video, arriba) y que usa app.webadb.com (construida sobre
   * esta misma librería) para shell/install/pull -- no una técnica nueva.
   */
  private async handleRpcRequest(
    requestId: number,
    op: string | undefined,
    msg: {
      command?: string;
      apks?: Array<{ name: string; data_b64: string }>; flags?: string[]; multi?: boolean;
      remote_path?: string;
      args?: string[]; duration_seconds?: number;
    },
  ): Promise<void> {
    try {
      if (op === "shell") {
        if (msg.command === undefined) {
          throw new Error("rpc_request 'shell' sin 'command'");
        }
        const result = await this.adb.subprocess.spawnAndWait(msg.command);
        this.sendControl({
          type: "rpc_response",
          request_id: requestId,
          ok: true,
          stdout: result.stdout,
          stderr: result.stderr,
          exit_code: result.exitCode,
        });
        return;
      }
      if (op === "install") {
        const result = await this.runInstall(msg.apks ?? [], msg.flags ?? [], !!msg.multi);
        this.sendControl({
          type: "rpc_response",
          request_id: requestId,
          ok: true,
          stdout: result.stdout,
          stderr: result.stderr,
          exit_code: result.exitCode,
        });
        return;
      }
      if (op === "pull") {
        if (msg.remote_path === undefined) {
          throw new Error("rpc_request 'pull' sin 'remote_path'");
        }
        const dataB64 = await this.runPull(msg.remote_path);
        this.sendControl({ type: "rpc_response", request_id: requestId, ok: true, data_b64: dataB64 });
        return;
      }
      if (op === "screencap") {
        const dataB64 = await this.runScreencap();
        this.sendControl({ type: "rpc_response", request_id: requestId, ok: true, data_b64: dataB64 });
        return;
      }
      if (op === "logcat") {
        const stdout = await this.runLogcat(msg.args ?? [], msg.duration_seconds ?? 30);
        this.sendControl({ type: "rpc_response", request_id: requestId, ok: true, stdout });
        return;
      }
      throw new Error(`op RPC desconocida: ${op}`);
    } catch (err) {
      console.error(`[nutcracker relay] rpc '${op}' falló:`, err);
      this.sendControl({
        type: "rpc_response",
        request_id: requestId,
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * Etapa 2 del plan: sube cada APK a /data/local/tmp/<nombre> con
   * `adb.sync().write()` (método nativo de Tango, el mismo que usa scrcpy
   * para subir su propio server -- ver startVideo() en main.ts), corre
   * `pm install[-multiple] <flags> <rutas>`, y borra los temporales
   * (best-effort -- un fallo de cleanup no debe tumbar la instalación, que
   * ya corrió con éxito o falló por su cuenta antes de este paso).
   */
  private async runInstall(
    apks: Array<{ name: string; data_b64: string }>,
    flags: string[],
    multi: boolean,
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    if (apks.length === 0) {
      throw new Error("rpc_request 'install' sin 'apks'");
    }
    const sync = await this.adb.sync();
    const remotePaths: string[] = [];
    try {
      for (const apk of apks) {
        const remotePath = `/data/local/tmp/${apk.name}`;
        const bytes = base64ToBytes(apk.data_b64);
        await sync.write({ filename: remotePath, file: singleChunkStream(bytes) });
        remotePaths.push(remotePath);
      }
    } finally {
      await sync.dispose();
    }

    const installCmd = multi
      ? ["pm", "install-multiple", ...flags, ...remotePaths]
      : ["pm", "install", ...flags, ...remotePaths];
    const result = await this.adb.subprocess.spawnAndWait(installCmd.join(" "));

    try {
      await this.adb.subprocess.spawnAndWait(`rm -f ${remotePaths.join(" ")}`);
    } catch (err) {
      console.warn("[nutcracker relay] limpieza de APKs temporales falló (no fatal):", err);
    }

    return result;
  }

  /** Etapa 4 del plan: `adb.sync().read()` -- también método nativo de
   * Tango, no un socket crudo. Devuelve el archivo entero en base64 (ver
   * readAllBytes -- streaming real de archivos grandes queda para después). */
  private async runPull(remotePath: string): Promise<string> {
    const sync = await this.adb.sync();
    try {
      const bytes = await readAllBytes(sync.read(remotePath));
      return bytesToBase64(bytes);
    } finally {
      await sync.dispose();
    }
  }

  /**
   * Etapa 3 del plan: `screencap -p` vía `adb.subprocess.spawn()` (NO
   * `spawnAndWait`, que decodifica stdout como texto UTF-8 -- corrompería
   * los bytes binarios del PNG). Se lee el stream crudo de stdout y se
   * manda en base64, igual que pull.
   */
  private async runScreencap(): Promise<string> {
    const process = await this.adb.subprocess.spawn("screencap -p");
    const bytes = await readAllBytes(process.stdout);
    await process.exit;
    return bytesToBase64(bytes);
  }

  /**
   * Etapa 5 del plan: NO es streaming línea-a-línea real -- aipwn solo
   * consume el logcat capturado DESPUÉS de que termina la ventana de
   * captura de todos modos (ver frida_capture.py::stream_logcat, que solo
   * junta líneas en una lista para razonar sobre ellas al final, nunca las
   * usa en vivo mientras llegan). Así que acá se junta todo lo que
   * `logcat` (sin `-c`, modo streaming real en el device) escupe durante
   * `durationSeconds` y se manda entero en un solo `rpc_response` -- mismo
   * patrón pedido-respuesta que shell/install/pull/screencap, sin agregar
   * un protocolo de streaming nuevo al relay.
   *
   * `reader.cancel()` (no `Promise.race` por lectura) es la forma correcta
   * de cortar un ReadableStream a mitad de lectura: soltar el lock mientras
   * hay un `read()` pendiente es inseguro (puede dejarlo colgado para
   * siempre). `cancel()` hace que el `read()` en vuelo resuelva `done` (o
   * en algunos casos rechace -- el catch de abajo cubre eso también).
   */
  private async runLogcat(args: string[], durationSeconds: number): Promise<string> {
    const process = await this.adb.subprocess.spawn(["logcat", ...args].join(" "));
    const reader = process.stdout.getReader();
    const chunks: Uint8Array[] = [];
    const timer = setTimeout(() => {
      reader.cancel().catch(() => {});
    }, Math.max(0, durationSeconds) * 1000);
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
    } catch {
      // reader.cancel() puede rechazar el read() en vuelo en vez de
      // resolverlo con done -- fin normal de la ventana de captura, no un
      // error real.
    } finally {
      clearTimeout(timer);
      try {
        reader.releaseLock();
      } catch {
        // idem -- puede que cancel() ya la haya soltado.
      }
      try {
        await process.kill();
      } catch (err) {
        console.warn("[nutcracker relay] no se pudo matar el proceso logcat (no fatal):", err);
      }
    }
    return new TextDecoder().decode(concatBytes(chunks));
  }

  private async handleData(frame: ArrayBuffer): Promise<void> {
    const { connId, payload } = unpackHeader(frame);
    const ch = this.channels.get(connId);
    if (!ch || ch.closed) return;
    if (ch.kind === "frida-ws") {
      await this.handleFridaWsBackendBytes(ch, payload);
      return;
    }
    try {
      await ch.writer.write(payload);
    } catch (err) {
      console.error("[nutcracker relay] write al device falló:", err);
      this.channels.delete(connId);
      await this.closeChannel(ch, /* notifyBackend */ true);
    }
  }

  private async openChannel(tunnel: string, connId: number): Promise<void> {
    if (tunnel === "frida") {
      this.openFridaWsChannel(connId);
      return;
    }
    const port = DEVICE_PORT_BY_TUNNEL[tunnel];
    if (port === undefined) {
      console.error(`[nutcracker relay] tunnel desconocido: ${tunnel}`);
      this.sendControl({ type: "closed", conn_id: connId });
      return;
    }
    let socket: AdbSocket;
    try {
      socket = await this.adb.createSocket(`tcp:${port}`);
    } catch (err) {
      console.error(`[nutcracker relay] no se pudo abrir tcp:${port} en el device:`, err);
      this.sendControl({ type: "closed", conn_id: connId });
      return;
    }
    const writer = socket.writable.getWriter();
    const channel: _TangoChannel = { kind: "tango", connId, socket, writer, closed: false };
    this.channels.set(connId, channel);
    void this.pumpDeviceToBackend(channel);
  }

  private async pumpDeviceToBackend(ch: _TangoChannel): Promise<void> {
    const reader = ch.socket.readable.getReader();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength > 0) {
          this.sendData(ch.connId, value);
        }
      }
    } catch (err) {
      console.error("[nutcracker relay] lectura del device falló:", err);
    } finally {
      reader.releaseLock();
      if (this.channels.delete(ch.connId)) {
        await this.closeChannel(ch, /* notifyBackend */ true);
      }
    }
  }

  private async closeChannel(ch: _Channel, notifyBackend: boolean): Promise<void> {
    if (ch.kind === "frida-ws") {
      await this.closeFridaWsChannel(ch, notifyBackend);
      return;
    }
    if (ch.closed) return;
    ch.closed = true;
    try {
      await ch.writer.close();
    } catch {
      // ya puede estar cerrado del otro lado -- no es un error real acá.
    }
    try {
      await ch.socket.close();
    } catch {
      // idem.
    }
    if (notifyBackend) {
      this.sendControl({ type: "closed", conn_id: ch.connId });
    }
  }

  // ── Canal "frida" -- traductor WS crudo <-> WebSocket nativo ────────────
  // Ver docstring de _FridaWsChannel para el porqué de todo este bloque.

  private openFridaWsChannel(connId: number): void {
    if (!this.fridaWsUrl) {
      console.error(
        "[nutcracker relay] no hay fridaWsUrl configurada -- no se puede abrir el túnel de frida " +
        "(ver el campo 'IP del device' al activar el relay)",
      );
      this.sendControl({ type: "closed", conn_id: connId });
      return;
    }
    const channel: _FridaWsChannel = {
      kind: "frida-ws", connId, ws: null, closed: false,
      handshakeDone: false, pendingHandshakeBytes: [], frameBuffer: new Uint8Array(0),
    };
    this.channels.set(connId, channel);
    // No abrimos el WebSocket nativo todavía -- recién cuando lleguen los
    // bytes del "GET /ws" que arma `frida`, para sacarle el
    // Sec-WebSocket-Key (ver handleFridaWsBackendBytes).
  }

  private async handleFridaWsBackendBytes(ch: _FridaWsChannel, payload: Uint8Array): Promise<void> {
    if (!ch.handshakeDone) {
      ch.pendingHandshakeBytes.push(payload);
      const total = concatBytes(ch.pendingHandshakeBytes);
      const headerEnd = findHttpHeaderEnd(total);
      if (headerEnd === -1) return; // handshake HTTP todavía incompleto, esperar más bytes

      const headerText = new TextDecoder().decode(total.subarray(0, headerEnd));
      const key = extractHttpHeader(headerText, "Sec-WebSocket-Key");
      if (!key) {
        console.error("[nutcracker relay] frida-ws: 'GET /ws' sin Sec-WebSocket-Key, no se puede completar el handshake");
        await this.closeFridaWsChannel(ch, true);
        return;
      }
      try {
        await this.completeFridaWsHandshake(ch, key);
      } catch (err) {
        console.error(`[nutcracker relay] frida-ws: no se pudo conectar a ${this.fridaWsUrl}:`, err);
        await this.closeFridaWsChannel(ch, true);
        return;
      }
      const leftover = total.subarray(headerEnd);
      if (leftover.length > 0) {
        ch.frameBuffer = leftover;
        this.processFridaWsFrames(ch);
      }
      return;
    }
    ch.frameBuffer = concatBytes([ch.frameBuffer, payload]);
    this.processFridaWsFrames(ch);
  }

  private async completeFridaWsHandshake(ch: _FridaWsChannel, key: string): Promise<void> {
    const accept = await computeWsAccept(key);
    const ws = new WebSocket(this.fridaWsUrl!);
    ws.binaryType = "arraybuffer";
    await new Promise<void>((resolve, reject) => {
      ws.onopen = () => resolve();
      ws.onerror = () => reject(new Error("el WebSocket nativo a frida-server falló al conectar"));
    });
    ch.ws = ws;
    ws.onmessage = (ev) => this.forwardFridaWsMessageToBackend(ch, ev);
    ws.onerror = () => console.error("[nutcracker relay] frida-ws: error en el WebSocket nativo (post-conexión)");
    ws.onclose = () => { void this.closeFridaWsChannel(ch, true); };

    ch.handshakeDone = true;
    const response =
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`;
    this.sendData(ch.connId, new TextEncoder().encode(response));
  }

  private processFridaWsFrames(ch: _FridaWsChannel): void {
    let buf = ch.frameBuffer;
    while (true) {
      const parsed = parseClientWsFrame(buf);
      if (!parsed) break;
      buf = buf.subarray(parsed.consumed);
      this.handleFridaClientFrame(ch, parsed.frame.opcode, parsed.frame.payload);
    }
    ch.frameBuffer = buf;
  }

  private handleFridaClientFrame(ch: _FridaWsChannel, opcode: number, payload: Uint8Array): void {
    if (opcode === WS_OPCODE_CLOSE) {
      void this.closeFridaWsChannel(ch, false);
      return;
    }
    if (opcode === WS_OPCODE_PING) {
      // Responder el ping nosotros mismos -- este lado "es" el servidor
      // desde la perspectiva de frida, no hace falta ida y vuelta al device.
      this.sendData(ch.connId, buildServerWsFrame(WS_OPCODE_PONG, payload));
      return;
    }
    if (opcode === WS_OPCODE_PONG) {
      return;
    }
    if (ch.ws && ch.ws.readyState === WebSocket.OPEN) {
      ch.ws.send(payload);
    }
  }

  private forwardFridaWsMessageToBackend(ch: _FridaWsChannel, ev: MessageEvent): void {
    if (typeof ev.data === "string") {
      this.sendData(ch.connId, buildServerWsFrame(WS_OPCODE_TEXT, new TextEncoder().encode(ev.data)));
    } else if (ev.data instanceof ArrayBuffer) {
      this.sendData(ch.connId, buildServerWsFrame(WS_OPCODE_BINARY, new Uint8Array(ev.data)));
    }
  }

  private async closeFridaWsChannel(ch: _FridaWsChannel, notifyBackend: boolean): Promise<void> {
    if (ch.closed) return;
    ch.closed = true;
    this.channels.delete(ch.connId);
    try {
      ch.ws?.close();
    } catch {
      // idem que en closeChannel -- ya puede estar cerrado del otro lado.
    }
    if (notifyBackend) {
      this.sendControl({ type: "closed", conn_id: ch.connId });
    }
  }

  private sendControl(msg: Record<string, unknown>): void {
    this.ws?.send(JSON.stringify(msg));
  }

  private sendData(connId: number, payload: Uint8Array): void {
    this.ws?.send(frameFor(connId, payload));
  }
}
