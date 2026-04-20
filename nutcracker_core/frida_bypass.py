"""
Generador de scripts Frida para bypass de protecciones anti-root.

Analiza qué detectores encontraron evidencias y genera un script .js
personalizado que hookea los métodos correspondientes en runtime.

Uso del script generado:
    frida -U -f <package_id> -l bypass_<package>.js
    frida -U --attach-pid <pid> -l bypass_<package>.js
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .analyzer import AnalysisResult


# ── Bloques de código Frida por categoría ────────────────────────────────────

_HEADER = """\
/**
 * Frida bypass script — generado por nutcracker
 * Package : {package}
 * Generado: {date}
 * 
 * Uso:
 *   frida -U -f {package} -l {filename}
 *
 * Instalar Frida:
 *   pip install frida-tools
 *   # Descargar frida-server en el dispositivo:
 *   # https://github.com/frida/frida/releases
 */

'use strict';

Java.perform(function() {
  console.log('[nutcracker] Iniciando bypass anti-root...');
"""

_FOOTER = """\

  console.log('[nutcracker] Hooks instalados correctamente.');
});
"""

_HOOK_FILE_EXISTS = """\
  // ── Bypass: comprobaciones de archivos root (su, busybox, etc.) ──────────
  (function() {
    var ROOT_PATHS = [
      '/system/xbin/su', '/system/bin/su', '/sbin/su', '/su/bin/su',
      '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
      '/system/xbin/busybox', '/system/bin/busybox',
      '/system/xbin/daemonsu', '/system/sd/xbin/su',
      '/system/app/Superuser.apk', '/system/app/SuperSU.apk',
      '/system/bin/failsafe/su', '/data/adb/magisk', '/sbin/.magisk',
    ];
    try {
      var File = Java.use('java.io.File');
      File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (ROOT_PATHS.indexOf(path) !== -1) {
          console.log('[Bypass] File.exists bloqueado para: ' + path);
          return false;
        }
        return this.exists();
      };
      File.canExecute.implementation = function() {
        var path = this.getAbsolutePath();
        if (ROOT_PATHS.indexOf(path) !== -1) return false;
        return this.canExecute();
      };
      console.log('[Bypass] ✔ File.exists/canExecute hooked');
    } catch(e) { console.log('[Bypass] File hook error: ' + e); }
  })();
"""

_HOOK_RUNTIME_EXEC = """\
  // ── Bypass: Runtime.exec("su"), "which su", etc. ─────────────────────────
  (function() {
    var BLOCKED_CMDS = ['su', 'which su', 'id\n', 'busybox'];
    function isRootCmd(cmd) {
      for (var i = 0; i < BLOCKED_CMDS.length; i++) {
        if (cmd.indexOf(BLOCKED_CMDS[i]) !== -1) return true;
      }
      return false;
    }
    try {
      var Runtime = Java.use('java.lang.Runtime');
      Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (isRootCmd(cmd)) {
          console.log('[Bypass] Runtime.exec bloqueado: ' + cmd);
          return this.exec('echo');
        }
        return this.exec(cmd);
      };
      Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
        var joined = cmds.join(' ');
        if (isRootCmd(joined)) {
          console.log('[Bypass] Runtime.exec[] bloqueado: ' + joined);
          return this.exec('echo');
        }
        return this.exec(cmds);
      };
      console.log('[Bypass] ✔ Runtime.exec hooked');
    } catch(e) { console.log('[Bypass] Runtime.exec hook error: ' + e); }
  })();
"""

_HOOK_PACKAGE_MANAGER = """\
  // ── Bypass: PackageManager — ocultar paquetes Magisk/SuperSU ─────────────
  (function() {
    var ROOT_PACKAGES = [
      'com.topjohnwu.magisk', 'io.github.vvb2060.magisk',
      'eu.chainfire.supersu', 'com.noshufou.android.su',
      'me.weishu.kernelsu', 'com.rifsxd.ksunext', 'me.bmax.apatch',
      'com.koushikdutta.superuser', 'com.thirdparty.superuser',
    ];
    try {
      var PackageManager = Java.use('android.app.ApplicationPackageManager');
      PackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
        var pkgs = this.getInstalledPackages(flags);
        var ArrayList = Java.use('java.util.ArrayList');
        var filtered = ArrayList.$new();
        for (var i = 0; i < pkgs.size(); i++) {
          var pkg = pkgs.get(i);
          if (ROOT_PACKAGES.indexOf(pkg.packageName.value) === -1) {
            filtered.add(pkg);
          } else {
            console.log('[Bypass] PackageManager ocultando: ' + pkg.packageName.value);
          }
        }
        return filtered;
      };
      PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(name, flags) {
        if (ROOT_PACKAGES.indexOf(name) !== -1) {
          console.log('[Bypass] getPackageInfo bloqueado para: ' + name);
          throw Java.use('android.content.pm.PackageManager')
                    .NameNotFoundException.$new(name);
        }
        return this.getPackageInfo(name, flags);
      };
      console.log('[Bypass] ✔ PackageManager hooked');
    } catch(e) { console.log('[Bypass] PackageManager hook error: ' + e); }
  })();
"""

_HOOK_BUILD_PROPS = """\
  // ── Bypass: propiedades del sistema (ro.build.tags, ro.debuggable, etc.) ──
  (function() {
    try {
      var SystemProperties = Java.use('android.os.SystemProperties');
      SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        var val = this.get(key);
        if (key === 'ro.build.tags' && val.indexOf('test-keys') !== -1) {
          console.log('[Bypass] SystemProperties.get bloqueado: ' + key);
          return 'release-keys';
        }
        if (key === 'ro.debuggable') return '0';
        if (key === 'ro.secure') return '1';
        if (key === 'ro.build.type' && (val === 'userdebug' || val === 'eng')) return 'user';
        return val;
      };
      SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
        var val = this.get(key, def);
        if (key === 'ro.build.tags' && val.indexOf('test-keys') !== -1) return 'release-keys';
        if (key === 'ro.debuggable') return '0';
        if (key === 'ro.secure') return '1';
        return val;
      };
      console.log('[Bypass] ✔ SystemProperties hooked');
    } catch(e) { console.log('[Bypass] SystemProperties hook error: ' + e); }
  })();
"""

_HOOK_ROOTBEER = """\
  // ── Bypass: RootBeer library ──────────────────────────────────────────────
  (function() {
    var methods = [
      'isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
      'detectPotentiallyDangerousApps', 'checkForBinary', 'checkForDangerousProps',
      'checkForRWPaths', 'detectTestKeys', 'checkSuExists',
    ];
    try {
      var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
      methods.forEach(function(m) {
        try {
          RootBeer[m].implementation = function() {
            console.log('[Bypass] RootBeer.' + m + ' → false');
            return false;
          };
        } catch(e) {}
      });
      console.log('[Bypass] ✔ RootBeer hooked');
    } catch(e) { console.log('[Bypass] RootBeer no encontrado (OK si no está en runtime): ' + e); }
  })();
"""

_HOOK_ROOTCLOAK = """\
  // ── Bypass: RootCloak ─────────────────────────────────────────────────────
  (function() {
    try {
      var RootCloak = Java.use('com.devadvance.rootcloak.RootCloak');
      RootCloak.checkForRootNative.implementation = function() { return false; };
      console.log('[Bypass] ✔ RootCloak hooked');
    } catch(e) { console.log('[Bypass] RootCloak no encontrado (OK): ' + e); }
  })();
"""

_HOOK_SAFETYNET = """\
  // ── Bypass: SafetyNet / Play Integrity ───────────────────────────────────
  // NOTA: SafetyNet/Play Integrity usa attestación del servidor.
  // Este hook intercepta la callback local para simular éxito.
  (function() {
    try {
      // Hookear el resultado del JNI de SafetyNet
      var SafetyNetHelper = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
      console.log('[Bypass] SafetyNet detectado (attestación requiere bypass a nivel red)');
    } catch(e) {}
    // Alternativa: interceptar la verificación de la respuesta en la app
    try {
      var JwsResult = Java.use('com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse');
      JwsResult.getJwsResult.implementation = function() {
        console.log('[Bypass] SafetyNet getJwsResult interceptado');
        // Devuelve un JWS con basicIntegrity=true, ctsProfileMatch=true (mock)
        return 'eyJhbGciOiJSUzI1NiJ9.eyJub25jZSI6IiIsInRpbWVzdGFtcE1zIjoxNjAwMDAwMDAwMDAwLCJhcGtQYWNrYWdlTmFtZSI6ImNvbS5leGFtcGxlIiwiYXBrQ2VydGlmaWNhdGVEaWdlc3QiOlsiIl0sImN0c1Byb2ZpbGVNYXRjaCI6dHJ1ZSwiYmFzaWNJbnRlZ3JpdHkiOnRydWV9.AAAAAA';
      };
      console.log('[Bypass] ✔ SafetyNet AttestationResponse hooked');
    } catch(e) {}
  })();
"""

_HOOK_FRIDA_DETECTION = """\
  // ── Bypass: Detección de Frida ────────────────────────────────────────────
  // Algunas apps detectan Frida leyendo /proc/self/maps o buscando "frida" en el proceso.
  (function() {
    try {
      // Interceptar lectura de /proc/maps para ocultar frida-agent
      var BufferedReader = Java.use('java.io.BufferedReader');
      var original_readLine = BufferedReader.readLine;
      BufferedReader.readLine.implementation = function() {
        var line = this.readLine();
        if (line !== null && (
          line.indexOf('frida') !== -1 ||
          line.indexOf('gum-js-loop') !== -1 ||
          line.indexOf('linjector') !== -1
        )) {
          console.log('[Bypass] /proc/maps línea Frida ocultada');
          return this.readLine(); // saltar esta línea
        }
        return line;
      };
      console.log('[Bypass] ✔ Detección Frida en /proc/maps hooked');
    } catch(e) { console.log('[Bypass] Frida-detection hook error: ' + e); }
  })();
"""


# ── Mapa detector → bloques de hooks ─────────────────────────────────────────

_DETECTOR_HOOKS: dict[str, list[str]] = {
    "KnownLibrariesDetector": [_HOOK_FILE_EXISTS, _HOOK_RUNTIME_EXEC],
    "RootBeer": [_HOOK_ROOTBEER, _HOOK_FILE_EXISTS],
    "RootCloak": [_HOOK_ROOTCLOAK],
    "SafetyNetDetector": [_HOOK_SAFETYNET],
    "ManualChecksDetector": [_HOOK_FILE_EXISTS, _HOOK_RUNTIME_EXEC, _HOOK_BUILD_PROPS],
    "MagiskDetector": [_HOOK_PACKAGE_MANAGER, _HOOK_FILE_EXISTS],
}

# Hooks siempre incluidos (defensa en profundidad)
_BASE_HOOKS: list[str] = [
    _HOOK_FILE_EXISTS,
    _HOOK_RUNTIME_EXEC,
    _HOOK_PACKAGE_MANAGER,
    _HOOK_BUILD_PROPS,
    _HOOK_FRIDA_DETECTION,
]


def generate_bypass_script(result: "AnalysisResult", output_dir: Path) -> Path:
    """
    Genera un script Frida de bypass personalizado según las protecciones detectadas.

    Args:
        result: Resultado del análisis de la APK.
        output_dir: Directorio donde guardar el script .js.

    Returns:
        Ruta al script .js generado.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"bypass_{result.package}_{today}.js"
    output_path = output_dir / filename

    # Recopilar bloques necesarios (sin duplicados, manteniendo orden)
    seen: set[str] = set()
    blocks: list[str] = []

    def add_block(block: str) -> None:
        key = block[:80]  # usar inicio del bloque como clave de deduplicación
        if key not in seen:
            seen.add(key)
            blocks.append(block)

    # Siempre incluir hooks base
    for block in _BASE_HOOKS:
        add_block(block)

    # Añadir hooks específicos por detector activo
    for detection in result.results:
        if not detection.detected:
            continue
        # Buscar por nombre exacto del detector
        for detector_key, hook_list in _DETECTOR_HOOKS.items():
            if detector_key.lower() in detection.name.lower():
                for hook in hook_list:
                    add_block(hook)
        # Buscar por evidencias específicas (ej: "RootBeer" en detalles)
        for detail in detection.details:
            if "rootbeer" in detail.lower():
                add_block(_HOOK_ROOTBEER)
            if "rootcloak" in detail.lower():
                add_block(_HOOK_ROOTCLOAK)

    # Construir script completo (sin .format() para no interferir con {} del JS)
    header = (
        _HEADER
        .replace("{package}", result.package)
        .replace("{date}", datetime.datetime.now().isoformat(timespec="seconds"))
        .replace("{filename}", filename)
    )
    script_content = header + "\n".join(blocks) + _FOOTER

    output_path.write_text(script_content, encoding="utf-8")
    return output_path


def frida_run_instructions(package: str, script_path: Path) -> str:
    """Devuelve instrucciones de uso del script Frida."""
    return (
        f"\n[bold]Instrucciones para ejecutar el bypass:[/bold]\n\n"
        f"1. Instala frida-tools en el PC:\n"
        f"   [cyan]pip install frida-tools[/cyan]\n\n"
        f"2. Descarga frida-server para tu dispositivo/emulador:\n"
        f"   [cyan]https://github.com/frida/frida/releases[/cyan]\n"
        f"   (elige la versión arm64 para el emulador Pixel)\n\n"
        f"3. Sube y arranca frida-server en el dispositivo:\n"
        f"   [cyan]adb push frida-server /data/local/tmp/[/cyan]\n"
        f"   [cyan]adb shell 'chmod 755 /data/local/tmp/frida-server'[/cyan]\n"
        f"   [cyan]adb shell '/data/local/tmp/frida-server &'[/cyan]\n\n"
        f"4. Ejecuta el bypass:\n"
        f"   [cyan]frida -U -f {package} -l {script_path}[/cyan]\n"
    )


# ── FART — script de volcado de DEX para DexGuard/Arxan ──────────────────────

_FART_SCRIPT = """\
/**
 * FART — Frida Android Runtime DEX Dumper
 * Package : {package}
 * Generado: {date}
 *
 * Qué hace:
 *  1. Memory scan: escanea la memoria del proceso buscando DEX ya cargados
 *  2. Hooks: intercepta DexFile, InMemoryDexClassLoader, BaseDexClassLoader
 *     para capturar DEX cargados dinámicamente
 *  3. Hookea métodos de descifrado de strings (heurístico para DexGuard):
 *     registra cada string descifrada y guarda el mapa en decrypt_map.txt
 *
 * Volcado en: <app_data>/files/frida_dump/
 *
 * Uso:
 *   frida -U -f {package} -l {filename}
 *
 * Pull:
 *   adb pull /data/user/0/{package}/files/frida_dump/ ./dumps/
 *   jadx --deobf -d ./source/ ./dumps/*.dex
 *
 * Requisitos:
 *   - frida-server corriendo en el dispositivo (misma versión que frida-tools)
 */

'use strict';

var DUMP_DIR = null; // se resuelve dinámicamente al dir de datos de la app
var MAX_DEX_BYTES = 100 * 1024 * 1024; // ignorar DEX > 100 MB
var _dumpIdx = 0;
var _decryptLog = [];
var _seenDex = {};

Java.perform(function () {
    console.log('[FART] Iniciando DEX dumper para {package}');

    // ── Resolver directorio de volcado dinámicamente ────────────────────────
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var ctx = ActivityThread.currentApplication().getApplicationContext();
        DUMP_DIR = ctx.getFilesDir().getAbsolutePath() + '/frida_dump/';
    } catch (e) {
        DUMP_DIR = '/data/user/0/{package}/files/frida_dump/';
    }

    // ── Crear directorio de volcado ─────────────────────────────────────────
    try {
        var File = Java.use('java.io.File');
        var dir = File.$new(DUMP_DIR);
        if (!dir.exists()) { dir.mkdirs(); }
        console.log('[FART] Directorio de volcado: ' + DUMP_DIR);
    } catch (e) { console.error('[FART] Error al crear directorio: ' + e); }

    // ── Helpers de I/O ──────────────────────────────────────────────────────

    /** Escribe un array de bytes Java a un archivo en /sdcard/ */
    function writeDex(javaBytes, name) {
        try {
            var outPath = DUMP_DIR + name;
            var fos = Java.use('java.io.FileOutputStream').$new(outPath);
            fos.write(javaBytes);
            fos.flush();
            fos.close();
            console.log('[FART] ✔ Volcado: ' + outPath +
                        ' (' + javaBytes.length + ' bytes)');
        } catch (e) { console.error('[FART] writeDex error: ' + e); }
    }

    /** Lee un archivo del dispositivo y lo vuelca si es DEX válido */
    function dumpFromPath(srcPath) {
        try {
            var File = Java.use('java.io.File');
            var f = File.$new(srcPath);
            if (!f.exists() || !f.canRead()) { return; }
            var len = Number(f.length());
            if (len < 8 || len > MAX_DEX_BYTES) { return; }

            var fis = Java.use('java.io.FileInputStream').$new(f);
            var data = Java.array('byte', new Array(len).fill(0));
            var read = fis.read(data);
            fis.close();

            if (read >= 8 && _isDexMagic(data)) {
                var base = f.getName().replace(/[^a-zA-Z0-9._-]/g, '_');
                writeDex(data, 'path_' + (++_dumpIdx) + '_' + base);
            }
        } catch (e) { console.error('[FART] dumpFromPath error: ' + e); }
    }

    /** Vuelca un ByteBuffer (InMemoryDexClassLoader) */
    function dumpByteBuffer(buf) {
        try {
            var saved_pos = buf.position();
            var saved_lim = buf.limit();
            buf.rewind();
            var sz = buf.limit();
            if (sz < 8 || sz > MAX_DEX_BYTES) { return; }

            var arr = Java.array('byte', new Array(sz).fill(0));
            buf.get(arr);
            buf.position(saved_pos);
            buf.limit(saved_lim);

            if (_isDexMagic(arr)) {
                writeDex(arr, 'inmem_' + (++_dumpIdx) + '.dex');
            }
        } catch (e) { console.error('[FART] dumpByteBuffer error: ' + e); }
    }

    /** Comprueba el magic header de un archivo DEX: 64 65 78 0a ("dex\\n") */
    function _isDexMagic(data) {
        return data[0] === 100 && data[1] === 101 &&
               data[2] === 120 && data[3] === 10;
    }

    // ── Hook 1: DexFile (adaptado a APIs modernas) ────────────────────────
    try {
        var DexFile = Java.use('dalvik.system.DexFile');
        var _dexOverloads = [
            ['java.lang.String'],
            ['java.io.File'],
            ['java.lang.String', 'java.lang.String', 'int'],
            ['java.lang.String', 'java.lang.String', 'int',
             'java.lang.ClassLoader', '[Ldalvik.system.DexPathList$Element;'],
            ['java.lang.String', 'java.lang.ClassLoader',
             '[Ldalvik.system.DexPathList$Element;'],
            ['java.io.File', 'java.lang.ClassLoader',
             '[Ldalvik.system.DexPathList$Element;'],
        ];
        var _dexHooked = 0;
        _dexOverloads.forEach(function (sig) {
            try {
                DexFile.$init.overload.apply(DexFile.$init, sig).implementation =
                    function () {
                        var src = arguments[0];
                        var p = (typeof src === 'string') ? src : String(src);
                        console.log('[FART] DexFile(' + sig[0].split('.').pop() + '): ' + p);
                        dumpFromPath(p);
                        return this.$init.apply(this, arguments);
                    };
                _dexHooked++;
            } catch (e) { /* overload no existe en este runtime */ }
        });
        console.log('[FART] ✔ DexFile hooked (' + _dexHooked + ' overloads)');
    } catch (e) { console.log('[FART] DexFile hook: ' + e); }

    // ── Hook 2: InMemoryDexClassLoader (Android 8+, usado por DexGuard) ────
    try {
        var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
        // Overload con un solo ByteBuffer
        try {
            IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation =
                function (buf, parent) {
                    console.log('[FART] InMemoryDexClassLoader(ByteBuffer) interceptado');
                    dumpByteBuffer(buf);
                    return this.$init(buf, parent);
                };
        } catch (e) {}
        // Overload con array de ByteBuffer (Android 10+)
        try {
            IMDCL.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader').implementation =
                function (bufs, parent) {
                    console.log('[FART] InMemoryDexClassLoader(ByteBuffer[]) interceptado');
                    for (var i = 0; i < bufs.length; i++) {
                        if (bufs[i] !== null) { dumpByteBuffer(bufs[i]); }
                    }
                    return this.$init(bufs, parent);
                };
        } catch (e) {}
        console.log('[FART] ✔ InMemoryDexClassLoader hooked');
    } catch (e) { console.log('[FART] InMemoryDexClassLoader: ' + e); }

    // ── Hook 3: BaseDexClassLoader (lista de paths separados por :) ─────────
    try {
        var BDCL = Java.use('dalvik.system.BaseDexClassLoader');
        // Intentar ambos overloads comunes
        var _bdclSigs = [
            ['java.lang.String', 'java.io.File',
             'java.lang.String', 'java.lang.ClassLoader'],
            ['java.lang.String', 'java.lang.String',
             'java.lang.ClassLoader', '[Ldalvik.system.DexPathList$Element;'],
        ];
        _bdclSigs.forEach(function (sig) {
            try {
                BDCL.$init.overload.apply(BDCL.$init, sig).implementation =
                    function () {
                        var dexPath = arguments[0];
                        String(dexPath).split(':').forEach(function (p) {
                            if (p.length > 0) {
                                console.log('[FART] BaseDexClassLoader path: ' + p);
                                dumpFromPath(p);
                            }
                        });
                        return this.$init.apply(this, arguments);
                    };
            } catch (e) {}
        });
        console.log('[FART] ✔ BaseDexClassLoader hooked');
    } catch (e) { console.log('[FART] BaseDexClassLoader: ' + e); }

    // ── Scan 0: Memory scan de DEX ya cargados ─────────────────────────────
    // Escanea la memoria del proceso buscando headers DEX que ya fueron
    // desempaquetados antes de que los hooks estuvieran listos.
    function _scanMemoryForDex() {
        console.log('[FART] Iniciando memory scan de DEX...');
        var found = 0;

        var ranges = Process.enumerateRanges('r--');
        ranges.forEach(function (range) {
            if (range.size < 112) { return; }
            try {
                var matches = Memory.scanSync(range.base, range.size, '64 65 78 0a');
                matches.forEach(function (match) {
                    try {
                        var addr = match.address;
                        var fileSz = addr.add(32).readU32();
                        if (fileSz < 112 || fileSz > MAX_DEX_BYTES) { return; }
                        var offset = addr.sub(range.base).toInt32();
                        if (offset + fileSz > range.size) { return; }

                        var chk = addr.add(8).readU32();
                        var key = chk + '_' + fileSz;
                        if (_seenDex[key]) { return; }
                        _seenDex[key] = true;

                        var name = 'memscan_' + (++_dumpIdx) + '.dex';
                        var outPath = DUMP_DIR + name;
                        var fos = Java.use('java.io.FileOutputStream').$new(outPath);
                        var data = addr.readByteArray(fileSz);
                        fos.write(Java.array('byte', new Uint8Array(data)));
                        fos.flush();
                        fos.close();
                        console.log('[FART] ✔ MemScan: ' + name + ' (' + fileSz + ' bytes)');
                        found++;
                    } catch (e) { /* skip unreadable match */ }
                });
            } catch (e) { /* skip unreadable range */ }
        });

        console.log('[FART] Memory scan completo: ' + found + ' DEX encontrados');
    }
    // Ejecutar memory scan tras 5s para que la app ya haya cargado sus DEX
    setTimeout(_scanMemoryForDex, 5000);

    // ── Hook 4: String decryptors de DexGuard (heurístico) ─────────────────
    // DexGuard inyecta métodos estáticos en clases con nombre de 1-3 chars
    // que reciben int/byte[] y devuelven String. Los interceptamos para
    // capturar el mapa de cifrado y guardarlo en decrypt_map.txt.

    function _saveDecryptMap() {
        if (_decryptLog.length === 0) { return; }
        try {
            var mapPath = DUMP_DIR + 'decrypt_map.txt';
            var fos2 = Java.use('java.io.FileOutputStream').$new(mapPath, false);
            var ps = Java.use('java.io.PrintStream').$new(fos2);
            _decryptLog.forEach(function (l) { ps.println(l); });
            ps.flush(); ps.close();
            console.log('[FART] ✔ decrypt_map.txt guardado (' +
                        _decryptLog.length + ' entradas)');
        } catch (e) { console.error('[FART] saveDecryptMap error: ' + e); }
    }

    function _hookStringDecryptors() {
        var Modifier = Java.use('java.lang.reflect.Modifier');
        var hooked = 0;
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                var simple = className.split('.').pop();
                if (simple.length > 3) { return; }
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    methods.forEach(function (m) {
                        try {
                            if (!Modifier.isStatic(m.getModifiers())) { return; }
                            if (m.getReturnType().getName() !== 'java.lang.String') { return; }
                            var params = m.getParameterTypes();
                            if (params.length < 1 || params.length > 2) { return; }
                            var mName = m.getName();
                            cls[mName].implementation = function () {
                                var res = this[mName].apply(this, arguments);
                                if (res !== null && res.length > 0) {
                                    var args = Array.prototype.slice.call(arguments).join(',');
                                    _decryptLog.push(
                                        className + '.' + mName +
                                        '(' + args + ')="' + res + '"'
                                    );
                                }
                                return res;
                            };
                            hooked++;
                        } catch (e2) { /* método no hookeable */ }
                    });
                } catch (e) { /* clase no accesible */ }
            },
            onComplete: function () {
                console.log('[FART] String decryptors hooked: ' + hooked);
                // Guardar mapa luego de que la app haya ejecutado sus <clinit>
                setTimeout(_saveDecryptMap, 8000);
            },
        });
    }

    // Esperar 2 s para que la app cargue sus clases DexGuard antes de enumerar
    setTimeout(_hookStringDecryptors, 2000);

    console.log('[FART] Todos los hooks instalados. Deja que la app arranque completamente.');
    console.log('[FART] Los DEX se volcarán en: ' + DUMP_DIR);
    console.log('[FART] Luego, en el PC, ejecuta:');
    console.log('[FART]   adb pull /data/user/0/{package}/files/frida_dump/ ./dumps/');
    console.log('[FART]   jadx --deobf -d ./source_clean/ ./dumps/*.dex');
});
"""


def generate_fart_script(package: str, output_dir: Path) -> Path:
    """
    Genera un script Frida FART para volcar DEX descifrados en runtime.

    Diseñado para apps protegidas con DexGuard/Arxan.

    Args:
        package: Package ID de la app (ej: com.example.app).
        output_dir: Directorio donde guardar el script .js.

    Returns:
        Ruta al script generado.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"fart_{package}_{today}.js"
    output_path = output_dir / filename

    content = (
        _FART_SCRIPT
        .replace("{package}", package)
        .replace("{date}", datetime.datetime.now().isoformat(timespec="seconds"))
        .replace("{filename}", filename)
    )
    output_path.write_text(content, encoding="utf-8")
    return output_path


def fart_run_instructions(package: str, script_path: Path) -> str:
    """Devuelve instrucciones paso a paso para ejecutar el script FART."""
    dump_dir = f"/data/user/0/{package}/files/frida_dump/"
    return (
        f"\n[bold]Instrucciones FART — Desofuscación DexGuard:[/bold]\n\n"
        f"1. Arranca frida-server en el dispositivo:\n"
        f"   [cyan]adb shell '/data/local/tmp/frida-server &'[/cyan]\n\n"
        f"2. Lanza la app con el script FART:\n"
        f"   [cyan]frida -U -f {package} -l {script_path}[/cyan]\n\n"
        f"3. Navega por la app para forzar la carga de todas las clases.\n\n"
        f"4. El script vuelca los DEX descifrados a:\n"
        f"   [dim]{dump_dir}[/dim]\n\n"
        f"5. Pulsa Enter aquí cuando la app haya cargado por completo.\n"
        f"   (O ejecuta manualmente: [cyan]adb pull {dump_dir} ./dumps/[/cyan])\n"
    )
