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
    var BLOCKED_CMDS = ['su', 'which su', 'id', 'busybox'];
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

_HOOK_GOOGLE_PLAY = """\
  // ── Bypass: Google Play Store / GMS no instalado en emulador AOSP ────────
  (function() {
    var GMS_PACKAGES = ['com.android.vending', 'com.google.android.gms',
                        'com.google.android.gsf', 'com.google.android.gsf.login'];

    function _makeAppInfo(name) {
      var ai = Java.use('android.content.pm.ApplicationInfo').$new();
      ai.packageName.value = name;
      ai.enabled.value = true;
      ai.flags.value = 0x00000001;
      return ai;
    }

    function _makePackageInfo(name) {
      var pi = Java.use('android.content.pm.PackageInfo').$new();
      pi.packageName.value = name;
      pi.versionName.value = '24.10.0';
      try { pi.versionCode.value = 241000000; } catch(e) {}
      try { pi.applicationInfo.value = _makeAppInfo(name); } catch(e) {}
      return pi;
    }

    try {
      var PackageManager = Java.use('android.app.ApplicationPackageManager');

      PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(name, flags) {
        for (var i = 0; i < GMS_PACKAGES.length; i++) {
          if (name === GMS_PACKAGES[i]) {
            console.log('[Bypass] getPackageInfo fake OK para: ' + name);
            return _makePackageInfo(name);
          }
        }
        return this.getPackageInfo(name, flags);
      };

      PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(name, flags) {
        for (var i = 0; i < GMS_PACKAGES.length; i++) {
          if (name === GMS_PACKAGES[i]) {
            console.log('[Bypass] getApplicationInfo fake OK para: ' + name);
            return _makeAppInfo(name);
          }
        }
        return this.getApplicationInfo(name, flags);
      };

      PackageManager.getApplicationEnabledSetting.implementation = function(name) {
        if (GMS_PACKAGES.indexOf(name) !== -1) {
          console.log('[Bypass] getApplicationEnabledSetting → ENABLED para: ' + name);
          return 1;
        }
        return this.getApplicationEnabledSetting(name);
      };

      console.log('[Bypass] ✔ Google Play Store / GMS hooked (AOSP emulator)');
    } catch(e) { console.log('[Bypass] Google Play hook error: ' + e); }

    // GoogleApiAvailability → SUCCESS (todos los overloads + métodos de error)
    try {
      var GmsAvail = Java.use('com.google.android.gms.common.GoogleApiAvailability');
      GmsAvail.isGooglePlayServicesAvailable.overloads.forEach(function(ov) {
        ov.implementation = function() {
          console.log('[Bypass] GoogleApiAvailability.isGooglePlayServicesAvailable → 0');
          return 0;
        };
      });
      try {
        GmsAvail.makeGooglePlayServicesAvailable.overloads.forEach(function(ov) {
          ov.implementation = function() {
            console.log('[Bypass] makeGooglePlayServicesAvailable → no-op');
          };
        });
      } catch(e) {}
      // showErrorDialogFragment → false (no mostrar diálogo de error GMS)
      try {
        GmsAvail.showErrorDialogFragment.overloads.forEach(function(ov) {
          ov.implementation = function() {
            console.log('[Bypass] showErrorDialogFragment → false (bloqueado)');
            return false;
          };
        });
      } catch(e) {}
      // showErrorDialog → null
      try {
        GmsAvail.showErrorDialog.overloads.forEach(function(ov) {
          ov.implementation = function() {
            console.log('[Bypass] showErrorDialog → null (bloqueado)');
            return null;
          };
        });
      } catch(e) {}
      console.log('[Bypass] ✔ GoogleApiAvailability hooked');
    } catch(e) { console.log('[Bypass] GoogleApiAvailability no disponible (AOSP): ' + e); }

    // GoogleApiAvailabilityLight → SUCCESS (la usada directamente por Firebase/GMS internals)
    try {
      var GmsAvailLight = Java.use('com.google.android.gms.common.GoogleApiAvailabilityLight');
      GmsAvailLight.isGooglePlayServicesAvailable.overloads.forEach(function(ov) {
        ov.implementation = function() {
          console.log('[Bypass] GoogleApiAvailabilityLight.isGooglePlayServicesAvailable → 0');
          return 0;
        };
      });
      try {
        GmsAvailLight.getApkVersion.overloads.forEach(function(ov) {
          ov.implementation = function() {
            console.log('[Bypass] GoogleApiAvailabilityLight.getApkVersion → 241000000');
            return 241000000;
          };
        });
      } catch(e) {}
      console.log('[Bypass] ✔ GoogleApiAvailabilityLight hooked');
    } catch(e) { console.log('[Bypass] GoogleApiAvailabilityLight hook error: ' + e); }

    // DeferredLifecycleHelper.showGooglePlayUnavailableMessage → no-op
    // (muestra el mensaje "Enable Google Play services" en FrameLayouts de Maps/GMS)
    try {
      var DeferredHelper = Java.use('com.google.android.gms.dynamic.DeferredLifecycleHelper');
      DeferredHelper.showGooglePlayUnavailableMessage.implementation = function() {
        console.log('[Bypass] DeferredLifecycleHelper.showGooglePlayUnavailableMessage → bloqueado');
      };
      console.log('[Bypass] ✔ DeferredLifecycleHelper hooked');
    } catch(e) { console.log('[Bypass] DeferredLifecycleHelper hook error: ' + e); }

    // GooglePlayServicesUtilLight → SUCCESS (usado por AdvertisingIdClient, DynamiteModule, etc.)
    try {
      var UtilLight = Java.use('com.google.android.gms.common.GooglePlayServicesUtilLight');
      UtilLight.isGooglePlayServicesAvailable.overloads.forEach(function(ov) {
        ov.implementation = function() {
          console.log('[Bypass] GooglePlayServicesUtilLight.isGooglePlayServicesAvailable → 0');
          return 0;
        };
      });
      try {
        UtilLight.getApkVersion.overloads.forEach(function(ov) {
          ov.implementation = function() { return 241000000; };
        });
      } catch(e) {}
      console.log('[Bypass] ✔ GooglePlayServicesUtilLight hooked');
    } catch(e) { console.log('[Bypass] GooglePlayServicesUtilLight hook error: ' + e); }
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

_HOOK_EMULATOR_DETECTION = """\
  // ── Bypass: detecciones de emulador y Google Play ─────────────────────────
  // Cubre checks que la app hace para saber si corre en Play Store real.
  (function() {
    // 1. getInstallerPackageName → finge que la app se instaló desde Play Store
    try {
      var ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
      ApplicationPackageManager.getInstallerPackageName.implementation = function(pkg) {
        console.log('[Bypass] getInstallerPackageName → com.android.vending');
        return 'com.android.vending';
      };
      console.log('[Bypass] ✔ getInstallerPackageName hooked');
    } catch(e) { console.log('[Bypass] getInstallerPackageName hook error: ' + e); }

    // 2. GoogleApiAvailability → cubierto por _HOOK_GOOGLE_PLAY (AOSP-safe)

    // 3. Play Integrity API (nueva, reemplaza SafetyNet desde 2023)
    try {
      var IntegrityManagerFactory = Java.use('com.google.android.play.core.integrity.IntegrityManagerFactory');
      IntegrityManagerFactory.create.implementation = function() {
        console.log('[Bypass] Play Integrity IntegrityManagerFactory interceptado');
        return null;
      };
    } catch(e) {}
    try {
      // Hook en la clase de resultado para apps que validan localmente
      var StandardIntegrityToken = Java.use('com.google.android.play.core.integrity.StandardIntegrityToken');
      StandardIntegrityToken.token.implementation = function() {
        console.log('[Bypass] Play Integrity token interceptado');
        return 'nutcracker_fake_token';
      };
    } catch(e) {}

    // 4. Build.FINGERPRINT / Build.MODEL — checks de emulador directos
    try {
      var Build = Java.use('android.os.Build');
      Build.FINGERPRINT.value = 'google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys';
      Build.MODEL.value = 'Pixel 2';
      Build.MANUFACTURER.value = 'Google';
      Build.BRAND.value = 'google';
      Build.PRODUCT.value = 'walleye';
      Build.HARDWARE.value = 'walleye';
      Build.DEVICE.value = 'walleye';
      Build.TAGS.value = 'release-keys';
      Build.TYPE.value = 'user';
      Build.HOST.value = 'android-build';
      console.log('[Bypass] ✔ Build fields spoofed');
    } catch(e) { console.log('[Bypass] Build spoof error: ' + e); }

    // 5. TelephonyManager — oculta device IDs y IMSIs típicos de emulador
    // FindEmulator.hasKnownDeviceId usa getDeviceId(); el emulador devuelve
    // "000000000000000" que está en la lista negra de muchas apps.
    try {
      var TelephonyManager = Java.use('android.telephony.TelephonyManager');
      // getDeviceId (API <26): emulador devuelve "000000000000000"
      try {
        TelephonyManager.getDeviceId.overloads.forEach(function(ov) {
          ov.implementation = function() {
            console.log('[Bypass] TelephonyManager.getDeviceId → IMEI spoofed');
            return '867686021328410';
          };
        });
      } catch(e) {}
      // getImei (API 26+)
      try {
        TelephonyManager.getImei.overloads.forEach(function(ov) {
          ov.implementation = function() {
            console.log('[Bypass] TelephonyManager.getImei → IMEI spoofed');
            return '867686021328410';
          };
        });
      } catch(e) {}
      // getSubscriberId: emulador devuelve "310260000000000" (en lista negra)
      try {
        TelephonyManager.getSubscriberId.implementation = function() {
          console.log('[Bypass] TelephonyManager.getSubscriberId → IMSI spoofed');
          return '310260123456789';
        };
      } catch(e) {}
      // getLine1Number: emulador devuelve números de la lista negra
      try {
        TelephonyManager.getLine1Number.implementation = function() {
          console.log('[Bypass] TelephonyManager.getLine1Number → spoofed');
          return '+15550001234';
        };
      } catch(e) {}
      console.log('[Bypass] ✔ TelephonyManager hooked (device ID/IMSI spoofed)');
    } catch(e) { console.log('[Bypass] TelephonyManager hook error: ' + e); }
  })();
"""

_HOOK_ROOT_UTILS = """\
  // ── Bypass: Utilidades anti-root/emulador propias de la app ──────────────
  // Usa ClassLoader.loadClass para hookear clases de detección en el momento
  // exacto en que la app las carga (deferred). El scan síncrono en spawn mode
  // no encuentra clases de la app porque aún no están cargadas en el JVM.
  (function() {
    var BOOL_FALSE_METHODS = [
      'isDeviceRooted', 'isRooted', 'checkRoot', 'isRootAvailable', 'isRootGiven',
      'checkRootMethod1', 'checkRootMethod2',
      'isQEmuEnvDetected', 'isEmulator', 'isEmulatorDetected', 'isVirtualDevice',
      'hasEmulatorBuild', 'hasKnownDeviceId', 'hasKnownImsi', 'hasKnownPhoneNumber',
      'hasPipes', 'hasGenyFiles', 'isTaintTrackingDetected', 'isMonkeyDetected',
      'isDeviceCompromised', 'isJailbroken',
    ];
    var DETECTION_CLASS_KEYWORDS = [
      'rootutil', 'rootutils', 'rootchecker', 'rootdetect',
      'officialdevice', 'findemulator', 'emulatordetect', 'antirobot',
      'antiemulator', 'findtaint', 'findmonkey',
      'securityutil', 'devicevalidat', 'devicecheck',
    ];

    function _nameMatches(name) {
      var low = name.toLowerCase();
      // Skip framework classes early for performance
      if (low.indexOf('java.') === 0 || low.indexOf('android.') === 0 ||
          low.indexOf('com.google.') === 0 || low.indexOf('kotlin.') === 0 ||
          low.indexOf('androidx.') === 0) return false;
      for (var i = 0; i < DETECTION_CLASS_KEYWORDS.length; i++) {
        if (low.indexOf(DETECTION_CLASS_KEYWORDS[i]) !== -1) return true;
      }
      return false;
    }

    function _hookBoolFalse(jcls, className) {
      BOOL_FALSE_METHODS.forEach(function(m) {
        try {
          if (jcls[m]) {
            jcls[m].overloads.forEach(function(ov) {
              try {
                if (ov.returnType && ov.returnType.name === 'boolean') {
                  ov.implementation = function() {
                    console.log('[Bypass] ' + className + '.' + m + ' → false');
                    return false;
                  };
                }
              } catch(e2) {}
            });
          }
        } catch(e) {}
      });
    }

    var _hooked = {};

    // Deferred hook via ClassLoader.loadClass — funciona en spawn mode
    // porque intercepta clases cuando se cargan por primera vez.
    try {
      var ClassLoader = Java.use('java.lang.ClassLoader');
      ClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
        var clazz = this.loadClass(name);
        if (!_hooked[name] && _nameMatches(name)) {
          _hooked[name] = true;
          try {
            _hookBoolFalse(Java.use(name), name);
            console.log('[Bypass] ✔ Detection class hooked (deferred): ' + name);
          } catch(e) {}
        }
        // PairIP LicenseClient: silencia handleError para que no lance LicenseActivity
        if (name === 'com.pairip.licensecheck.LicenseClient') {
          try {
            var LC = Java.use('com.pairip.licensecheck.LicenseClient');
            LC.handleError.implementation = function(ex) {
              console.log('[Bypass] PairIP LicenseClient.handleError → bypassed');
            };
            LC.connectToLicensingService.implementation = function() {
              console.log('[Bypass] PairIP LicenseClient.connectToLicensingService → skipped');
            };
            console.log('[Bypass] ✔ PairIP LicenseClient hooked (deferred)');
          } catch(e) {}
        }
        return clazz;
      };
      console.log('[Bypass] ✔ ClassLoader hook activo para clases de detección');
    } catch(e) { console.log('[Bypass] ClassLoader hook error: ' + e); }

    // Fallback: scan clases ya cargadas (para casos de attach-mode)
    try {
      Java.enumerateLoadedClassesSync().forEach(function(name) {
        if (!_hooked[name] && _nameMatches(name)) {
          _hooked[name] = true;
          try {
            _hookBoolFalse(Java.use(name), name);
            console.log('[Bypass] ✔ Detection class hooked (sync): ' + name);
          } catch(e) {}
        }
      });
    } catch(e) {}
  })();
"""

_HOOK_RESTRICTION_ACTIVITY = """\
  // ── Bypass: Activity blocker (showBlockingRestrictionActivity, etc.) ──────
  // Hookea métodos de bloqueo por root al crear cada Activity (deferred),
  // porque las clases de la app no están cargadas en el momento del spawn.
  (function() {
    var BLOCK_METHODS = [
      'showBlockingRestrictionActivity', 'showRootedDeviceActivity',
      'showRootDetectedActivity', 'blockRootedDevice', 'showDeviceNotCompatible',
      'showSecurityBlockActivity', 'onRootDetected', 'onDeviceCompromised',
      'showDeviceRootedScreen', 'showRootedDialog',
      // Google Play / GMS blocking
      'showGooglePlayNotAvailableActivity', 'showGooglePlayRequiredActivity',
      'showGooglePlayNotEnabledActivity', 'showGooglePlayDisabledActivity',
      'showPlayStoreRequiredActivity', 'showPlayStoreNotAvailableActivity',
      'showGmsNotAvailableActivity', 'showGooglePlayServicesDialog',
      'showGooglePlayServicesError', 'blockGooglePlayNotAvailable',
      'showPlayServicesErrorActivity', 'showPlayServicesNotEnabled',
    ];
    var _patched = {};

    function _patchHierarchy(cls) {
      try {
        var name = cls.getName();
        if (_patched[name] || name.indexOf('android.') === 0 || name.indexOf('java.') === 0) return;
        _patched[name] = true;
        var jcls = Java.use(name);

        // ── One-time: hookear clases de detección específicas de la app ─────────
        // Corre antes de Activity.onCreate (desde callActivityOnCreate), así que
        // SplashPresenter.onCreate ya verá los valores falseados.
        if (!_patched['__app_detection_init']) {
          _patched['__app_detection_init'] = true;
          // OfficialDevice
          try {
            var OD = Java.use('com.mibanco.adcurpi.util.officialdevice.OfficialDevice');
            OD.isQEmuEnvDetected.implementation = function() {
              console.log('[Bypass] OfficialDevice.isQEmuEnvDetected → false');
              return false;
            };
            OD.isMonkeyDetected.implementation = function() { return false; };
            OD.isTaintTrackingDetected.implementation = function() { return false; };
            console.log('[Bypass] ✔ OfficialDevice hooked');
          } catch(e) {}
          // FindEmulator
          try {
            var FE = Java.use('com.mibanco.adcurpi.util.officialdevice.FindEmulator');
            FE.hasPipes.implementation = function() { return false; };
            FE.hasGenyFiles.implementation = function() { return false; };
            FE.hasEmulatorBuild.implementation = function() { return false; };
            FE.hasKnownDeviceId.implementation = function() {
              console.log('[Bypass] FindEmulator.hasKnownDeviceId → false');
              return false;
            };
            FE.hasKnownImsi.implementation = function() { return false; };
            FE.hasKnownPhoneNumber.implementation = function() { return false; };
            console.log('[Bypass] ✔ FindEmulator hooked');
          } catch(e) {}
          // RootUtil
          try {
            var RU = Java.use('com.mibanco.adcurpi.util.RootUtil');
            RU.isDeviceRooted.implementation = function() {
              console.log('[Bypass] RootUtil.isDeviceRooted → false');
              return false;
            };
            console.log('[Bypass] ✔ RootUtil hooked');
          } catch(e) {}
        }

        BLOCK_METHODS.forEach(function(m) {
          try {
            if (jcls[m]) {
              jcls[m].overloads.forEach(function(ov) {
                ov.implementation = function() {
                  console.log('[Bypass] ' + name + '.' + m + ' → bloqueado');
                };
              });
            }
          } catch(e) {}
        });

        // 2. Dynamic scan: hook void methods whose name suggests security/play blocking
        try {
          var declaredMethods = cls.getDeclaredMethods();
          for (var j = 0; j < declaredMethods.length; j++) {
            var method = declaredMethods[j];
            var mName = method.getName();
            var mNameLower = mName.toLowerCase();
            if (method.getReturnType().getName() === 'void' &&
                (mNameLower.indexOf('google') !== -1 || mNameLower.indexOf('play') !== -1 ||
                 mNameLower.indexOf('restriction') !== -1 || mNameLower.indexOf('security') !== -1) &&
                (mNameLower.indexOf('show') !== -1 || mNameLower.indexOf('block') !== -1 ||
                 mNameLower.indexOf('required') !== -1 || mNameLower.indexOf('enabled') !== -1 ||
                 mNameLower.indexOf('check') !== -1)) {
              (function(capturedName) {
                try {
                  if (jcls[capturedName]) {
                    jcls[capturedName].overloads.forEach(function(ov) {
                      ov.implementation = function() {
                        console.log('[Bypass] Dynamic: ' + name + '.' + capturedName + ' → bloqueado');
                      };
                    });
                  }
                } catch(e) {}
              })(mName);
            }
          }
        } catch(e) {}

        // PairIP: LicenseActivity muestra error y llama closeApp → System.exit(0)
        // Debemos llamar super.onStart() para evitar SuperNotCalledException, luego finish().
        if (name === 'com.pairip.licensecheck.LicenseActivity') {
          try {
            var ActivityBase = Java.use('android.app.Activity');
            jcls.onStart.implementation = function() {
              // Android exige que super.onStart() sea llamado
              try { ActivityBase.onStart.call(this); } catch(e) {}
              console.log('[Bypass] PairIP LicenseActivity.onStart → finishing (bypassed)');
              try { this.finish(); } catch(e) {}
            };
          } catch(e) {}
          try {
            jcls.closeApp.implementation = function() {
              console.log('[Bypass] PairIP LicenseActivity.closeApp → no-op (prevented System.exit)');
              try { this.finish(); } catch(e) {}
            };
          } catch(e) {}
          // LicenseClient ya está cargado cuando LicenseActivity se crea → hookearlo aquí
          try {
            var LC = Java.use('com.pairip.licensecheck.LicenseClient');
            // handleError es no-op para que los reintentos fallidos no lancen más Activities
            LC.handleError.implementation = function(ex) {
              console.log('[Bypass] PairIP LicenseClient.handleError → bypassed');
            };
            // performLocalInstallerCheck → true: estado pasa a LOCAL_CHECK_OK
            LC.performLocalInstallerCheck.implementation = function() {
              console.log('[Bypass] PairIP LicenseClient.performLocalInstallerCheck → true');
              return true;
            };
            console.log('[Bypass] ✔ PairIP LicenseClient hooked (from LicenseActivity patch)');
          } catch(e) {}
          console.log('[Bypass] ✔ PairIP LicenseActivity hooked');
        }

        var sup = cls.getSuperclass();
        if (sup) _patchHierarchy(sup);
      } catch(e) {}
    }

    try {
      var Instr = Java.use('android.app.Instrumentation');
      Instr.callActivityOnCreate.overload(
        'android.app.Activity', 'android.os.Bundle'
      ).implementation = function(activity, bundle) {
        _patchHierarchy(activity.getClass());
        return this.callActivityOnCreate(activity, bundle);
      };
      console.log('[Bypass] ✔ Restriction activity blocker hooked (deferred)');
    } catch(e) { console.log('[Bypass] Restriction blocker error: ' + e); }
  })();
"""

_HOOK_PAIRIP = """\
  // ── Bypass: PairIP LicenseClient (early timer) ───────────────────────────
  // LicenseContentProvider inicializa LicenseClient ANTES de cualquier Activity.
  // Usamos setInterval para hookear LicenseClient en cuanto se cargue la clase,
  // antes de que connectToLicensingService se llame por primera vez.
  (function() {
    var _hooked = false;
    var _attempts = 0;
    var _timer = setInterval(function() {
      _attempts++;
      if (_hooked) { clearInterval(_timer); return; }
      if (_attempts > 60) { clearInterval(_timer); return; }  // timeout 3s
      try {
        Java.perform(function() {
          var LC = Java.use('com.pairip.licensecheck.LicenseClient');
          LC.handleError.implementation = function() {
            console.log('[Bypass] PairIP LicenseClient.handleError → no-op (early)');
          };
          LC.connectToLicensingService.implementation = function() {
            console.log('[Bypass] PairIP LicenseClient.connectToLicensingService → skipped (early)');
          };
          LC.performLocalInstallerCheck.implementation = function() {
            return true;
          };
          _hooked = true;
          clearInterval(_timer);
          console.log('[Bypass] ✔ PairIP LicenseClient hooked (early, attempt #' + _attempts + ')');
        });
      } catch(e) {}
    }, 50);
    console.log('[Bypass] ✔ PairIP early timer iniciado');
  })();
"""

_HOOK_FRIDA_DETECTION = """\
  // ── Bypass: Detección de Frida ────────────────────────────────────────────
  // Algunas apps detectan Frida leyendo /proc/self/maps o buscando "frida" en el proceso.
  (function() {
    try {
      // Interceptar lectura de /proc/maps para ocultar frida-agent
      var BufferedReader = Java.use('java.io.BufferedReader');
      var original_readLine = BufferedReader.readLine.overload();
      BufferedReader.readLine.overload().implementation = function() {
        var line = original_readLine.call(this);
        if (line !== null && (
          line.indexOf('frida') !== -1 ||
          line.indexOf('gum-js-loop') !== -1 ||
          line.indexOf('linjector') !== -1
        )) {
          console.log('[Bypass] /proc/maps línea Frida ocultada');
          return original_readLine.call(this); // saltar esta línea
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
    "SafetyNetDetector": [_HOOK_SAFETYNET, _HOOK_EMULATOR_DETECTION],
    "ManualChecksDetector": [_HOOK_FILE_EXISTS, _HOOK_RUNTIME_EXEC, _HOOK_BUILD_PROPS],
    "MagiskDetector": [_HOOK_PACKAGE_MANAGER, _HOOK_FILE_EXISTS],
}

# Hooks siempre incluidos (defensa en profundidad)
_BASE_HOOKS: list[str] = [
    _HOOK_FILE_EXISTS,
    _HOOK_RUNTIME_EXEC,
    _HOOK_PACKAGE_MANAGER,
    _HOOK_BUILD_PROPS,
    _HOOK_GOOGLE_PLAY,
    _HOOK_EMULATOR_DETECTION,
    _HOOK_ROOT_UTILS,
    _HOOK_RESTRICTION_ACTIVITY,
    _HOOK_PAIRIP,
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
    // Cascada de memory scans para capturar DEX que se descifran en distintos
    // momentos del arranque. Es fundamental que estos timers corran ANTES de
    // _hookStringDecryptors (que enumera todas las clases síncronamente y
    // bloquea el event loop varios segundos).
    setTimeout(_scanMemoryForDex,   500);
    setTimeout(_scanMemoryForDex,  3000);
    setTimeout(_scanMemoryForDex,  8000);
    setTimeout(_scanMemoryForDex, 15000);
    setTimeout(_scanMemoryForDex, 25000);
    setTimeout(_scanMemoryForDex, 35000);
    setInterval(_scanMemoryForDex, 12000);

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
        var seenClasses = 0;
        var MAX_CLASSES = 5000;  // tope para no congelar event loop con apps gigantes
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (seenClasses++ > MAX_CLASSES) { return; }
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

    // Lanzar enumerate-classes DESPUÉS de los memory scans iniciales para no
    // bloquear el event loop antes de que se descarguen los DEX descifrados.
    setTimeout(_hookStringDecryptors, 45000);

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
