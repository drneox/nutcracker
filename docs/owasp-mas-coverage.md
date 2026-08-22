# Cobertura OWASP MAS de nutcracker

Generado automáticamente por `tools/gen_owasp_coverage.py` desde `nutcracker_core/checks/` (Fase 2 del plan). No editar a mano — regenerar tras cambios en `masvs.py` o en los checks.

**Resumen:** 18/24 controles MASVS v2.1 con al menos un check · 68 checks totales (66 estáticos, 2 dinámicos) · 33/119 debilidades MASWE referenciadas.

## Cobertura por control MASVS

| Control | Descripción | Checks | MASWE |
|---|---|---|---|
| `MASVS-STORAGE-1` | La app almacena de forma segura los datos sensibles, sin importar la ubicación (privada o pública) | `ST001`, `ST002`, `ST003`, `ST004` | MASWE-0002, MASWE-0006, MASWE-0007 |
| `MASVS-STORAGE-2` | La app evita la fuga no intencional de datos sensibles (por ejemplo vía backups o logs) | `HC001`, `HC002`, `HC003`, `HC004`, `HC005`, `HC007`, `HC008`, `AUTH001`, `DBG002`, `DBG003`, `ST006`, `NAT004` | MASWE-0001, MASWE-0002, MASWE-0005, MASWE-0013 |
| `MASVS-CRYPTO-1` | La app usa criptografía fuerte y actual según las mejores prácticas de la industria | `HC006`, `CRYPTO001`, `CRYPTO002`, `CRYPTO003`, `CRYPTO004`, `CRYPTO005`, `CRYPTO006`, `NAT008` | MASWE-0013, MASWE-0020, MASWE-0021, MASWE-0022, MASWE-0027 |
| `MASVS-CRYPTO-2` | La app gestiona las claves criptográficas (generación, almacenamiento, rotación) según las mejores prácticas | `CRYPTO007` | MASWE-0010 |
| `MASVS-AUTH-1` | La app usa protocolos de autenticación y autorización seguros y sigue las mejores prácticas relevantes | — | — |
| `MASVS-AUTH-2` | La app realiza la autenticación local (biometría, PIN) de forma segura según las mejores prácticas de la plataforma | `AUTH002` | MASWE-0032 |
| `MASVS-AUTH-3` | La app protege las operaciones sensibles con autenticación adicional (step-up) | — | — |
| `MASVS-NETWORK-1` | La app protege todo el tráfico de red según las mejores prácticas actuales (TLS, validación de certificados) | `HC008`, `NET001`, `NET002`, `NET003`, `NET004`, `NET006`, `NAT005`, `NAT007`, `DYN-CLEARTEXT-TRAFFIC` | MASWE-0047, MASWE-0050, MASWE-0052 |
| `MASVS-NETWORK-2` | La app implementa identity pinning (certificate/public key pinning) para los endpoints bajo control del desarrollador | `NET005`, `NAT007`, `Certificate pinning` | MASWE-0047 |
| `MASVS-PLATFORM-1` | La app usa los mecanismos de IPC de forma segura (intents, deep links, componentes exportados) | `COMP004`, `INJ004`, `COMP006`, `COMP007`, `COMP008` | MASWE-0058, MASWE-0062, MASWE-0063, MASWE-0064, MASWE-0119 |
| `MASVS-PLATFORM-2` | La app usa WebViews de forma segura (sin JS innecesario, sin acceso a archivos, sin puentes JS expuestos) | `COMP001`, `COMP002`, `COMP003`, `COMP005`, `NET006` | MASWE-0052, MASWE-0068, MASWE-0069, MASWE-0072 |
| `MASVS-PLATFORM-3` | La app usa la interfaz de usuario de forma segura (evita fugas vía capturas de pantalla, clipboard, etc.) | `ST005` | MASWE-0053 |
| `MASVS-CODE-1` | La app requiere una versión de plataforma actualizada | `MANIFEST-LOW-TARGET-SDK` | MASWE-0078 |
| `MASVS-CODE-2` | La app tiene un mecanismo para forzar actualizaciones ante vulnerabilidades críticas | — | — |
| `MASVS-CODE-3` | La app solo usa componentes de software sin vulnerabilidades conocidas | — | — |
| `MASVS-CODE-4` | La app valida y sanitiza toda entrada no confiable (SQL, IPC, deserialización, comandos) | `INJ001`, `INJ002`, `INJ003`, `DESER001`, `NAT001`, `NAT002` | MASWE-0081, MASWE-0086, MASWE-0088 |
| `MASVS-RESILIENCE-1` | La app valida la integridad de la plataforma (detecta dispositivos rooteados/comprometidos) | `NAT006`, `Known anti-root libraries`, `SafetyNet / Play Integrity API`, `Manual root checks`, `Anti Magisk / SuperSU / KernelSU / Frida`, `AppDome` | — |
| `MASVS-RESILIENCE-2` | La app implementa mecanismos anti-tampering (verifica firma del paquete, integridad de DEX/código nativo/recursos) | `DBG001`, `DexGuardDetector`, `AppDome`, `APK signature verification` | MASWE-0095 |
| `MASVS-RESILIENCE-3` | La app implementa mecanismos anti-análisis-estático (ofuscación de código, recursos y strings) | `OBF001`, `DexGuardDetector`, `AppDome` | — |
| `MASVS-RESILIENCE-4` | La app implementa técnicas anti-análisis-dinámico (detección de debugger, Frida, hooking) | `INFO001`, `NAT003`, `Anti Magisk / SuperSU / KernelSU / Frida`, `DexGuardDetector`, `AppDome`, `DYN-DEBUGGABLE` | MASWE-0067, MASWE-0101 |
| `MASVS-PRIVACY-1` | La app minimiza el acceso a datos y recursos sensibles (principio de mínimo privilegio en permisos) | `EXTRA001` | MASWE-0117 |
| `MASVS-PRIVACY-2` | La app evita la identificación del usuario (anonimización/pseudonimización) | `PRIVACY001` | MASWE-0110 |
| `MASVS-PRIVACY-3` | La app es transparente sobre la recolección y uso de datos | — | — |
| `MASVS-PRIVACY-4` | La app ofrece al usuario control sobre sus datos | — | — |

## Controles sin cobertura hoy (gap honesto, no una promesa)

- `MASVS-AUTH-1` — La app usa protocolos de autenticación y autorización seguros y sigue las mejores prácticas relevantes
- `MASVS-AUTH-3` — La app protege las operaciones sensibles con autenticación adicional (step-up)
- `MASVS-CODE-2` — La app tiene un mecanismo para forzar actualizaciones ante vulnerabilidades críticas
- `MASVS-CODE-3` — La app solo usa componentes de software sin vulnerabilidades conocidas
- `MASVS-PRIVACY-3` — La app es transparente sobre la recolección y uso de datos
- `MASVS-PRIVACY-4` — La app ofrece al usuario control sobre sus datos

## Checks registrados

| ID | Kind | Fuente | Severidad | MASVS | MASWE | CWE |
|---|---|---|---|---|---|---|
| `DYN-CLEARTEXT-TRAFFIC` | dynamic | dynamic | high | MASVS-NETWORK-1 | MASWE-0050 | CWE-319 |
| `DYN-DEBUGGABLE` | dynamic | dynamic | high | MASVS-RESILIENCE-4 | MASWE-0067 | CWE-489 |
| `APK signature verification` | static | detector | medium | MASVS-RESILIENCE-2 | — | — |
| `Anti Magisk / SuperSU / KernelSU / Frida` | static | detector | high | MASVS-RESILIENCE-1, MASVS-RESILIENCE-4 | — | — |
| `AppDome` | static | detector | high | MASVS-RESILIENCE-1, MASVS-RESILIENCE-2, MASVS-RESILIENCE-3, MASVS-RESILIENCE-4 | — | — |
| `Certificate pinning` | static | detector | high | MASVS-NETWORK-2 | — | — |
| `DexGuardDetector` | static | detector | high | MASVS-RESILIENCE-2, MASVS-RESILIENCE-3, MASVS-RESILIENCE-4 | — | — |
| `Known anti-root libraries` | static | detector | high | MASVS-RESILIENCE-1 | — | — |
| `Manual root checks` | static | detector | medium | MASVS-RESILIENCE-1 | — | — |
| `SafetyNet / Play Integrity API` | static | detector | high | MASVS-RESILIENCE-1 | — | — |
| `MANIFEST-LOW-TARGET-SDK` | static | manifest_analyzer | medium | MASVS-CODE-1 | MASWE-0078 | — |
| `NAT001` | static | native_scanner | high | MASVS-CODE-4 | — | CWE-120 |
| `NAT002` | static | native_scanner | critical | MASVS-CODE-4 | — | CWE-78 |
| `NAT003` | static | native_scanner | info | MASVS-RESILIENCE-4 | MASWE-0101 | — |
| `NAT004` | static | native_scanner | high | MASVS-STORAGE-2 | MASWE-0002 | CWE-798 |
| `NAT005` | static | native_scanner | high | MASVS-NETWORK-1 | MASWE-0052 | CWE-295 |
| `NAT006` | static | native_scanner | medium | MASVS-RESILIENCE-1 | — | — |
| `NAT007` | static | native_scanner | medium | MASVS-NETWORK-1, MASVS-NETWORK-2 | MASWE-0047 | — |
| `NAT008` | static | native_scanner | high | MASVS-CRYPTO-1 | MASWE-0020, MASWE-0021 | CWE-327 |
| `AUTH001` | static | vuln_scanner | high | MASVS-STORAGE-2 | MASWE-0001 | CWE-532 |
| `AUTH002` | static | vuln_scanner | medium | MASVS-AUTH-2 | MASWE-0032 | CWE-477 |
| `COMP001` | static | vuln_scanner | medium | MASVS-PLATFORM-2 | MASWE-0072 | CWE-79 |
| `COMP002` | static | vuln_scanner | high | MASVS-PLATFORM-2 | MASWE-0069 | CWE-200 |
| `COMP003` | static | vuln_scanner | critical | MASVS-PLATFORM-2 | MASWE-0068 | CWE-749 |
| `COMP004` | static | vuln_scanner | medium | MASVS-PLATFORM-1 | MASWE-0063 | CWE-925 |
| `COMP005` | static | vuln_scanner | high | MASVS-PLATFORM-2 | MASWE-0072 | CWE-79 |
| `COMP006` | static | vuln_scanner | critical | MASVS-PLATFORM-1 | MASWE-0119 | CWE-926 |
| `COMP007` | static | vuln_scanner | high | MASVS-PLATFORM-1 | MASWE-0062 | CWE-926 |
| `COMP008` | static | vuln_scanner | critical | MASVS-PLATFORM-1 | MASWE-0064 | CWE-926 |
| `CRYPTO001` | static | vuln_scanner | medium | MASVS-CRYPTO-1 | MASWE-0021 | CWE-328 |
| `CRYPTO002` | static | vuln_scanner | low | MASVS-CRYPTO-1 | MASWE-0021 | CWE-328 |
| `CRYPTO003` | static | vuln_scanner | high | MASVS-CRYPTO-1 | MASWE-0020 | CWE-327 |
| `CRYPTO004` | static | vuln_scanner | high | MASVS-CRYPTO-1 | MASWE-0020 | CWE-327 |
| `CRYPTO005` | static | vuln_scanner | high | MASVS-CRYPTO-1 | MASWE-0022 | CWE-329 |
| `CRYPTO006` | static | vuln_scanner | medium | MASVS-CRYPTO-1 | MASWE-0027 | CWE-330 |
| `CRYPTO007` | static | vuln_scanner | high | MASVS-CRYPTO-2 | MASWE-0010 | CWE-916 |
| `DBG001` | static | vuln_scanner | medium | MASVS-RESILIENCE-2 | MASWE-0095 | CWE-489 |
| `DBG002` | static | vuln_scanner | medium | MASVS-STORAGE-2 | MASWE-0001 | CWE-532 |
| `DBG003` | static | vuln_scanner | low | MASVS-STORAGE-2 | MASWE-0001 | CWE-209 |
| `DESER001` | static | vuln_scanner | high | MASVS-CODE-4 | MASWE-0088 | CWE-502 |
| `EXTRA001` | static | vuln_scanner | info | MASVS-PRIVACY-1 | MASWE-0117 | CWE-250 |
| `HC001` | static | vuln_scanner | high | MASVS-STORAGE-2 | MASWE-0005 | CWE-798 |
| `HC002` | static | vuln_scanner | critical | MASVS-STORAGE-2 | MASWE-0002 | CWE-798 |
| `HC003` | static | vuln_scanner | critical | MASVS-STORAGE-2 | MASWE-0013 | CWE-798, CWE-321 |
| `HC004` | static | vuln_scanner | high | MASVS-STORAGE-2 | MASWE-0005 | CWE-798 |
| `HC005` | static | vuln_scanner | critical | MASVS-STORAGE-2 | MASWE-0005 | CWE-798 |
| `HC006` | static | vuln_scanner | high | MASVS-CRYPTO-1 | MASWE-0013 | CWE-321 |
| `HC007` | static | vuln_scanner | medium | MASVS-STORAGE-2 | — | — |
| `HC008` | static | vuln_scanner | high | MASVS-STORAGE-2, MASVS-NETWORK-1 | — | — |
| `INFO001` | static | vuln_scanner | high | MASVS-RESILIENCE-4 | MASWE-0067 | CWE-489 |
| `INJ001` | static | vuln_scanner | critical | MASVS-CODE-4 | MASWE-0086 | CWE-89 |
| `INJ002` | static | vuln_scanner | high | MASVS-CODE-4 | MASWE-0081 | CWE-22 |
| `INJ003` | static | vuln_scanner | critical | MASVS-CODE-4 | MASWE-0081 | CWE-78 |
| `INJ004` | static | vuln_scanner | high | MASVS-PLATFORM-1 | MASWE-0058 | CWE-926 |
| `NET001` | static | vuln_scanner | high | MASVS-NETWORK-1 | MASWE-0050 | CWE-319 |
| `NET002` | static | vuln_scanner | critical | MASVS-NETWORK-1 | MASWE-0052 | CWE-295 |
| `NET003` | static | vuln_scanner | high | MASVS-NETWORK-1 | MASWE-0052 | CWE-295 |
| `NET004` | static | vuln_scanner | high | MASVS-NETWORK-1 | — | CWE-327 |
| `NET005` | static | vuln_scanner | medium | MASVS-NETWORK-2 | MASWE-0047 | — |
| `NET006` | static | vuln_scanner | critical | MASVS-NETWORK-1, MASVS-PLATFORM-2 | MASWE-0052 | CWE-295 |
| `OBF001` | static | vuln_scanner | info | MASVS-RESILIENCE-3 | — | — |
| `PRIVACY001` | static | vuln_scanner | medium | MASVS-PRIVACY-2 | MASWE-0110 | CWE-359 |
| `ST001` | static | vuln_scanner | medium | MASVS-STORAGE-1 | MASWE-0006 | CWE-312 |
| `ST002` | static | vuln_scanner | high | MASVS-STORAGE-1 | MASWE-0002 | CWE-732 |
| `ST003` | static | vuln_scanner | high | MASVS-STORAGE-1 | MASWE-0007 | CWE-922 |
| `ST004` | static | vuln_scanner | medium | MASVS-STORAGE-1 | MASWE-0006 | CWE-312 |
| `ST005` | static | vuln_scanner | medium | MASVS-PLATFORM-3 | MASWE-0053 | — |
| `ST006` | static | vuln_scanner | high | MASVS-STORAGE-2 | — | — |
