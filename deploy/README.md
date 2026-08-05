# Desplegar el dashboard en un VPS con HTTPS

WebUSB (`navigator.usb`) solo funciona en un "secure context": HTTPS, o
`http://localhost`. Un VPS con IP pública servido por HTTP plano bloquea
WebUSB por completo en el navegador — este setup es un requisito duro, no una
mejora opcional.

Esta guía asume que **ya tenés un certificado TLS como archivo** (emitido por
donde sea: Let's Encrypt/certbot, un Key Vault/gestor de secretos de tu nube,
uno propio de tu organización) y usa **nginx** como reverse proxy — nginx solo
carga `cert.pem`/`key.pem` y reenvía a uvicorn, no emite ni renueva nada.

> Si en cambio no tenés un certificado todavía y querés que se emita solo (sin
> gestionarlo vos), la vía más simple es Caddy con Let's Encrypt automático
> sobre tu propio dominio (o un subdominio gratis de
> [DuckDNS](https://www.duckdns.org) si no tenés uno) — avisame y armamos esa
> variante en vez de la de acá.

## 0. Convención de dónde poner el certificado

Si no tenés ya un lugar establecido para tus certs, una convención simple:

```bash
sudo mkdir -p /etc/nutcracker/tls
sudo cp /ruta/a/tu/cert.pem /etc/nutcracker/tls/cert.pem
sudo cp /ruta/a/tu/key.pem  /etc/nutcracker/tls/key.pem
```

El resto de esta guía (y [`nutcracker.nginx.conf`](nutcracker.nginx.conf))
usa `/etc/nutcracker/tls/` como ejemplo — si tus archivos ya viven en otro
lado (Key Vault descargado a otra ruta, etc.), ajustá `ssl_certificate`/
`ssl_certificate_key` en ese archivo a tu ruta real en vez de copiarlos.

## 1. Confirmar qué dominio/IP cubre el certificado

```bash
openssl x509 -in /etc/nutcracker/tls/cert.pem -noout -subject -ext subjectAltName -enddate
```

La URL con la que entrás al navegador (dominio o IP) tiene que coincidir con
el CN/SAN del certificado — si no, el navegador va a mostrar advertencia de
certificado sin importar que la conexión esté cifrada igual. Anotá también la
fecha de expiración (`enddate`) y quién es responsable de renovarlo antes de
que venza (nginx no lo hace, ver la sección "Pendiente" al final).

## 1.5 Si el VPS es una VM de Azure: abrir el NSG

Azure filtra el tráfico entrante a nivel de nube con un **Network Security
Group (NSG)**, aparte del firewall del sistema operativo (`ufw`, paso 4) — si
no se abre acá, el tráfico HTTPS no llega nunca a la VM aunque `ufw` esté bien
configurado. (Equivalente en otras nubes: security groups de AWS, firewall
rules de GCP, etc.)

En el [Azure Portal](https://portal.azure.com): recurso de la VM → menú
**Networking** (o el recurso "Network security group" asociado) → **Inbound
port rules** → **Add**, y agregar una regla permitiendo:

- **Puerto 8765** (el puerto público elegido para HTTPS, en vez del 443
  estándar)

El puerto 22 (SSH) normalmente ya está abierto (es como te conectás hoy). El
puerto 8766 (el dashboard interno real) **no** debe abrirse acá — solo nginx
(local en la VM) debe alcanzarlo, igual que con `ufw` en el paso 4.

## 2. Instalar nginx (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y nginx
```

## 3. Configurar el server block

Copiar [`nutcracker.nginx.conf`](nutcracker.nginx.conf) a
`/etc/nginx/conf.d/nutcracker.conf` (ese directorio ya se incluye desde el
bloque `http{}` de nginx.conf por defecto en Ubuntu/Debian — no hace falta
tocar nginx.conf). Trae rutas de ejemplo `/etc/nutcracker/tls/cert.pem`/
`key.pem` (paso 0) — ajustalas si tus certs viven en otro lado.

```bash
sudo cp deploy/nutcracker.nginx.conf /etc/nginx/conf.d/nutcracker.conf
sudo nginx -t   # valida la sintaxis antes de aplicar
sudo systemctl reload nginx   # o `start` si nginx no estaba corriendo todavía
```

No hace falta darle permiso a `www-data` sobre el cert/key (ni `chown` ni
`chmod`): nginx lee `ssl_certificate`/`ssl_certificate_key` en su **proceso
master, que corre como root** — root puede leer esos archivos sin importar su
dueño/permisos actuales, antes de que los workers (que sí corren como
`www-data`) arranquen. De hecho, dejarlos legibles SOLO por root (como suele
venir por defecto) es más restrictivo/seguro que abrirle lectura a
`www-data` — verificado en vivo: funciona sin tocar ownership/permisos.

A diferencia de Caddy, nginx no maneja WebSocket "solo" — el archivo ya trae
el bloque `map` y los `proxy_set_header Upgrade/Connection` necesarios para
que `/ws/jobs`, `/ws/chat` y `/ws/relay` funcionen detrás del proxy; si los
sacás, esos WebSocket van a fallar el handshake.

## 3.5 Activar el login del dashboard (obligatorio en internet)

Expuesto a internet, el dashboard **debe** exigir autenticación — si no,
cualquiera con la URL lo opera (encolar jobs, manejar el relay al dispositivo,
leer reportes). Generá las credenciales:

```bash
python nutcracker.py dashboard-hash-password -u admin
```

Pide la contraseña sin eco e imprime un bloque YAML listo (con `password_hash`
pbkdf2 y un `secret_key` aleatorio). Pegalo en `config.yaml` bajo `dashboard:`:

```yaml
dashboard:
  bind: '127.0.0.1'
  port: 8766
  auth:
    enabled: true
    username: admin
    password_hash: 'pbkdf2_sha256$...'   # lo que imprimió el comando
    secret_key: '...'                    # idem — fijo para que las sesiones sobrevivan reinicios
    session_hours: 12
    # secure_cookie NO se declara acá -- queda en su default (true), correcto
    # porque el VPS sirve por HTTPS. Esa línea solo se usa para pruebas
    # locales por HTTP plano (ver el resto de plan.md).
```

La contraseña nunca se guarda en texto plano — solo el hash. El `secret_key`
firma las cookies de sesión: manténelo fijo y secreto (quien lo tenga puede
falsificar sesiones).

## 4. Correr el dashboard en 127.0.0.1 (no 0.0.0.0)

En el VPS, a diferencia del uso local en LAN (`--host 0.0.0.0` para que el
celular lo alcance por WiFi), el dashboard **no debe escuchar directo en la
IP pública** — solo nginx (local) le habla, y el firewall bloquea el puerto
del dashboard desde afuera:

```bash
sudo ufw allow 8765/tcp   # puerto público elegido para HTTPS
sudo ufw deny 8766/tcp    # el dashboard interno solo debe ser alcanzable vía nginx
```

Usar [`nutcracker-dashboard.service`](nutcracker-dashboard.service) como
unit de systemd (ajustar `User`/`WorkingDirectory`/`ExecStart` a la ruta real
de tu máquina):

```bash
sudo cp deploy/nutcracker-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nutcracker-dashboard
```

## 5. Verificar

- `https://<tu-dominio-o-ip>:8765` redirige a la pantalla de login; tras
  ingresar con usuario/contraseña, abre el dashboard con candado válido.
- La pestaña "Dispositivo" → WebUSB detecta `navigator.usb` disponible (antes,
  por HTTP, el botón fallaría silenciosamente o el navegador ni lo expondría).
- Los WebSocket (`/ws/jobs/{id}`, `/ws/chat/{pkg}`, `/ws/relay/{id}`) siguen
  funcionando (probar la pestaña "Cola" → logs en vivo de un job).

## Pendiente (no cubierto por este setup)

Con esto el dashboard queda en HTTPS y con login por usuario/contraseña. Lo
que sigue sin resolver para un despliegue verdaderamente multi-usuario:

- **Un solo usuario/credencial compartida** — el login es de un único par
  usuario+contraseña, no hay cuentas por persona ni aislamiento entre ellas.
- **API key del LLM compartida** — sigue siendo una sola key en `config.yaml`
  para todos; multi-tenant necesitaría una key por usuario o un proxy medido
  (ver `plan.md`).
- **Renovación del certificado**: como esta guía asume un certificado externo
  a nginx (no lo emite Caddy/certbot acá), la renovación es responsabilidad
  de quien lo generó originalmente — nginx no la dispara ni avisa cuando se
  acerca el vencimiento. Si preferís que se renueve solo, ver la alternativa
  de Caddy+Let's Encrypt mencionada arriba.
