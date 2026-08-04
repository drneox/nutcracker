# Desplegar el dashboard en un VPS con HTTPS

WebUSB (`navigator.usb`) solo funciona en un "secure context": HTTPS en un
dominio público, o `http://localhost`. Un VPS con IP pública servido por HTTP
plano bloquea WebUSB por completo en el navegador — este setup es un
requisito duro, no una mejora opcional.

Let's Encrypt (usado acá vía Caddy, con renovación automática) **no emite
certificados para una IP sola** — hace falta un nombre de dominio con un
registro DNS A/AAAA apuntando al VPS.

## 1. Conseguir un dominio/subdominio

Sin dominio propio todavía, la vía gratis más simple es
**[DuckDNS](https://www.duckdns.org)**: entrás con GitHub/Google, elegís un
subdominio (`tuusuario.duckdns.org`) y le apuntás la IP pública del VPS.
DuckDNS es un registro DNS real y Let's Encrypt lo acepta sin problema — es
el camino usado normalmente para VPS/home-lab sin comprar dominio.

Si preferís algo más permanente/profesional, un dominio propio (~10 USD/año
en Namecheap, Cloudflare Registrar, etc.) con un registro A apuntando a la
IP del VPS funciona igual — el resto de esta guía no cambia.

## 2. Instalar Caddy (Ubuntu/Debian)

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

## 3. Configurar el Caddyfile

Copiar [`Caddyfile`](Caddyfile) a `/etc/caddy/Caddyfile` en el VPS,
reemplazando `{$NUTCRACKER_DOMAIN}` por el dominio real (o exportando
`NUTCRACKER_DOMAIN=tuusuario.duckdns.org` antes de arrancar el servicio).
Caddy emite el certificado y lo renueva solo — no hace falta certbot ni cron.

```bash
sudo systemctl reload caddy
```

## 4. Correr el dashboard en 127.0.0.1 (no 0.0.0.0)

En el VPS, a diferencia del uso local en LAN (`--host 0.0.0.0` para que el
celular lo alcance por WiFi), el dashboard **no debe escuchar directo en la
IP pública** — solo Caddy (local) le habla, y el firewall bloquea el puerto
del dashboard desde afuera:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 8765/tcp   # el dashboard solo debe ser alcanzable vía Caddy
```

Usar [`nutcracker-dashboard.service`](nutcracker-dashboard.service) como
unit de systemd (ajustar `User`/`WorkingDirectory`/`ExecStart` a la ruta real
del VPS):

```bash
sudo cp deploy/nutcracker-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nutcracker-dashboard
```

## 5. Verificar

- `https://tuusuario.duckdns.org` abre el dashboard con candado válido.
- La pestaña "Dispositivo" → WebUSB detecta `navigator.usb` disponible (antes,
  por HTTP, el botón fallaría silenciosamente o el navegador ni lo expondría).
- Los WebSocket (`/ws/jobs/{id}`, `/ws/chat/{pkg}`, `/ws/relay/{id}`) siguen
  funcionando igual — Caddy los proxea sin config adicional.

## Pendiente (no cubierto por este setup)

Con esto el dashboard queda en HTTPS y accesible desde cualquier navegador,
pero sigue **sin autenticación** — cualquiera con la URL puede operarlo. Es
el siguiente bloqueador real para un despliegue verdaderamente público (ver
`plan.md`).
