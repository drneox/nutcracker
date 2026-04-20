"""Descargador de APKs usando apkeep (Google Play o APKPure) o URL directa."""

from __future__ import annotations

import os
import re
import subprocess
import urllib.request
from pathlib import Path
from urllib.parse import urlparse, parse_qs


class APKDownloadError(Exception):
    """Error durante la descarga de una APK."""


_APKEEP = "apkeep"


def _check_apkeep() -> None:
    """Verifica que apkeep esté instalado."""
    try:
        subprocess.run([_APKEEP, "--version"], capture_output=True, check=True, timeout=10)
    except FileNotFoundError:
        raise APKDownloadError(
            "apkeep no está instalado.\n"
            "  macOS: brew install apkeep\n"
            "  Linux: https://github.com/EFForg/apkeep/releases"
        )
    except subprocess.CalledProcessError as exc:
        raise APKDownloadError(f"Error al verificar apkeep: {exc.stderr}") from exc


def _extract_package_id(url: str) -> str:
    """
    Extrae el package ID desde una URL de Google Play o lo devuelve tal cual.

    Soporta:
      https://play.google.com/store/apps/details?id=com.example.app&hl=es
      market://details?id=com.example.app
      com.example.app  (package ID directo)
    """
    _pkg_re = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")

    if _pkg_re.match(url):
        return url

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if "id" in params:
        pkg = params["id"][0]
        if _pkg_re.match(pkg):
            return pkg

    raise APKDownloadError(
        f"No se pudo extraer el package ID de: {url}\n"
        "Formato esperado: https://play.google.com/store/apps/details?id=com.example.app"
    )


def _find_downloaded_apk(output_dir: Path, package_id: str) -> Path:
    """Busca el APK base recién descargado en el directorio de salida."""
    # Caso App Bundle: apkeep puede guardar en una carpeta por paquete,
    # por ejemplo downloads/com.foo.app/com.foo.app.apk + split_config.*.apk
    #            o bien  downloads/com.foo.app/base.apk   + split_config.*.apk
    package_dir = output_dir / package_id
    if package_dir.is_dir():
        # 1. APK con nombre del paquete (formato apkeep >= 0.18)
        pkg_apk = package_dir / f"{package_id}.apk"
        if pkg_apk.exists():
            return pkg_apk
        # 2. base.apk (formato App Bundle clásico)
        base_apk = package_dir / "base.apk"
        if base_apk.exists():
            return base_apk
        # 3. Cualquier .apk que NO sea split/config (heurística)
        for apk in sorted(package_dir.glob("*.apk"), key=os.path.getmtime, reverse=True):
            name_lower = apk.name.lower()
            if "config." not in name_lower and "split_" not in name_lower:
                return apk
        # 4. Búsqueda recursiva de base.apk
        nested_base = sorted(package_dir.rglob("base.apk"), key=os.path.getmtime, reverse=True)
        if nested_base:
            return nested_base[0]

    for pattern in [f"{package_id}*.apk", f"{package_id}*.xapk"]:
        matches = sorted(output_dir.glob(pattern), key=os.path.getmtime, reverse=True)
        if matches:
            return matches[0]
    raise APKDownloadError(
        f"APK no encontrada en '{output_dir}' tras la descarga.\n"
        "Verifica que la app esté disponible y que las credenciales sean correctas."
    )


def _run_apkeep(cmd: list[str], redact: list[str] | None = None) -> None:
    """Ejecuta apkeep y lanza APKDownloadError si falla."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired as exc:
        raise APKDownloadError("Tiempo de descarga agotado (5 min).") from exc

    if result.returncode != 0:
        stderr = result.stderr
        for secret in (redact or []):
            if secret:
                stderr = stderr.replace(secret, "***")
        raise APKDownloadError(f"apkeep falló (código {result.returncode}):\n{stderr}")


def is_direct_apk_url(url: str) -> bool:
    """
    Devuelve True si la URL apunta directamente a un archivo .apk descargable.

    Se considera URL directa cuando:
      - El path termina en .apk, o
      - El host no es play.google.com / apkpure.com y la URL comienza por http(s)
        y tiene la cadena '.apk' en la URL (incluyendo query params típicos de CDNs).
    """
    if not url.startswith(("http://", "https://")):
        return False
    parsed = urlparse(url)
    # Path termina en .apk (caso más común)
    if parsed.path.lower().endswith(".apk"):
        return True
    # CDNs que meten el nombre en query params (ej. ?file=app.apk)
    if ".apk" in url.lower() and parsed.hostname not in (
        "play.google.com", "market.android.com", "apkpure.com", "apkpure.net"
    ):
        return True
    return False


# ── Descarga directa por URL ──────────────────────────────────────────────────

class DirectURLDownloader:
    """
    Descarga una APK desde una URL HTTP/HTTPS directa.

    Útil para mirrors, CDNs internos o cualquier enlace directo a un .apk.
    """

    def __init__(self, output_dir: str = "./downloads"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def dest_path(self, url: str) -> Path:
        """Devuelve el path local donde se guardaría la APK de url (sin descargar)."""
        parsed = urlparse(url)
        raw_name = Path(parsed.path).name or "download.apk"
        safe_name = re.sub(r"[^\w.\-]", "_", raw_name)
        if not safe_name.lower().endswith(".apk"):
            safe_name += ".apk"
        return self.output_dir / safe_name

    def download(
        self,
        url: str,
        progress_callback=None,
        use_cache: bool = False,
    ) -> Path:
        """
        Descarga la APK desde la URL en chunks y la guarda en output_dir.

        Args:
            url: URL directa al archivo .apk.
            progress_callback: callable(downloaded_bytes, total_bytes | None)
                               llamado cada chunk para reportar progreso.
            use_cache: si es True y el archivo ya existe en output_dir, lo
                       reutiliza sin volver a descargar.

        Returns:
            Path al archivo .apk descargado.
        """
        parsed = urlparse(url)

        # Nombre de archivo desde el path de la URL
        raw_name = Path(parsed.path).name or "download.apk"
        safe_name = re.sub(r"[^\w.\-]", "_", raw_name)
        if not safe_name.lower().endswith(".apk"):
            safe_name += ".apk"

        dest = self.output_dir / safe_name

        # ── Caché: si el archivo ya existe y es valid, no descargar de nuevo ──
        if use_cache and dest.exists() and dest.stat().st_size > 0:
            header = dest.read_bytes()[:4]
            if header == b"PK\x03\x04":
                return dest

        chunk_size = 64 * 1024  # 64 KB por chunk

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Android; nutcracker/1.0)"},
            )
            # timeout por operación (connect + cada read de chunk)
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                content_type = resp.headers.get("Content-Type", "")
                if content_type and "html" in content_type.lower():
                    raise APKDownloadError(
                        f"La URL devolvio HTML en lugar de un APK.\n"
                        f"Asegurate de que la URL apunte directamente al archivo .apk.\n"
                        f"URL: {url}"
                    )
                total = resp.headers.get("Content-Length")
                total_bytes = int(total) if total else None
                downloaded = 0

                with open(dest, "wb") as fh:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        fh.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback:
                            progress_callback(downloaded, total_bytes)

        except APKDownloadError:
            raise
        except urllib.error.HTTPError as exc:
            raise APKDownloadError(
                f"Error HTTP {exc.code} descargando APK: {exc.reason}\nURL: {url}"
            ) from exc
        except Exception as exc:
            dest.unlink(missing_ok=True)
            raise APKDownloadError(
                f"No se pudo descargar la APK: {exc}\nURL: {url}"
            ) from exc

        # Verificar que es un APK válido (magic bytes PK\x03\x04)
        header = dest.read_bytes()[:4]
        if header != b"PK\x03\x04":
            dest.unlink(missing_ok=True)
            raise APKDownloadError(
                f"El archivo descargado no es un APK valido (magic bytes incorrectos).\n"
                f"URL: {url}"
            )

        return dest


# ── APKPure (sin autenticación) ───────────────────────────────────────────────

class APKPureDownloader:
    """Descarga APKs desde APKPure sin necesidad de credenciales."""

    def __init__(self, output_dir: str = "./downloads"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        _check_apkeep()

    def download(self, url: str) -> Path:
        package_id = _extract_package_id(url)
        _run_apkeep([_APKEEP, "-a", package_id, "-d", "apk-pure", str(self.output_dir)])
        return _find_downloaded_apk(self.output_dir, package_id)


# ── Google Play (requiere AAS token) ─────────────────────────────────────────

class GooglePlayDownloader:
    """
    Descarga APKs desde Google Play usando apkeep >= 0.18.0.

    Requiere email + aas_token (ver config.yaml para instrucciones).
    """

    def __init__(self, email: str, aas_token: str, output_dir: str = "./downloads"):
        self.email = email
        self._aas_token = aas_token
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        _check_apkeep()

    def download(self, url: str) -> Path:
        package_id = _extract_package_id(url)
        cmd = [
            _APKEEP,
            "-a", package_id,
            "-d", "google-play",
            "-o", "split_apk=true",
            "-e", self.email,
            "-t", self._aas_token,
            "--accept-tos",
            str(self.output_dir),
        ]
        _run_apkeep(cmd, redact=[self._aas_token, self.email])
        return _find_downloaded_apk(self.output_dir, package_id)



