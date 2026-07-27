"""Tests de nutcracker_core/plugins/dashboard/scrcpy_video.py (video en vivo
real vía el cliente scrcpy oficial — ver el docstring del módulo para el
porqué de invocar el binario real en vez de reimplementar el protocolo).

Todo mockeado: ni un subprocess real ni una decodificación H.264 real corren
en estos tests — lo que se ejercita es la mecánica propia (localización del
binario, construcción del comando, ciclo de reinicio, generador multipart),
no el pipeline de video real (verificado a mano contra hardware, ver plan.md).
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from nutcracker_core.plugins.dashboard import scrcpy_video


# ── find_scrcpy_binary / _find_adjacent_adb ─────────────────────────────────

def test_find_scrcpy_binary_prefers_configured_path(tmp_path):
    fake_bin = tmp_path / "scrcpy.exe"
    fake_bin.write_text("fake")
    config = {"dashboard": {"scrcpy_path": str(fake_bin)}}
    assert scrcpy_video.find_scrcpy_binary(config) == str(fake_bin)


def test_find_scrcpy_binary_falls_back_to_path_when_configured_missing(tmp_path):
    config = {"dashboard": {"scrcpy_path": str(tmp_path / "nope")}}
    with patch("shutil.which", return_value="/usr/bin/scrcpy"):
        assert scrcpy_video.find_scrcpy_binary(config) == "/usr/bin/scrcpy"


def test_find_scrcpy_binary_none_when_nothing_found():
    with patch("shutil.which", return_value=None):
        assert scrcpy_video.find_scrcpy_binary({}) is None
        assert scrcpy_video.find_scrcpy_binary(None) is None


def test_find_adjacent_adb_returns_sibling_when_present(tmp_path):
    scrcpy_bin = tmp_path / "scrcpy.exe"
    scrcpy_bin.write_text("fake")
    adb_bin = tmp_path / "adb.exe"
    adb_bin.write_text("fake")
    assert scrcpy_video._find_adjacent_adb(str(scrcpy_bin)) == str(adb_bin)


def test_find_adjacent_adb_none_when_absent(tmp_path):
    scrcpy_bin = tmp_path / "scrcpy"
    scrcpy_bin.write_text("fake")
    assert scrcpy_video._find_adjacent_adb(str(scrcpy_bin)) is None


# ── decode_last_frame_jpeg ───────────────────────────────────────────────────

def test_decode_last_frame_jpeg_missing_file(tmp_path):
    assert scrcpy_video.decode_last_frame_jpeg(tmp_path / "nope.mkv") is None


def test_decode_last_frame_jpeg_empty_file(tmp_path):
    p = tmp_path / "empty.mkv"
    p.write_bytes(b"")
    assert scrcpy_video.decode_last_frame_jpeg(p) is None


def test_decode_last_frame_jpeg_unreadable_container(tmp_path):
    p = tmp_path / "garbage.mkv"
    p.write_bytes(b"not a real mkv file")
    # av.open lanzará sobre bytes basura -- debe devolver None, no propagar.
    assert scrcpy_video.decode_last_frame_jpeg(p) is None


def test_decode_last_frame_jpeg_returns_last_frame_as_jpeg(tmp_path):
    p = tmp_path / "clip.mkv"
    p.write_bytes(b"fake but non-empty")

    fake_image = MagicMock()

    def _fake_save(buf, format=None, quality=None):
        buf.write(b"\xff\xd8\xff\xd9")  # marcadores JPEG start/end, contenido irrelevante

    fake_image.save.side_effect = _fake_save

    frame1, frame2 = MagicMock(), MagicMock()
    frame1.to_image.return_value = fake_image
    frame2.to_image.return_value = fake_image

    fake_container = MagicMock()
    fake_container.duration = None  # archivo "recién creado" -- sin seek, decode desde el principio
    fake_container.decode.return_value = [frame1, frame2]

    with patch("av.open", return_value=fake_container):
        result = scrcpy_video.decode_last_frame_jpeg(p)

    assert result == b"\xff\xd8\xff\xd9"
    fake_container.close.assert_called_once()
    fake_container.seek.assert_not_called()
    # Debe quedarse con el ÚLTIMO frame decodificado, no el primero.
    frame2.to_image.assert_called_once()
    frame1.to_image.assert_not_called()


def test_decode_last_frame_jpeg_seeks_near_end_on_long_recording(tmp_path):
    """Con un archivo lo bastante largo (container.duration disponible y
    mayor al lookback), debe hacer seek cerca del final en vez de decodificar
    desde el principio -- ver docstring del módulo para la medición real que
    motiva esto (0.5s/poll sin seek vs 0.07s/poll con seek)."""
    p = tmp_path / "clip.mkv"
    p.write_bytes(b"fake but non-empty")

    fake_image = MagicMock()
    fake_image.save.side_effect = lambda buf, format=None, quality=None: buf.write(b"\xff\xd8\xff\xd9")
    frame = MagicMock()
    frame.to_image.return_value = fake_image

    fake_container = MagicMock()
    fake_container.duration = 30_000_000  # 30s, bien por encima del lookback de 1.5s
    fake_container.decode.return_value = [frame]

    with patch("av.open", return_value=fake_container):
        result = scrcpy_video.decode_last_frame_jpeg(p)

    assert result == b"\xff\xd8\xff\xd9"
    fake_container.seek.assert_called_once_with(
        30_000_000 - scrcpy_video._SEEK_LOOKBACK_US, any_frame=False,
    )


def test_decode_last_frame_jpeg_falls_back_when_seek_raises(tmp_path):
    """Si el seek falla (formato inesperado, versión de ffmpeg, etc.), debe
    seguir intentando decode() en vez de propagar la excepción."""
    p = tmp_path / "clip.mkv"
    p.write_bytes(b"fake but non-empty")

    fake_image = MagicMock()
    fake_image.save.side_effect = lambda buf, format=None, quality=None: buf.write(b"\xff\xd8\xff\xd9")
    frame = MagicMock()
    frame.to_image.return_value = fake_image

    fake_container = MagicMock()
    fake_container.duration = 30_000_000
    fake_container.seek.side_effect = RuntimeError("seek no soportado")
    fake_container.decode.return_value = [frame]

    with patch("av.open", return_value=fake_container):
        result = scrcpy_video.decode_last_frame_jpeg(p)

    assert result == b"\xff\xd8\xff\xd9"


# ── ScrcpyVideoSession._build_cmd ────────────────────────────────────────────

def test_build_cmd_includes_serial_when_given(tmp_path):
    session = scrcpy_video.ScrcpyVideoSession("scrcpy", serial="ZY22GPM27J")
    cmd = session._build_cmd(tmp_path / "clip_1.mkv")
    assert cmd[0] == "scrcpy"
    assert "--no-window" in cmd
    assert "-s" in cmd and cmd[cmd.index("-s") + 1] == "ZY22GPM27J"
    assert any(c.startswith("--record=") for c in cmd)
    session.stop()


def test_build_cmd_omits_serial_when_none(tmp_path):
    session = scrcpy_video.ScrcpyVideoSession("scrcpy", serial=None)
    cmd = session._build_cmd(tmp_path / "clip_1.mkv")
    assert "-s" not in cmd
    session.stop()


# ── ScrcpyVideoSession._run (ciclo de fondo, todo mockeado) ──────────────────

def test_session_sets_latest_jpeg_when_frames_decode(monkeypatch, tmp_path):
    monkeypatch.setattr(scrcpy_video, "_RESTART_INTERVAL_S", 0.3)
    monkeypatch.setattr(scrcpy_video, "_POLL_INTERVAL_S", 0.05)

    fake_proc = MagicMock()
    fake_proc.poll.return_value = None  # "vivo" durante todo el ciclo
    fake_proc.stdout = None

    with patch("subprocess.Popen", return_value=fake_proc), \
         patch("subprocess.run"), \
         patch.object(scrcpy_video, "decode_last_frame_jpeg", return_value=b"jpegdata"):
        session = scrcpy_video.ScrcpyVideoSession("scrcpy", serial=None)
        session.start()
        time.sleep(0.5)
        assert session.latest_jpeg() == b"jpegdata"
        assert session.error() is None
        session.stop()


def test_session_sets_error_when_no_frames_ever_decode(monkeypatch, tmp_path):
    monkeypatch.setattr(scrcpy_video, "_RESTART_INTERVAL_S", 0.2)
    monkeypatch.setattr(scrcpy_video, "_POLL_INTERVAL_S", 0.05)
    monkeypatch.setattr(scrcpy_video, "_RETRY_BACKOFF_S", 0.05)

    fake_proc = MagicMock()
    fake_proc.poll.return_value = None
    fake_stdout = MagicMock()
    fake_stdout.read.return_value = "[server] ERROR: something broke"
    fake_proc.stdout = fake_stdout

    with patch("subprocess.Popen", return_value=fake_proc), \
         patch("subprocess.run"), \
         patch.object(scrcpy_video, "decode_last_frame_jpeg", return_value=None):
        session = scrcpy_video.ScrcpyVideoSession("scrcpy", serial=None)
        session.start()
        time.sleep(0.4)
        assert session.latest_jpeg() is None
        assert session.error() is not None
        assert "something broke" in session.error()
        session.stop()


def test_session_reports_error_when_binary_not_found(tmp_path):
    with patch("subprocess.Popen", side_effect=FileNotFoundError("no such file")):
        session = scrcpy_video.ScrcpyVideoSession("scrcpy-inexistente", serial=None)
        session.start()
        time.sleep(0.2)
        assert session.error() is not None
        session.stop()


# ── mjpeg_multipart ──────────────────────────────────────────────────────────

def test_mjpeg_multipart_yields_frame_with_correct_headers():
    session = MagicMock()
    session.latest_jpeg.return_value = b"abc123"

    gen = scrcpy_video.mjpeg_multipart(session, boundary="testboundary", fps=1000)
    chunk = next(gen)

    assert b"--testboundary\r\n" in chunk
    assert b"Content-Type: image/jpeg\r\n" in chunk
    assert b"Content-Length: 6\r\n" in chunk
    assert chunk.endswith(b"abc123\r\n")
    gen.close()


def test_mjpeg_multipart_skips_resending_same_frame(monkeypatch):
    frame_a = b"frame-a"
    frame_b = b"frame-b"
    session = MagicMock()
    # Tres lecturas seguidas del mismo objeto frame_a, luego cambia a frame_b.
    session.latest_jpeg.side_effect = [frame_a, frame_a, frame_a, frame_b]
    monkeypatch.setattr(scrcpy_video.time, "sleep", lambda _: None)

    gen = scrcpy_video.mjpeg_multipart(session, fps=1000)
    first = next(gen)   # frame_a es nuevo -> yield
    second = next(gen)  # frame_b tras dos repeticiones de frame_a -> yield
    gen.close()

    assert first.endswith(b"frame-a\r\n")
    assert second.endswith(b"frame-b\r\n")
    # Se llamó a latest_jpeg() 4 veces (3 de frame_a + 1 de frame_b) para
    # producir solo 2 yields -- confirma que las repeticiones no re-emiten.
    assert session.latest_jpeg.call_count == 4
