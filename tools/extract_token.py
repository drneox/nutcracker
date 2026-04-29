#!/usr/bin/env python3
"""Asistente interactivo para obtener y guardar google_play.aas_token en config.yaml."""

from __future__ import annotations

import argparse
import sqlite3
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from nutcracker_core.i18n import init as _i18n_init, t as t


def _peek_language() -> str:
    """Lee el idioma de config.yaml sin cargarlo completamente."""
    for candidate in [Path("config.yaml"), Path(__file__).parent.parent / "config.yaml"]:
        if candidate.exists():
            try:
                with candidate.open(encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                return str(cfg.get("language", "en")).strip().lower()
            except Exception:
                pass
    return "en"


_i18n_init(_peek_language())


def _adb(serial: str | None, *args: str, timeout: int = 20) -> tuple[str, int]:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (result.stdout + result.stderr).strip(), result.returncode


def _pause(msg: str, interactive: bool) -> None:
    if interactive:
        input(msg)


def _list_devices() -> tuple[list[str], list[str]]:
    out, _ = _adb(None, "devices")
    lines = [l for l in out.splitlines() if "\t" in l]
    authorized = [l.split("\t")[0] for l in lines if l.endswith("device")]
    unauthorized = [l.split("\t")[0] for l in lines if "unauthorized" in l]
    return authorized, unauthorized


def _select_device(preferred_serial: str | None, interactive: bool) -> str:
    authorized, unauthorized = _list_devices()

    if unauthorized:
        print(t("et_err_unauthorized"))
        for serial in unauthorized:
            print(f"  - {serial}")
        print(t("et_unlock_usb"))
        sys.exit(1)

    if not authorized:
        print(t("et_err_no_devices"))
        print(t("et_suggested_steps"))
        print(t("et_step_connect_usb"))
        print(t("et_step_dev_options"))
        print(t("et_step_accept_dialog"))
        sys.exit(1)

    if preferred_serial:
        if preferred_serial in authorized:
            return preferred_serial
        print(t("et_warn_serial", serial=preferred_serial))

    if len(authorized) == 1 or not interactive:
        return authorized[0]

    print(t("et_devices_found"))
    for i, serial in enumerate(authorized, 1):
        model_out, _ = _adb(serial, "shell", "getprop", "ro.product.model")
        model = model_out.strip() or t("et_unknown_model")
        print(f"  {i}) {serial}  [{model}]")

    while True:
        try:
            idx = int(input(t("et_choose_device", count=len(authorized))).strip())
            if 1 <= idx <= len(authorized):
                return authorized[idx - 1]
        except ValueError:
            pass
        print(t("et_invalid_input"))


def _device_instructions() -> None:
    print(t("et_device_steps_header"))
    print(t("et_device_no_play_store"))
    print(t("et_device_step1"))
    print(t("et_device_step2"))
    print(t("et_device_step3"))


def _load_email(config_path: Path, email_arg: str | None) -> str:
    if email_arg:
        return email_arg
    if not config_path.exists():
        print(t("et_err_no_config", path=config_path))
        sys.exit(1)
    with config_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    email = str(cfg.get("google_play", {}).get("email", "")).strip()
    if not email:
        print(t("et_err_no_email"))
        sys.exit(1)
    return email


def _save_aas_token(config_path: Path, email: str, aas_token: str) -> None:
    cfg: dict
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}

    gp = cfg.setdefault("google_play", {})
    gp["email"] = email
    gp["aas_token"] = aas_token

    with config_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=False)


def _get_android_id(serial: str) -> str:
    out, _ = _adb(serial, "shell", "settings", "get", "secure", "android_id")
    return out.strip()


def _try_root_database(serial: str) -> str | None:
    root_runner = None

    # Ruta 1: adbd root (emuladores y builds debug)
    out, code = _adb(serial, "root")
    if code == 0 and not any(w in out.lower() for w in ["cannot", "not allowed", "production"]):
        time.sleep(2)

        def _run_as_root(cmd: str, timeout: int = 12) -> tuple[str, int]:
            return _adb(serial, "shell", cmd, timeout=timeout)

        root_runner = _run_as_root
    else:
        # Ruta 2: dispositivo rooteado con Magisk/su (cuando adb root está bloqueado)
        su_out, su_code = _adb(serial, "shell", "su", "-c", "id", timeout=8)
        if su_code == 0 and "uid=0" in su_out:

            def _run_as_root(cmd: str, timeout: int = 12) -> tuple[str, int]:
                return _adb(serial, "shell", "su", "-c", cmd, timeout=timeout)

            root_runner = _run_as_root

    if root_runner is None:
        return None

    def _adb_exec_bytes(cmd: str, timeout: int = 15) -> tuple[bytes, int]:
        result = subprocess.run(
            ["adb", "-s", serial, "exec-out", "su", "-c", cmd],
            capture_output=True,
            timeout=timeout,
        )
        return result.stdout, result.returncode

    def _pick_token(raw: str) -> str | None:
        for line in raw.splitlines():
            for part in line.split("|"):
                v = part.strip()
                if not v:
                    continue
                if v.startswith("aas_et/"):
                    return v
                if v.startswith("oauth2_4/"):
                    return v
                if v.startswith("V1"):
                    return v
                if v.startswith("ya29."):
                    return v
                if len(v) > 40 and any(k in v for k in ("-", "_", "/")):
                    return v
        return None

    def _has_device_sqlite() -> bool:
        out, _ = root_runner("sqlite3 -version", timeout=8)
        if out and "not found" not in out.lower() and "inaccessible" not in out.lower():
            return True
        out, _ = root_runner("toybox sqlite3 -help", timeout=8)
        return bool(out and "not found" not in out.lower() and "inaccessible" not in out.lower())

    def _query_local_copy(db_path: str, query: str) -> str:
        # Fallback para dispositivos rooteados sin sqlite3: copiar DB y consultar en host.
        raw, code = _adb_exec_bytes(f"cat {db_path}", timeout=20)
        if code != 0 or not raw:
            return ""
        with tempfile.NamedTemporaryFile(prefix="nutcracker_db_", suffix=".db", delete=False) as tmp:
            tmp.write(raw)
            tmp_path = Path(tmp.name)
        try:
            with sqlite3.connect(tmp_path) as conn:
                cur = conn.cursor()
                cur.execute(query)
                rows = cur.fetchall()
            values: list[str] = []
            for row in rows:
                for col in row:
                    if col is None:
                        continue
                    values.append(str(col))
            return "\n".join(values)
        except Exception:
            return ""
        finally:
            tmp_path.unlink(missing_ok=True)

    has_sqlite = _has_device_sqlite()

    def _run_query(db_path: str, query: str, timeout: int = 12) -> str:
        if has_sqlite:
            out, _ = root_runner(f'sqlite3 {db_path} "{query}"', timeout=timeout)
            return out
        return _query_local_copy(db_path, query)

    # Android moderno: accounts_ce.db suele contener token utilizable.
    modern_queries = [
        ("/data/system_ce/0/accounts_ce.db", "select password from accounts where type='com.google' limit 1"),
        ("/data/system_ce/0/accounts_ce.db", "select password from accounts where type like '%google%' limit 20"),
        ("/data/system_ce/0/accounts_ce.db", "select password from accounts limit 20"),
        ("/data/system_ce/0/accounts_ce.db", "select authtoken from authtokens limit 20"),
        ("/data/system_ce/0/accounts_ce.db", "select type,authtoken from authtokens limit 50"),
    ]
    for db, q in modern_queries:
        out = _run_query(db, q, timeout=12)
        if out and "error" not in out.lower() and "unable to open" not in out.lower():
            tok = _pick_token(out)
            if tok:
                return tok

    # Fallback legacy: gservices.db
    legacy_queries = [
        "select value from main where name='oauth2_4/com.google.android.gms'",
        "select value from main where name like 'oauth2%google%' limit 1",
        "select value from main where name='master_token' limit 1",
        "select name, value from main where name like '%token%' and length(value) > 50 limit 10",
    ]
    legacy_db = "/data/data/com.google.android.gms/databases/gservices.db"
    for q in legacy_queries:
        out = _run_query(legacy_db, q, timeout=12)
        if not out or "error" in out.lower() or "unable to open" in out.lower():
            continue
        tok = _pick_token(out)
        if tok:
            return tok
    return None


def _try_dumpsys(serial: str, email: str) -> str | None:
    out, _ = _adb(serial, "shell", "dumpsys", "account", timeout=25)
    if not out:
        return None

    lines = out.splitlines()
    for i, line in enumerate(lines):
        if email.lower() not in line.lower():
            continue
        window = lines[i:i + 40]
        for wline in window:
            m = re.search(r'(?:authtoken|token)\s*[=:]\s*([A-Za-z0-9_/\-+]{30,})', wline, re.I)
            if m:
                return m.group(1)
    return None


def _try_gsf_provider(serial: str) -> str | None:
    # Este método suele no funcionar en dispositivos físicos modernos por permisos.
    # Se mantiene por compatibilidad, pero no se considera confiable.
    cmd = (
        "content query "
        "--uri content://com.google.android.gsf.gservices "
        "--where \"name='oauth2:https://www.googleapis.com/auth/androidmarket'\""
    )
    out, _ = _adb(serial, "shell", cmd, timeout=12)
    if not out or "value=" not in out:
        return None
    m = re.search(r"value=([A-Za-z0-9_./\-+]{30,})", out)
    return m.group(1) if m else None


def _is_emulator(serial: str) -> bool:
    if serial.startswith("emulator-"):
        return True
    out, _ = _adb(serial, "shell", "getprop", "ro.kernel.qemu")
    return out.strip() == "1"


def _has_su_root(serial: str) -> bool:
    out, code = _adb(serial, "shell", "su", "-c", "id", timeout=8)
    return code == 0 and "uid=0" in out


def _get_aas_token(email: str, oauth_token: str) -> str | None:
    if oauth_token.startswith("aas_et/"):
        return oauth_token

    # Algunos dispositivos rooteados almacenan master tokens que empiezan con V1.
    # En ese caso, primero intentamos convertirlo directamente a AAS.
    if oauth_token.startswith("V1"):
        v1_candidates = [oauth_token]
        # En algunos dumps aparece como "V1:...,..."; probamos también la parte previa a la coma.
        if "," in oauth_token:
            v1_candidates.append(oauth_token.split(",", 1)[0].strip())
        for idx, v1 in enumerate(v1_candidates, 1):
            print(t("et_diag_v1", idx=idx, total=len(v1_candidates)))
            aas = _master_token_to_aas(email, v1)
            if aas:
                return aas

    tmp_dir = Path("/tmp/apk_token_probe")
    tmp_dir.mkdir(exist_ok=True)

    cmd = [
        "apkeep",
        "-a", "com.google.android.gm",
        "-d", "google-play",
        "-e", email,
        "--oauth-token", oauth_token,
        "--accept-tos",
        str(tmp_dir),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=70)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    output = result.stdout + result.stderr
    if result.returncode != 0:
        print(t("et_diag_apkeep_fail", code=result.returncode))
        for line in output.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()
            if any(k in low for k in ("error", "bad", "auth", "forbidden", "needsbrowser", "captcha", "denied")):
                print(t("et_diag_apkeep_line", line=s))
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("aas_et/"):
            return line
        if "aas_et/" in line:
            idx = line.index("aas_et/")
            return line[idx:].split()[0].rstrip("'\"")
    return None


def _master_token_to_aas(email: str, master_token: str) -> str | None:
    """Convierte un master token (ej. prefijo V1...) a aas_et/* usando endpoint Android auth."""
    url = "https://android.googleapis.com/auth"
    headers = {
        "User-Agent": "GoogleAuth/1.4 (generic_x86 APQ8064; Print/N2G48H)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "Email": email,
        "EncryptedPasswd": master_token,
        "service": "ac2dm",
        "accountType": "HOSTED_OR_GOOGLE",
        "has_permission": "1",
        "add_account": "1",
        "ACCESS_TOKEN": "1",
        "app": "com.google.android.gms",
        "client_sig": "38918a453d07199354f8b19af05ec6562ced5788",
        "callerPkg": "com.google.android.gms",
        "callerSig": "38918a453d07199354f8b19af05ec6562ced5788",
        "sdk_version": "34",
        "device_country": "us",
        "operatorCountry": "us",
        "lang": "en",
    }

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=20)
    except requests.RequestException:
        print(t("et_diag_auth_timeout"))
        return None

    token = None
    diag_lines: list[str] = []
    for line in resp.text.splitlines():
        s = line.strip()
        if s.startswith(("Error=", "Info=", "Url=", "NeedsBrowser=")):
            diag_lines.append(s)
        if line.startswith("Token="):
            token = line[6:].strip()
            break
        if line.startswith("Auth="):
            token = line[5:].strip()
            break

    if not token:
        if diag_lines:
            for s in diag_lines:
                print(t("et_diag_auth_line", line=s))
        else:
            print(t("et_diag_auth_no_token", status=resp.status_code))
        return None

    if token.startswith("aas_et/"):
        return token
    if token.startswith("oauth2_4/"):
        return "aas_et/" + token[9:]
    return "aas_et/" + token


def _extract_oauth_token(
    serial: str,
    email: str,
    method: str,
    interactive: bool,
) -> str | None:
    if method == "auto":
        # Siempre intentamos root primero: si no hay permisos, _try_root_database
        # devuelve None y el flujo continúa con dumpsys/gsf.
        methods = ["root", "dumpsys", "gsf"]
    else:
        methods = [method]

    for m in methods:
        print(t("et_trying_method", method=m))
        token = None
        if m == "root":
            token = _try_root_database(serial)
        elif m == "dumpsys":
            token = _try_dumpsys(serial, email)
        elif m == "gsf":
            token = _try_gsf_provider(serial)

        if token:
            return token

        print(t("et_no_token_method"))
        if interactive and method == "auto":
            _pause(t("et_next_method"), interactive)

    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=t("et_argparse_desc"))
    parser.add_argument("--config", default="config.yaml", help=t("et_arg_config"))
    parser.add_argument("--serial", default=None, help=t("et_arg_serial"))
    parser.add_argument("--email", default=None, help=t("et_arg_email"))
    parser.add_argument("--method", default="auto", choices=["auto", "root", "dumpsys", "gsf"],
                        help=t("et_arg_method"))
    parser.add_argument("--no-interactive", action="store_true", help=t("et_arg_no_interactive"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    interactive = not args.no_interactive
    config_path = Path(args.config)

    print(t("et_header"))

    email = _load_email(config_path, args.email)
    serial = _select_device(args.serial, interactive)
    model, _ = _adb(serial, "shell", "getprop", "ro.product.model")
    print(t("et_device_info", serial=serial, model=model.strip() or t("et_unknown_model")))
    android_id = _get_android_id(serial)
    print(t("et_android_id", android_id=android_id or "N/A"))

    if interactive:
        _device_instructions()
        _pause(t("et_press_enter"), interactive)

    token = _extract_oauth_token(serial, email, args.method, interactive)
    if not token:
        print(t("et_no_auto_token"))
        print(t("et_suggestions"))
        print(t("et_sugg1"))
        print(t("et_sugg2"))
        print(t("et_sugg3"))
        sys.exit(1)

    print(t("et_intermediate_token", token=token[:24]))
    aas_token = _get_aas_token(email, token)
    if not aas_token:
        print(t("et_err_apkeep_convert"))
        print(t("et_verify_apkeep"))
        sys.exit(1)

    _save_aas_token(config_path, email, aas_token)
    print(t("et_aas_saved", path=config_path))
    print(t("et_ready"))


if __name__ == "__main__":
    main()
