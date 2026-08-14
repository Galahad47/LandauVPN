import base64
import csv
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urlparse

APP_NAME = "LandauVPN"
REQUEST_TIMEOUT = 20
FREE_VPN_LIMIT = 50
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = ""


def project_dir() -> Path:
    """Возвращает директорию проекта"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    if "__file__" in globals():
        return Path(__file__).resolve().parent.parent
    return Path.cwd()


BASE_DIR = project_dir()
CONFIG_DIR = Path.home() / f".{APP_NAME}"
VPN_DOWNLOAD_DIR = CONFIG_DIR / "profiles"
AUTH_FILE = CONFIG_DIR / "auth.json"
VPN_PROFILES_FILE = CONFIG_DIR / "vpn_profiles.json"

FREE_VPN_JSON_CANDIDATES = [
    BASE_DIR / "vpn_servers.json",
    Path.cwd() / "vpn_servers.json",
    CONFIG_DIR / "vpn_servers.json",
]
FREE_VPN_JSON_FILE = next(
    (p for p in FREE_VPN_JSON_CANDIDATES if p.exists()),
    FREE_VPN_JSON_CANDIDATES[0],
)


def ensure_config_dirs():
    """Создаёт директории конфигурации"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    VPN_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)


def hash_password(password: str) -> str:
    """Хеширует пароль через SHA256"""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def save_admin_auth(username: str, password: str) -> None:
    """Сохраняет учётные данные администратора"""
    payload = {
        "admin_username": username,
        "admin_password_hash": hash_password(password),
    }
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(AUTH_FILE, 0o600)
    except Exception:
        pass


def load_admin_auth() -> Tuple[str, str]:
    """Загружает учётные данные администратора"""
    if not AUTH_FILE.exists():
        save_admin_auth(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD)
        return DEFAULT_ADMIN_USERNAME, hash_password(DEFAULT_ADMIN_PASSWORD)

    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        username = str(data.get("admin_username", DEFAULT_ADMIN_USERNAME)).strip() or DEFAULT_ADMIN_USERNAME
        password_hash = str(data.get("admin_password_hash", hash_password(DEFAULT_ADMIN_PASSWORD))).strip()
        return username, password_hash
    except Exception:
        save_admin_auth(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD)
        return DEFAULT_ADMIN_USERNAME, hash_password(DEFAULT_ADMIN_PASSWORD)


def load_profiles(path: Path = VPN_PROFILES_FILE) -> List["VPNProfile"]:
    """Загружает профили VPN из JSON файла"""
    from ..core.models import VPNProfile
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            raw = raw.get("profiles", [])
        return [VPNProfile(**x) for x in raw if isinstance(x, dict)]
    except Exception:
        return []


def save_profiles(profiles: List["VPNProfile"], path: Path = VPN_PROFILES_FILE) -> None:
    """Сохраняет профили VPN в JSON файл"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(p) for p in profiles], f, ensure_ascii=False, indent=2)


def _to_int(x, default: int = 0) -> int:
    """Преобразует значение в int"""
    try:
        return int(float(str(x).strip()))
    except Exception:
        return default


def _score_tuple(item: dict) -> Tuple[int, int, int]:
    """Возвращает ключ сортировки для серверов VPNGate"""
    return (_to_int(item.get("score")), -_to_int(item.get("ping"), 9999), _to_int(item.get("speed")))


def _parse_vpngate_csv_lines(text: str) -> List[dict]:
    """Парсит CSV ответ от VPNGate"""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("*")]
    rows: List[dict] = []
    for line in lines:
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if len(row) < 15:
            continue
        rows.append({
            "country": row[6].strip(),
            "hostname": row[0].strip(),
            "ip": row[1].strip(),
            "score": row[3].strip(),
            "ping": row[4].strip(),
            "speed": row[5].strip(),
            "config_b64": row[14].strip(),
        })
    return rows


def fetch_vpngate_profiles(limit: int = FREE_VPN_LIMIT) -> List["VPNProfile"]:
    """Получает профили VPNGate"""
    from ..core.models import VPNProfile
    import requests
    r = requests.get("https://www.vpngate.net/api/iphone/", timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    candidates = [s for s in _parse_vpngate_csv_lines(r.text) if s["hostname"] and s["ip"] and s["config_b64"]]
    candidates.sort(key=_score_tuple, reverse=True)
    chosen = candidates[:limit]

    profiles: List[VPNProfile] = []
    for idx, item in enumerate(chosen, start=1):
        profiles.append(
            VPNProfile(
                name=f"VPNGate {item['country']} #{idx} — {item['hostname']}",
                kind="vpngate",
                source=f"vpngate://{item['hostname']}|{item['ip']}",
                note=f"score {item['score']}, ping {item['ping']} ms, speed {item['speed']}",
            )
        )
    return profiles


def load_free_profiles_from_json() -> List["VPNProfile"]:
    """Загружает бесплатные профили из JSON"""
    from ..core.models import VPNProfile
    if not FREE_VPN_JSON_FILE.exists():
        return []
    try:
        with open(FREE_VPN_JSON_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            rows = payload.get("profiles", [])
        else:
            rows = []
        return [VPNProfile(**x) for x in rows if isinstance(x, dict)]
    except Exception:
        return []


def save_free_profiles_json(profiles: List["VPNProfile"]) -> None:
    """Сохраняет бесплатные профили в JSON"""
    payload = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "VPNGate public relay server list",
        "profiles": [asdict(p) for p in profiles],
    }
    with open(FREE_VPN_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
