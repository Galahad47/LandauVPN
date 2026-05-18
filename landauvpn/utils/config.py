"""
LandauVPN - Configuration Module
Настройки и пути приложения
"""

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Tuple

# Константы
APP_NAME = "LandauVPN"
REQUEST_TIMEOUT = 20
FREE_VPN_LIMIT = 50
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = ""


def project_dir() -> Path:
    """Директория, где лежит скрипт или .exe (поддержка PyInstaller)."""
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

# Поиск vpn_servers.json
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
    """Создание необходимых директорий"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    VPN_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ================== АВТОРИЗАЦИЯ ==================
def hash_password(password: str) -> str:
    """Хеширование пароля"""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def save_admin_auth(username: str, password: str) -> None:
    """Сохранение учётных данных администратора"""
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
    """Загрузка учётных данных администратора"""
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
