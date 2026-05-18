"""
LandauVPN - Core Module
Модель данных и основные функции управления VPN профилями
"""

import base64
import csv
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import requests

# Константы
APP_NAME = "LandauVPN"
REQUEST_TIMEOUT = 20
FREE_VPN_LIMIT = 50
VPN_GATE_API = "https://www.vpngate.net/api/iphone/"


@dataclass
class VPNProfile:
    """Модель VPN профиля"""
    name: str
    kind: str          # openvpn | wireguard | vpngate
    source: str        # путь, URL или vpngate://host|ip
    local_path: str = ""
    enabled: bool = True
    note: str = ""


def is_url(text: str) -> bool:
    """Проверка является ли строка URL"""
    try:
        u = urlparse(text.strip())
        return u.scheme in ("http", "https") and bool(u.netloc)
    except Exception:
        return False


def is_vpngate_ref(text: str) -> bool:
    """Проверка является ли строка ссылкой на VPNGate"""
    return text.startswith("vpngate://")


def parse_vpngate_ref(ref: str) -> Tuple[str, str]:
    """Парсинг ссылки VPNGate"""
    raw = ref.replace("vpngate://", "", 1).strip()
    if "|" in raw:
        host, ip = raw.split("|", 1)
        return host.strip(), ip.strip()
    return raw, ""


def safe_filename(text: str) -> str:
    """Создание безопасного имени файла"""
    cleaned = "".join(c for c in text if c.isalnum() or c in ("_", "-", " ")).strip().replace(" ", "_")
    return cleaned or "vpn_profile"


def _to_int(x, default: int = 0) -> int:
    """Безопасное преобразование в int"""
    try:
        return int(float(str(x).strip()))
    except Exception:
        return default


def _score_tuple(item: dict) -> Tuple[int, int, int]:
    """Кортеж для сортировки серверов VPNGate"""
    return (_to_int(item.get("score")), -_to_int(item.get("ping"), 9999), _to_int(item.get("speed")))


def _parse_vpngate_csv_lines(text: str) -> List[dict]:
    """Парсинг CSV ответа от VPNGate"""
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


def fetch_vpngate_profiles(limit: int = FREE_VPN_LIMIT) -> List[VPNProfile]:
    """Получение списка бесплатных VPN профилей с VPNGate"""
    r = requests.get(VPN_GATE_API, timeout=REQUEST_TIMEOUT)
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


def load_profiles(path: Path) -> List[VPNProfile]:
    """Загрузка профилей из JSON файла"""
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


def save_profiles(profiles: List[VPNProfile], path: Path) -> None:
    """Сохранение профилей в JSON файл"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(p) for p in profiles], f, ensure_ascii=False, indent=2)


def load_free_profiles_from_json(path: Path) -> List[VPNProfile]:
    """Загрузка бесплатных профилей из JSON"""
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        rows = payload.get("profiles", payload if isinstance(payload, list) else [])
        return [VPNProfile(**x) for x in rows if isinstance(x, dict)]
    except Exception:
        return []


def save_free_profiles_json(profiles: List[VPNProfile], path: Path) -> None:
    """Сохранение бесплатных профилей в JSON"""
    import time
    payload = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "VPNGate public relay server list",
        "profiles": [asdict(p) for p in profiles],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
