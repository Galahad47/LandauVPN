import base64
import csv
import hashlib
import json
import os
import platform
import queue
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import customtkinter as ctk
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# ================== НАСТРОЙКИ И ПУТИ ==================
APP_NAME = "LandauVPN"
REQUEST_TIMEOUT = 20
FREE_VPN_LIMIT = 50


def project_dir() -> Path:
    """Директория, где лежит скрипт или .exe (поддержка PyInstaller)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    if "__file__" in globals():
        return Path(__file__).resolve().parent
    return Path.cwd()


BASE_DIR = project_dir()
CONFIG_DIR = Path.home() / f".{APP_NAME}"
VPN_DOWNLOAD_DIR = CONFIG_DIR / "profiles"
AUTH_FILE = CONFIG_DIR / "auth.json"
VPN_PROFILES_FILE = CONFIG_DIR / "vpn_profiles.json"

# Поиск vpn_servers.json (работает и из IDE, и из собранного .exe)
FREE_VPN_JSON_CANDIDATES = [
    BASE_DIR / "vpn_servers.json",
    Path.cwd() / "vpn_servers.json",
    CONFIG_DIR / "vpn_servers.json",
]
FREE_VPN_JSON_FILE = next(
    (p for p in FREE_VPN_JSON_CANDIDATES if p.exists()),
    FREE_VPN_JSON_CANDIDATES[0],  # создастся при первом сохранении
)

VPN_GATE_API = "https://www.vpngate.net/api/iphone/"

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = ""

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
VPN_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ================== АВТОРИЗАЦИЯ ==================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def save_admin_auth(username: str, password: str) -> None:
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


# ================== МОДЕЛЬ ==================
@dataclass
class VPNProfile:
    name: str
    kind: str          # openvpn | wireguard | vpngate
    source: str        # путь, URL или vpngate://host|ip
    local_path: str = ""
    enabled: bool = True
    note: str = ""


def is_url(text: str) -> bool:
    try:
        u = urlparse(text.strip())
        return u.scheme in ("http", "https") and bool(u.netloc)
    except Exception:
        return False


def is_vpngate_ref(text: str) -> bool:
    return text.startswith("vpngate://")


def parse_vpngate_ref(ref: str) -> Tuple[str, str]:
    raw = ref.replace("vpngate://", "", 1).strip()
    if "|" in raw:
        host, ip = raw.split("|", 1)
        return host.strip(), ip.strip()
    return raw, ""


def safe_filename(text: str) -> str:
    cleaned = "".join(c for c in text if c.isalnum() or c in ("_", "-", " ")).strip().replace(" ", "_")
    return cleaned or "vpn_profile"


def load_profiles(path: Path = VPN_PROFILES_FILE) -> List[VPNProfile]:
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


def save_profiles(profiles: List[VPNProfile], path: Path = VPN_PROFILES_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(p) for p in profiles], f, ensure_ascii=False, indent=2)


# ================== VPNGATE ==================
def _to_int(x, default: int = 0) -> int:
    try:
        return int(float(str(x).strip()))
    except Exception:
        return default


def _score_tuple(item: dict) -> Tuple[int, int, int]:
    return (_to_int(item.get("score")), -_to_int(item.get("ping"), 9999), _to_int(item.get("speed")))


def _parse_vpngate_csv_lines(text: str) -> List[dict]:
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


# ================== КОНТРОЛЛЕР VPN ==================
class VPNController:
    def __init__(self, log_func):
        self.proc: Optional[subprocess.Popen] = None
        self.current_profile: Optional[VPNProfile] = None
        self.log = log_func

    def _fetch_live_vpngate_servers(self) -> List[dict]:
        r = requests.get(VPN_GATE_API, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return _parse_vpngate_csv_lines(r.text)

    def _download_profile_if_needed(self, profile: VPNProfile) -> str:
        if profile.local_path and os.path.exists(profile.local_path):
            return profile.local_path

        if not is_url(profile.source) and not is_vpngate_ref(profile.source):
            if os.path.exists(profile.source):
                profile.local_path = profile.source
                return profile.local_path
            raise FileNotFoundError(f"Файл профиля не найден: {profile.source}")

        if is_url(profile.source):
            ext = ".ovpn" if profile.kind in ("openvpn", "vpngate") else ".conf"
            local_path = VPN_DOWNLOAD_DIR / f"{safe_filename(profile.name)}{ext}"
            self.log(f"Скачивание конфига: {profile.source}")
            r = requests.get(profile.source, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            with open(local_path, "wb") as f:
                f.write(r.content)
            profile.local_path = str(local_path)
            return profile.local_path

        if is_vpngate_ref(profile.source):
            wanted_host, wanted_ip = parse_vpngate_ref(profile.source)
            servers = self._fetch_live_vpngate_servers()
            chosen = None
            for s in servers:
                if wanted_host and s["hostname"] == wanted_host or wanted_ip and s["ip"] == wanted_ip:
                    chosen = s
                    break
            if not chosen:
                if not servers:
                    raise RuntimeError("VPNGate список пуст")
                self.log("VPNGate профиль не найден → берём первый доступный")
                chosen = servers[0]

            ovpn_data = base64.b64decode(chosen["config_b64"]).decode("utf-8", errors="replace")
            local_path = VPN_DOWNLOAD_DIR / f"{safe_filename(profile.name)}.ovpn"
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(ovpn_data)
            profile.local_path = str(local_path)
            self.log(f"VPNGate профиль готов: {chosen['hostname']} ({chosen['ip']})")
            return profile.local_path

        raise ValueError(f"Неизвестный источник профиля: {profile.source}")

    def _build_command(self, profile: VPNProfile, config_path: str) -> List[str]:
        system = platform.system()
        if profile.kind in ("openvpn", "vpngate"):
            if system == "Windows":
                return ["openvpn", "--config", config_path]
            return ["sudo", "openvpn", "--config", config_path]

        if profile.kind == "wireguard":
            if system == "Windows":
                return ["wireguard", "/installtunnelservice", config_path]
            return ["sudo", "wg-quick", "up", config_path]

        raise ValueError(f"Неизвестный тип VPN: {profile.kind}")

    def _disconnect_wireguard(self) -> None:
        """Специальная команда отключения WireGuard (сервис / wg-quick down)."""
        if not self.current_profile or not self.current_profile.local_path:
            return
        config_path = self.current_profile.local_path
        system = platform.system()

        if system == "Windows":
            tunnel_name = Path(config_path).stem
            cmd = ["wireguard", "/uninstalltunnelservice", tunnel_name]
        else:
            cmd = ["sudo", "wg-quick", "down", config_path]

        try:
            self.log(f"Отключение WireGuard: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            output = result.stdout.strip() or result.stderr.strip() or "OK"
            self.log(f"WireGuard down: {output}")
        except Exception as e:
            self.log(f"Ошибка отключения WireGuard: {e}")

    def start(self, profile: VPNProfile):
        if self.proc and self.proc.poll() is None:
            raise RuntimeError("VPN уже запущен")

        config_path = self._download_profile_if_needed(profile)
        cmd = self._build_command(profile, config_path)

        self.log(f"Запуск: {' '.join(cmd)}")
        self.current_profile = profile

        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
        return self.proc

    def stop(self):
        """Универсальная остановка с учётом типа VPN."""
        if self.current_profile and self.current_profile.kind == "wireguard":
            self._disconnect_wireguard()

        if not self.proc or self.proc.poll() is not None:
            self.proc = None
            self.current_profile = None
            return

        # OpenVPN / VPNGate
        try:
            self.proc.terminate()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

        self.log("VPN остановлен (OpenVPN)")
        self.proc = None
        self.current_profile = None


# ================== GUI ==================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class MasterApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"🛡️ {APP_NAME} — Admin VPN Manager")
        self.geometry("1260x860")
        self.minsize(1140, 780)

        self.ui_queue: queue.Queue = queue.Queue()
        self.vpn = VPNController(self._queue_log)

        self.custom_profiles: List[VPNProfile] = load_profiles()
        self.free_profiles: List[VPNProfile] = []  # загрузим позже
        self._profile_lock = threading.Lock()
        self._pending_logs: List[str] = []
        self._connected_profile: Optional[VPNProfile] = None

        self.show_login()
        self.after(80, self._process_ui_queue)

    # ---------- Очередь UI ----------
    def _queue_log(self, msg: str):
        self.ui_queue.put(("log", msg))

    def _queue_status(self, msg: str, color: str = "gray"):
        self.ui_queue.put(("status", msg, color))

    def _queue_free_status(self, msg: str, color: str = "gray"):
        self.ui_queue.put(("free_status", msg, color))

    def _process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                kind = item[0]
                if kind == "log" and hasattr(self, "log_text"):
                    self._append_log(item[1])
                elif kind == "status" and hasattr(self, "status_bar"):
                    self.status_bar.configure(text=item[1], text_color=item[2])
                elif kind == "free_status" and hasattr(self, "free_status_label"):
                    self.free_status_label.configure(text=item[1], text_color=item[2])
        except queue.Empty:
            pass
        self.after(80, self._process_ui_queue)

    def _append_log(self, message: str):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} {message}\n")
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)

    def log(self, message: str):
        self._queue_log(message)

    # ---------- Логин ----------
    def show_login(self):
        self.login_frame = ctk.CTkFrame(self)
        self.login_frame.pack(fill="both", expand=True, padx=40, pady=40)

        ctk.CTkLabel(self.login_frame, text="MASTER ДОСТУП", font=ctk.CTkFont(size=28, weight="bold")).pack(pady=20)
        ctk.CTkLabel(
            self.login_frame,
            text="Логин и пароль хранятся в auth.json",
            font=ctk.CTkFont(size=13),
            text_color="gray",
        ).pack(pady=(0, 10))

        self.login_user = ctk.CTkEntry(self.login_frame, placeholder_text="Логин", width=320)
        self.login_user.pack(pady=10)
        saved_user, _ = load_admin_auth()
        self.login_user.insert(0, saved_user)

        self.login_pass = ctk.CTkEntry(self.login_frame, placeholder_text="Пароль", width=320, show="*")
        self.login_pass.pack(pady=10)
        self.login_pass.bind("<Return>", lambda e: self.check_master_login())

        ctk.CTkButton(self.login_frame, text="Войти", font=ctk.CTkFont(size=16), height=45, command=self.check_master_login).pack(pady=18)

    def check_master_login(self):
        saved_user, saved_hash = load_admin_auth()
        entered_user = self.login_user.get().strip()
        entered_pass = self.login_pass.get()

        if entered_user == saved_user and hash_password(entered_pass) == saved_hash:
            self.login_frame.destroy()
            self.create_main_interface()
        else:
            messagebox.showerror("Ошибка", "Неверный логин или пароль администратора")

    # ---------- Главный интерфейс ----------
    def create_main_interface(self):
        header = ctk.CTkFrame(self)
        header.pack(fill="x", padx=20, pady=(12, 8))
        ctk.CTkLabel(header, text="MASTER — Управление VPN профилями", font=ctk.CTkFont(size=24, weight="bold")).pack(
            side="left", padx=10, pady=8
        )
        ctk.CTkButton(header, text="Обновить бесплатные", command=self.refresh_free_from_web, width=170).pack(
            side="right", padx=8
        )
        ctk.CTkButton(header, text="Перечитать JSON", command=self.reload_free_from_json, width=150).pack(
            side="right", padx=8
        )

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=10)

        self.tab_profiles = self.tabview.add("🌐 VPN профили")
        self._create_profiles_tab()
        self.tab_free = self.tabview.add("🆓 Бесплатные VPN")
        self._create_free_tab()
        self.tab_add = self.tabview.add("➕ Добавить профиль")
        self._create_add_tab()
        self.tab_settings = self.tabview.add("⚙️ Настройки")
        self._create_settings_tab()

        self.log_text = scrolledtext.ScrolledText(self, height=7, state="disabled", bg="#2b2b2b", fg="white", font=("Consolas", 9))
        self.log_text.pack(fill="x", padx=20, pady=(0, 5))

        for msg in self._pending_logs:
            self._append_log(msg)
        self._pending_logs.clear()

        self.status_bar = ctk.CTkLabel(self, text="● Не подключено", font=ctk.CTkFont(size=14), text_color="gray")
        self.status_bar.pack(side="bottom", fill="x", padx=20, pady=8)

        self._append_log("Приложение запущено")
        self.reload_free_from_json()          # начальная загрузка бесплатных
        self._refresh_profiles_list()

    # ---------- Счётчики ----------
    def _update_counters(self):
        if hasattr(self, "profiles_counter_label"):
            total = len(self._visible_custom_profiles()) + len(self._visible_free_profiles())
            self.profiles_counter_label.configure(text=f"Всего профилей: {total}")
        if hasattr(self, "free_counter_label"):
            self.free_counter_label.configure(text=f"Бесплатных: {len(self.free_profiles)}")
        if hasattr(self, "custom_counter_label"):
            self.custom_counter_label.configure(text=f"Локальных: {len(self.custom_profiles)}")

    # ---------- Фильтры ----------
    def _visible_free_profiles(self) -> List[VPNProfile]:
        q = getattr(self, "free_search_var", tk.StringVar(value="")).get().strip().lower()
        if not q:
            return self.free_profiles[:]
        return [p for p in self.free_profiles if q in p.name.lower() or q in p.source.lower() or q in p.note.lower()]

    def _visible_custom_profiles(self) -> List[VPNProfile]:
        q = getattr(self, "custom_search_var", tk.StringVar(value="")).get().strip().lower()
        if not q:
            return self.custom_profiles[:]
        return [p for p in self.custom_profiles if q in p.name.lower() or q in p.source.lower() or q in p.note.lower()]

    def _reset_custom_search(self):
        self.custom_search_var.set("")
        self._refresh_profiles_list()

    def _reset_free_search(self):
        self.free_search_var.set("")
        self._refresh_free_list()

    # ---------- Вкладка "Все профили" ----------
    def _create_profiles_tab(self):
        frame = ctk.CTkFrame(self.tab_profiles)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        top = ctk.CTkFrame(frame)
        top.pack(fill="x", padx=4, pady=(4, 8))
        self.custom_search_var = tk.StringVar(value="")
        ctk.CTkLabel(top, text="Поиск:").pack(side="left", padx=6)
        ctk.CTkEntry(top, textvariable=self.custom_search_var, width=360, placeholder_text="name / ip / note").pack(
            side="left", padx=6
        )
        ctk.CTkButton(top, text="Фильтр", command=self._refresh_profiles_list).pack(side="left", padx=6)
        ctk.CTkButton(top, text="Сброс", command=self._reset_custom_search).pack(side="left", padx=6)
        self.custom_counter_label = ctk.CTkLabel(top, text="Локальных: 0", text_color="gray")
        self.custom_counter_label.pack(side="right", padx=8)

        left = ctk.CTkFrame(frame)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        ctk.CTkLabel(left, text="Список всех профилей", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=8)

        self.profile_listbox = tk.Listbox(left, bg="#343638", fg="white", selectbackground="#1f538d", height=18)
        self.profile_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.profile_listbox.bind("<Double-Button-1>", lambda e: self.connect_selected_profile())

        right = ctk.CTkFrame(frame, width=330)
        right.pack(side="right", fill="y")

        for text, cmd in [
            ("Обновить список", self._refresh_profiles_list),
            ("Подключить выбранный", self.connect_selected_profile),
            ("Отключить VPN", self.disconnect_vpn),
            ("Удалить профиль", self.delete_selected_profile),
            ("Вкл/выкл профиль", self.toggle_selected_profile),
            ("Проверить выбранные", self.test_profiles_parallel),
            ("Открыть папку профилей", self.open_profiles_folder),
        ]:
            ctk.CTkButton(right, text=text, command=cmd).pack(fill="x", padx=10, pady=3)

        self.profiles_counter_label = ctk.CTkLabel(right, text="Всего профилей: 0", text_color="gray")
        self.profiles_counter_label.pack(anchor="w", padx=12, pady=(14, 4))

    def _refresh_profiles_list(self):
        if not hasattr(self, "profile_listbox"):
            return
        visible = self._visible_free_profiles() + self._visible_custom_profiles()
        self.profile_listbox.delete(0, tk.END)
        for p in visible:
            state = "on" if p.enabled else "off"
            src = p.local_path if p.local_path else p.source
            note = f" | {p.note}" if p.note else ""
            self.profile_listbox.insert(tk.END, f"[{state}] {p.name} — {p.kind} — {src}{note}")
        self._update_counters()

    def _selected_profile(self) -> Optional[VPNProfile]:
        sel = self.profile_listbox.curselection()
        if not sel:
            return None
        idx = sel[0]
        visible = self._visible_free_profiles() + self._visible_custom_profiles()
        return visible[idx] if 0 <= idx < len(visible) else None

    # ---------- Подключение ----------
    def connect_selected_profile(self):
        profile = self._selected_profile()
        if not profile:
            messagebox.showwarning("Внимание", "Выберите профиль")
            return
        if not profile.enabled:
            messagebox.showwarning("Внимание", "Профиль отключен")
            return
        threading.Thread(target=lambda: self._connect_profile_worker(profile), daemon=True).start()

    def _monitor_vpn_output(self):
        """Мониторинг вывода процесса (разный для OpenVPN и WireGuard)."""
        proc = self.vpn.proc
        if not proc or not proc.stdout:
            self._queue_log("[VPN] Нет вывода процесса")
            return

        profile = self.vpn.current_profile
        if profile and profile.kind == "wireguard":
            # WireGuard сразу настраивается и процесс завершается
            self._queue_status("● VPN активен (WireGuard)", "lime")
            try:
                for line in proc.stdout:
                    msg = line.strip()
                    if msg:
                        self._queue_log(f"[WG] {msg}")
                rc = proc.wait()
                self._queue_log(f"WireGuard настройка завершена, код: {rc}")
            except Exception as e:
                self._queue_log(f"Ошибка чтения WG: {e}")
            return  # НЕ переводим в "Не подключено"!

        # OpenVPN / VPNGate — процесс живёт до отключения
        try:
            for line in iter(proc.stdout.readline, ""):
                msg = line.strip()
                if not msg:
                    continue
                self._queue_log(f"[VPN] {msg}")
                if "Initialization Sequence Completed" in msg or "interface is up" in msg.lower():
                    self._queue_status("● VPN активен", "lime")
        except Exception as e:
            self._queue_log(f"Ошибка чтения вывода VPN: {e}")
        finally:
            rc = proc.wait() if proc else -1
            self._queue_log(f"VPN завершился, код: {rc}")
            self._queue_status("● Не подключено", "gray")
            self._connected_profile = None

    def _connect_profile_worker(self, profile: VPNProfile):
        try:
            self._connected_profile = profile
            self._queue_status("● Подключение...", "orange")
            self.vpn.start(profile)
            self._queue_log(f"Профиль выбран: {profile.name}")
            self._monitor_vpn_output()
        except Exception as e:
            self._queue_log(f"Ошибка запуска VPN: {e}")
            self._queue_status("● Ошибка подключения", "red")

    def disconnect_vpn(self):
        try:
            self.vpn.stop()
            self._queue_status("● Не подключено", "gray")
            self._connected_profile = None
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def delete_selected_profile(self):
        profile = self._selected_profile()
        if not profile:
            return
        if profile.source.startswith("vpngate://"):
            messagebox.showwarning("Внимание", "Встроенный бесплатный профиль нельзя удалить")
            return
        if messagebox.askyesno("Удаление", f"Удалить профиль '{profile.name}'?"):
            self.custom_profiles = [p for p in self.custom_profiles if p is not profile]
            save_profiles(self.custom_profiles)
            self._refresh_profiles_list()
            self._append_log(f"Профиль удалён: {profile.name}")

    def toggle_selected_profile(self):
        profile = self._selected_profile()
        if not profile:
            return
        profile.enabled = not profile.enabled
        save_profiles(self.custom_profiles)
        self._refresh_profiles_list()
        self._append_log(f"Профиль {'включён' if profile.enabled else 'выключен'}: {profile.name}")

    def test_profiles_parallel(self):
        profiles = [p for p in (self._visible_free_profiles() + self._visible_custom_profiles()) if p.enabled]
        if not profiles:
            messagebox.showinfo("Информация", "Нет профилей для проверки")
            return

        def worker():
            self._queue_status("● Параллельная проверка...", "orange")
            with ThreadPoolExecutor(max_workers=8) as ex:
                futures = [ex.submit(self._can_materialize_profile, p) for p in profiles[:20]]
                results = [fut.result() for fut in as_completed(futures)]
            ok = sum(1 for _, ok in results if ok)
            self._queue_log(f"Проверка завершена: {ok}/{len(results)}")
            self._queue_status("● Проверка завершена", "lime" if ok else "red")

        threading.Thread(target=worker, daemon=True).start()

    def _can_materialize_profile(self, profile: VPNProfile) -> Tuple[str, bool]:
        try:
            if profile.kind == "vpngate":
                host, ip = parse_vpngate_ref(profile.source)
                servers = self.vpn._fetch_live_vpngate_servers()
                return profile.name, any(
                    (host and s["hostname"] == host) or (ip and s["ip"] == ip) for s in servers
                )
            if is_url(profile.source):
                return profile.name, True
            return profile.name, os.path.exists(profile.source)
        except Exception:
            return profile.name, False

    # ---------- Вкладка "Бесплатные VPN" ----------
    def _create_free_tab(self):
        frame = ctk.CTkFrame(self.tab_free)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        top = ctk.CTkFrame(frame)
        top.pack(fill="x", pady=5)
        self.free_search_var = tk.StringVar(value="")
        ctk.CTkLabel(top, text="Поиск:").pack(side="left", padx=8)
        ctk.CTkEntry(top, textvariable=self.free_search_var, width=300, placeholder_text="country / host / ip / note").pack(
            side="left", padx=6
        )
        ctk.CTkButton(top, text="Фильтр", command=self._refresh_free_list).pack(side="left", padx=6)
        ctk.CTkButton(top, text="Сброс", command=self._reset_free_search).pack(side="left", padx=6)
        ctk.CTkButton(top, text="Обновить из VPNGate", command=self.refresh_free_from_web).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Перечитать JSON", command=self.reload_free_from_json).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Подключить выбранный", command=self.connect_selected_free).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Лучший бесплатный VPN", command=self.connect_best_free).pack(side="left", padx=8)

        self.free_counter_label = ctk.CTkLabel(top, text="Бесплатных: 0", text_color="gray")
        self.free_counter_label.pack(side="right", padx=8)

        mid = ctk.CTkFrame(frame)
        mid.pack(fill="both", expand=True, pady=8)
        self.free_listbox = tk.Listbox(mid, bg="#343638", fg="white", selectbackground="#1f538d", height=18)
        self.free_listbox.pack(side="left", fill="both", expand=True)
        self.free_listbox.bind("<Double-Button-1>", lambda e: self.connect_selected_free())

        scrollbar = ctk.CTkScrollbar(mid, command=self.free_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.free_listbox.config(yscrollcommand=scrollbar.set)

        bottom = ctk.CTkFrame(frame)
        bottom.pack(fill="x", pady=5)
        self.free_status_label = ctk.CTkLabel(bottom, text="Статус пула: готов", font=ctk.CTkFont(size=13), text_color="gray")
        self.free_status_label.pack(side="left", padx=8)

    def _refresh_free_list(self):
        if not hasattr(self, "free_listbox"):
            return
        visible = self._visible_free_profiles()
        self.free_listbox.delete(0, tk.END)
        for p in visible:
            state = "on" if p.enabled else "off"
            self.free_listbox.insert(tk.END, f"[{state}] {p.name} — {p.source} | {p.note}")
        self._update_counters()
        self._queue_free_status(f"Статус пула: {len(visible)} показано из {len(self.free_profiles)}", "gray")

    def reload_free_from_json(self):
        def worker():
            try:
                self._queue_free_status("Статус пула: загрузка JSON...", "orange")
                with self._profile_lock:
                    # ИСПРАВЛЕНО: убран бессмысленный условный оператор
                    self.free_profiles = load_free_profiles_from_json()
                self._refresh_free_list()
                # ДОБАВЛЕНО: обновление общего списка профилей
                self._refresh_profiles_list()
                self._queue_free_status(f"Статус пула: {len(self.free_profiles)} серверов", "lime")
                self._queue_log(f"JSON перечитан: {len(self.free_profiles)} бесплатных профилей")
            except Exception as e:
                self._queue_free_status("Статус пула: ошибка", "red")
                self._queue_log(f"Ошибка чтения JSON: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def refresh_free_from_web(self):
        def worker():
            try:
                self._queue_free_status("Статус пула: обновление из VPNGate...", "orange")
                free_profiles = fetch_vpngate_profiles(FREE_VPN_LIMIT)
                save_free_profiles_json(free_profiles)
                with self._profile_lock:
                    self.free_profiles = free_profiles
                self._refresh_free_list()
                # ДОБАВЛЕНО: обновление общего списка профилей
                self._refresh_profiles_list()
                self._queue_free_status(f"Статус пула: обновлено {len(free_profiles)}", "lime")
                self._queue_log(f"Бесплатный пул обновлён: {len(free_profiles)} профилей")
            except Exception as e:
                self._queue_free_status("Статус пула: ошибка", "red")
                self._queue_log(f"Ошибка обновления VPNGate: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def _selected_free(self) -> Optional[VPNProfile]:
        sel = self.free_listbox.curselection()
        if not sel:
            return None
        idx = sel[0]
        visible = self._visible_free_profiles()
        return visible[idx] if 0 <= idx < len(visible) else None

    def connect_selected_free(self):
        profile = self._selected_free()
        if not profile:
            messagebox.showwarning("Внимание", "Выберите бесплатный сервер")
            return
        threading.Thread(target=lambda: self._connect_profile_worker(profile), daemon=True).start()

    def connect_best_free(self):
        enabled = [p for p in self._visible_free_profiles() if p.enabled]
        if not enabled:
            messagebox.showwarning("Внимание", "Список пуст — сначала обновите бесплатные VPN")
            return
        threading.Thread(target=lambda: self._connect_profile_worker(enabled[0]), daemon=True).start()

    # ---------- Добавление профиля ----------
    def _create_add_tab(self):
        frame = ctk.CTkFrame(self.tab_add)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Новый VPN профиль", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        form = ctk.CTkFrame(frame)
        form.pack(fill="x", padx=10, pady=10)

        self.new_name = ctk.CTkEntry(form, placeholder_text="Имя профиля")
        self.new_name.pack(fill="x", padx=10, pady=8)

        self.new_kind = ctk.CTkComboBox(form, values=["openvpn", "wireguard", "vpngate"])
        self.new_kind.set("openvpn")
        self.new_kind.pack(fill="x", padx=10, pady=8)

        self.new_source = ctk.CTkEntry(form, placeholder_text="Путь к .ovpn/.conf, URL или vpngate://host|ip")
        self.new_source.pack(fill="x", padx=10, pady=8)

        btns = ctk.CTkFrame(frame)
        btns.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(btns, text="Выбрать файл", command=self.pick_profile_file).pack(side="left", padx=5)
        ctk.CTkButton(btns, text="Сохранить профиль", command=self.add_profile).pack(side="left", padx=5)
        ctk.CTkButton(btns, text="Открыть папку профилей", command=self.open_profiles_folder).pack(side="left", padx=5)

    def pick_profile_file(self):
        path = filedialog.askopenfilename(
            title="Выберите конфиг VPN",
            filetypes=[("VPN config", "*.ovpn *.conf"), ("All files", "*.*")],
        )
        if path:
            self.new_source.delete(0, tk.END)
            self.new_source.insert(0, path)

    def add_profile(self):
        name = self.new_name.get().strip()
        kind = self.new_kind.get().strip()
        source = self.new_source.get().strip()

        if not name or not kind or not source:
            messagebox.showerror("Ошибка", "Заполните все поля")
            return
        if kind not in ("openvpn", "wireguard", "vpngate"):
            messagebox.showerror("Ошибка", "Поддерживаются только openvpn, wireguard, vpngate")
            return
        if kind == "vpngate" and not is_vpngate_ref(source):
            messagebox.showerror("Ошибка", "Для VPNGate используйте формат vpngate://hostname|ip")
            return
        if kind != "vpngate" and not is_url(source) and not os.path.exists(source):
            messagebox.showerror("Ошибка", "Укажите корректный путь к файлу или URL")
            return

        profile = VPNProfile(name=name, kind=kind, source=source)
        with self._profile_lock:
            self.custom_profiles.append(profile)
            save_profiles(self.custom_profiles)

        self._refresh_profiles_list()
        self._refresh_free_list()
        self.new_name.delete(0, tk.END)
        self.new_source.delete(0, tk.END)
        self._append_log(f"Профиль добавлен: {name}")

    # ---------- Настройки ----------
    def _create_settings_tab(self):
        frame = ctk.CTkFrame(self.tab_settings)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Настройки администратора", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        self.new_user_entry = ctk.CTkEntry(frame, placeholder_text="Новый логин admin", width=320)
        self.new_user_entry.pack(pady=10)
        self.new_user_entry.insert(0, load_admin_auth()[0])

        self.new_pass_entry = ctk.CTkEntry(frame, placeholder_text="Новый пароль admin", width=320, show="*")
        self.new_pass_entry.pack(pady=10)

        ctk.CTkButton(frame, text="Сохранить новый пароль и логин", command=self.change_admin_credentials).pack(pady=6)
        ctk.CTkButton(frame, text="Обновить бесплатные VPN", command=self.refresh_free_from_web).pack(pady=6)
        ctk.CTkButton(frame, text="Открыть auth.json", command=self.open_auth_file).pack(pady=6)

        ctk.CTkLabel(
            frame,
            text="Все сетевые операции и запуск VPN выполняются в фоне.\nДля WireGuard/OpenVPN на Linux/macOS нужен sudo без пароля.",
            justify="left",
        ).pack(pady=14)

    def change_admin_credentials(self):
        username = self.new_user_entry.get().strip() or DEFAULT_ADMIN_USERNAME
        pwd = self.new_pass_entry.get().strip()
        if len(pwd) < 8:
            messagebox.showwarning("Внимание", "Пароль слишком короткий (минимум 8 символов)")
            return
        save_admin_auth(username, pwd)
        self.new_pass_entry.delete(0, tk.END)
        self._append_log("Учётные данные администратора обновлены")
        messagebox.showinfo("Готово", "Данные сохранены в auth.json")

    # ---------- Вспомогательные ----------
    def open_profiles_folder(self):
        try:
            path = str(VPN_DOWNLOAD_DIR)
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def open_auth_file(self):
        try:
            path = str(AUTH_FILE)
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ---------- Завершение ----------
    def on_closing(self):
        try:
            self.disconnect_vpn()
        except Exception:
            pass
        self.destroy()


# ================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ FREE VPN ==================
def load_free_profiles_from_json() -> List[VPNProfile]:
    if not FREE_VPN_JSON_FILE.exists():
        return []
    try:
        with open(FREE_VPN_JSON_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        rows = payload.get("profiles", payload if isinstance(payload, list) else [])
        return [VPNProfile(**x) for x in rows if isinstance(x, dict)]
    except Exception:
        return []


def save_free_profiles_json(profiles: List[VPNProfile]) -> None:
    payload = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "VPNGate public relay server list",
        "profiles": [asdict(p) for p in profiles],
    }
    with open(FREE_VPN_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


# ================== ЗАПУСК ==================
if __name__ == "__main__":
    app = MasterApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()