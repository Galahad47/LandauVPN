import base64
import csv
import hashlib
import json
import os
import platform
import queue
import subprocess
import sys
import tempfile
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
from tkinter import filedialog, messagebox, scrolledtext, ttk

# ================== SETTINGS ==================
APP_NAME = "UserVPNProxy"
REQUEST_TIMEOUT = 15
FREE_VPN_LIMIT = 50
VPN_GATE_API = "https://www.vpngate.net/api/iphone/"


def project_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    if "__file__" in globals():
        return Path(__file__).resolve().parent
    return Path.cwd()


BASE_DIR = project_dir()
CONFIG_DIR = Path.home() / f".{APP_NAME}"
AUTH_FILE = CONFIG_DIR / "auth.json"
USER_CONFIG_FILE = CONFIG_DIR / "user_config.json"
PROFILES_FILE = CONFIG_DIR / "profiles.json"
VPN_DOWNLOAD_DIR = CONFIG_DIR / "vpn_configs"
FREE_VPN_JSON_FILE = next(
    (p for p in [BASE_DIR / "vpn_servers.json", Path.cwd() / "vpn_servers.json", CONFIG_DIR / "vpn_servers.json"] if p.exists()),
    BASE_DIR / "vpn_servers.json",
)

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
VPN_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ================== DEFAULT CONFIG ==================
DEFAULT_AUTH = {
    "user_password": "UserConnect2026!",
}

DEFAULT_USER_CONFIG = {
    "preset_socks_ip": "YOUR.VPN.SERVER.IP",
    "preset_socks_port": 1080,
    "free_proxy_sources": [
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    ],
    "vpn_gate_api": VPN_GATE_API,
}

# ================== HELPERS ==================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


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
    return cleaned or "profile"


def safe_gui_call(widget, func, *args, **kwargs):
    try:
        widget.after(0, lambda: func(*args, **kwargs))
    except Exception:
        pass


def open_path(path: Path):
    if platform.system() == "Windows":
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif platform.system() == "Darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


# ================== CONFIG LOAD/SAVE ==================
def load_json_file(path: Path, default: dict) -> dict:
    if not path.exists():
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=4, ensure_ascii=False)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return default.copy()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Invalid config")
        result = default.copy()
        result.update(data)
        return result
    except Exception:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=4, ensure_ascii=False)
        return default.copy()


def load_auth() -> dict:
    auth = load_json_file(AUTH_FILE, DEFAULT_AUTH)
    if "user_password" not in auth:
        auth["user_password"] = DEFAULT_AUTH["user_password"]
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(auth, f, indent=4, ensure_ascii=False)
    return auth


def save_auth(new_password: str) -> None:
    payload = {"user_password": new_password}
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)
    try:
        os.chmod(AUTH_FILE, 0o600)
    except Exception:
        pass


def load_user_config() -> dict:
    return load_json_file(USER_CONFIG_FILE, DEFAULT_USER_CONFIG)


# ================== DATA MODEL ==================
@dataclass
class VPNProfile:
    name: str
    kind: str  # openvpn | wireguard | vpngate
    source: str
    local_path: str = ""
    enabled: bool = True
    note: str = ""


def load_profiles() -> List[VPNProfile]:
    if not PROFILES_FILE.exists():
        return []
    try:
        with open(PROFILES_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        rows = payload.get("profiles", payload if isinstance(payload, list) else [])
        result: List[VPNProfile] = []
        for item in rows:
            if isinstance(item, dict):
                try:
                    result.append(VPNProfile(**item))
                except Exception:
                    continue
        return result
    except Exception:
        return []


def save_profiles(profiles: List[VPNProfile]) -> None:
    payload = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "profiles": [asdict(p) for p in profiles],
    }
    with open(PROFILES_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def load_free_profiles_from_json() -> List[VPNProfile]:
    if not FREE_VPN_JSON_FILE.exists():
        return []
    try:
        with open(FREE_VPN_JSON_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        rows = payload.get("profiles", payload if isinstance(payload, list) else [])
        result: List[VPNProfile] = []
        for item in rows:
            if isinstance(item, dict):
                try:
                    result.append(VPNProfile(**item))
                except Exception:
                    continue
        return result
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


# ================== FREE VPN FETCH ==================
def _to_int(x, default=0):
    try:
        return int(float(str(x).strip()))
    except Exception:
        return default


def _score_tuple(item: dict) -> Tuple[int, int, int]:
    return (_to_int(item.get("score")), -_to_int(item.get("ping"), 9999), _to_int(item.get("speed")))


def _parse_vpngate_csv(text: str) -> List[dict]:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("*")]
    servers: List[dict] = []
    for line in lines:
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if len(row) < 15:
            continue
        servers.append(
            {
                "country": row[6].strip(),
                "hostname": row[0].strip(),
                "ip": row[1].strip(),
                "score": row[3].strip(),
                "ping": row[4].strip(),
                "speed": row[5].strip(),
                "config_b64": row[14].strip(),
            }
        )
    return servers


def fetch_vpngate_profiles(limit: int = FREE_VPN_LIMIT) -> List[VPNProfile]:
    r = requests.get(VPN_GATE_API, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    candidates = [s for s in _parse_vpngate_csv(r.text) if s["hostname"] and s["ip"] and s["config_b64"]]
    candidates.sort(key=_score_tuple, reverse=True)

    result: List[VPNProfile] = []
    for idx, item in enumerate(candidates[:limit], start=1):
        result.append(
            VPNProfile(
                name=f"VPNGate {item['country']} #{idx} — {item['hostname']}",
                kind="vpngate",
                source=f"vpngate://{item['hostname']}|{item['ip']}",
                note=f"score {item['score']}, ping {item['ping']} ms, speed {item['speed']}",
            )
        )
    return result


# ================== SOCKS5 HELPERS ==================
def check_socks5_proxy(proxy_str: str, timeout: int = 5) -> Tuple[bool, float]:
    try:
        proxies = {
            "http": f"socks5://{proxy_str}",
            "https": f"socks5://{proxy_str}",
        }
        start = time.time()
        r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=timeout)
        return r.status_code == 200, (time.time() - start) * 1000
    except Exception:
        return False, 0.0


# ================== VPN CONTROLLER ==================
class VPNController:
    def __init__(self, log_func):
        self.proc: Optional[subprocess.Popen] = None
        self.current_profile: Optional[VPNProfile] = None
        self.log = log_func

    def _fetch_live_vpngate_servers(self) -> List[dict]:
        r = requests.get(VPN_GATE_API, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return _parse_vpngate_csv(r.text)

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
                if wanted_host and s["hostname"] == wanted_host:
                    chosen = s
                    break
                if wanted_ip and s["ip"] == wanted_ip:
                    chosen = s
                    break
            if not chosen:
                if not servers:
                    raise RuntimeError("VPNGate список пуст")
                self.log("VPNGate профиль не найден, беру первый доступный сервер")
                chosen = servers[0]

            ovpn_data = base64.b64decode(chosen["config_b64"]).decode("utf-8", errors="replace")
            local_path = VPN_DOWNLOAD_DIR / f"{safe_filename(profile.name)}.ovpn"
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(ovpn_data)
            profile.local_path = str(local_path)
            self.log(f"VPNGate профиль готов: {chosen['hostname']} ({chosen['ip']})")
            return profile.local_path

        raise ValueError(f"Не удалось обработать источник профиля: {profile.source}")

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
        if not self.proc or self.proc.poll() is not None:
            return
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
        self.log("VPN остановлен")
        self.proc = None
        self.current_profile = None


# ================== GUI ==================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class UserApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"🔑 {APP_NAME} — VPN и Proxy")
        self.geometry("1120x780")
        self.minsize(1000, 680)

        self.auth = load_auth()
        self.config_data = load_user_config()
        self.free_proxy_sources = self.config_data.get("free_proxy_sources", DEFAULT_USER_CONFIG["free_proxy_sources"])
        self.preset_socks_ip = self.config_data.get("preset_socks_ip", DEFAULT_USER_CONFIG["preset_socks_ip"])
        self.preset_socks_port = int(self.config_data.get("preset_socks_port", DEFAULT_USER_CONFIG["preset_socks_port"]))
        self.vpn_gate_api = self.config_data.get("vpn_gate_api", VPN_GATE_API)

        self.current_proxy = None
        self.vpn_process: Optional[subprocess.Popen] = None
        self.ui_queue: queue.Queue = queue.Queue()
        self.vpn = VPNController(self.log)

        self.show_password_screen()
        self.after(100, self.process_ui_queue)

    # ---------- UI queue ----------
    def process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._append_log(item[1])
                elif kind == "status":
                    _, text, color = item
                    if hasattr(self, "status_bar"):
                        self.status_bar.configure(text=text, text_color=color)
                elif kind == "vpn_status":
                    _, text, color = item
                    if hasattr(self, "vpn_status_label"):
                        self.vpn_status_label.configure(text=text, text_color=color)
                elif kind == "preset_status":
                    _, text, color = item
                    if hasattr(self, "preset_status_label"):
                        self.preset_status_label.configure(text=text, text_color=color)
        except queue.Empty:
            pass
        self.after(100, self.process_ui_queue)

    def log(self, message: str):
        self.ui_queue.put(("log", message))

    def _append_log(self, message: str):
        if not hasattr(self, "log_text"):
            return
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')}  {message}\n")
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)

    # ---------- login ----------
    def show_password_screen(self):
        self.pass_frame = ctk.CTkFrame(self)
        self.pass_frame.pack(fill="both", expand=True, padx=50, pady=70)

        ctk.CTkLabel(self.pass_frame, text="ВХОД ДЛЯ ПОЛЬЗОВАТЕЛЯ", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=25)

        self.user_pass_entry = ctk.CTkEntry(self.pass_frame, placeholder_text="Пароль доступа", width=320, height=42, show="*")
        self.user_pass_entry.pack(pady=15)
        self.user_pass_entry.bind("<Return>", lambda e: self.check_user_password())

        ctk.CTkButton(self.pass_frame, text="Войти", font=ctk.CTkFont(size=17), height=46, command=self.check_user_password).pack(pady=18)

        ctk.CTkLabel(self.pass_frame, text="Пароль выдаёт администратор", font=ctk.CTkFont(size=12), text_color="gray").pack(pady=10)

    def check_user_password(self):
        if self.user_pass_entry.get() == self.auth["user_password"]:
            self.pass_frame.destroy()
            self.create_user_interface()
        else:
            messagebox.showerror("Ошибка доступа", "Неверный пароль")

    # ---------- main UI ----------
    def create_user_interface(self):
        header = ctk.CTkLabel(
            self,
            text=f"Подключение к вашему серверу\n{self.preset_socks_ip}:{self.preset_socks_port}",
            font=ctk.CTkFont(size=19, weight="bold"),
        )
        header.pack(pady=12)

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=6)

        self.tab_free_proxy = self.tabview.add("🌐 Бесплатные SOCKS5")
        self.create_free_proxy_tab()

        self.tab_free_vpn = self.tabview.add("🆓 Бесплатные VPN")
        self.create_free_vpn_tab()

        self.tab_preset = self.tabview.add("🔒 Ваш сервер")
        self.create_preset_vpn_tab()

        self.log_text = scrolledtext.ScrolledText(self, height=7, state="disabled", bg="#2b2b2b", fg="white", font=("Consolas", 9))
        self.log_text.pack(fill="x", padx=20, pady=(0, 6))

        self.status_bar = ctk.CTkLabel(self, text="● Не подключено", font=ctk.CTkFont(size=13), text_color="gray")
        self.status_bar.pack(side="bottom", fill="x", padx=20, pady=8)

        self.log("Доступ разрешён ✓")

    # ---------- helpers ----------
    def set_status(self, text: str, color: str = "gray"):
        self.ui_queue.put(("status", text, color))

    def set_vpn_status(self, text: str, color: str = "gray"):
        self.ui_queue.put(("vpn_status", text, color))

    def set_preset_status(self, text: str, color: str = "gray"):
        self.ui_queue.put(("preset_status", text, color))

    # ---------- proxy tab ----------
    def create_free_proxy_tab(self):
        frame = ctk.CTkFrame(self.tab_free_proxy)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        src_frame = ctk.CTkFrame(frame)
        src_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(src_frame, text="Источник списка:").pack(side="left", padx=5)

        self.proxy_source_combo = ctk.CTkComboBox(src_frame, values=self.free_proxy_sources, width=560)
        self.proxy_source_combo.pack(side="left", padx=5)
        if self.free_proxy_sources:
            self.proxy_source_combo.set(self.free_proxy_sources[0])

        ctk.CTkButton(src_frame, text="Загрузить", command=self.load_free_proxies).pack(side="left", padx=5)

        list_frame = ctk.CTkFrame(frame)
        list_frame.pack(fill="both", expand=True, pady=5)
        self.proxy_listbox = tk.Listbox(list_frame, bg="#343638", fg="white", selectbackground="#1f538d", height=12)
        self.proxy_listbox.pack(side="left", fill="both", expand=True)
        scrollbar = ctk.CTkScrollbar(list_frame, command=self.proxy_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.proxy_listbox.config(yscrollcommand=scrollbar.set)

        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(fill="x", pady=5)
        ctk.CTkButton(btn_frame, text="Проверить выбранный", command=self.test_selected_proxy).pack(side="left", padx=3)
        ctk.CTkButton(btn_frame, text="Проверить все", command=self.test_all_proxies).pack(side="left", padx=3)
        ctk.CTkButton(btn_frame, text="Подключить", command=self.apply_selected_proxy).pack(side="left", padx=3)
        ctk.CTkButton(btn_frame, text="Отключить", command=self.disable_proxy).pack(side="left", padx=3)

        self.proxy_progress = ctk.CTkProgressBar(frame)
        self.proxy_progress.pack(fill="x", pady=3)
        self.proxy_progress.set(0)

    def load_free_proxies(self):
        url = self.proxy_source_combo.get().strip()
        if not url:
            messagebox.showwarning("Внимание", "Выберите источник")
            return
        self.log(f"Загрузка прокси из {url}...")
        threading.Thread(target=self._fetch_proxies_thread, args=(url,), daemon=True).start()

    def _fetch_proxies_thread(self, url: str):
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            proxies = [line.strip() for line in r.text.splitlines() if line.strip() and ":" in line]

            def update_list():
                self.proxy_listbox.delete(0, tk.END)
                for p in proxies:
                    self.proxy_listbox.insert(tk.END, p)
                self.log(f"Загружено {len(proxies)} прокси")

            safe_gui_call(self, update_list)
        except Exception as e:
            self.log(f"Ошибка загрузки: {e}")

    def test_selected_proxy(self):
        sel = self.proxy_listbox.curselection()
        if not sel:
            messagebox.showwarning("Внимание", "Выберите прокси")
            return
        proxy = self.proxy_listbox.get(sel[0])
        self.log(f"Проверка {proxy}...")
        threading.Thread(target=self._test_single_proxy_thread, args=(proxy,), daemon=True).start()

    def _test_single_proxy_thread(self, proxy: str):
        works, latency = check_socks5_proxy(proxy)
        self.log(f"{'✅' if works else '❌'} {proxy}" + (f" — {latency:.1f} мс" if works else ""))

    def test_all_proxies(self):
        proxies = list(self.proxy_listbox.get(0, tk.END))
        if not proxies:
            messagebox.showinfo("Информация", "Список пуст")
            return
        self.log(f"Проверка {len(proxies)} прокси...")
        self.proxy_progress.set(0)
        threading.Thread(target=self._test_all_proxies_thread, args=(proxies,), daemon=True).start()

    def _test_all_proxies_thread(self, proxies: List[str]):
        working = []
        total = len(proxies)
        for i, proxy in enumerate(proxies):
            works, latency = check_socks5_proxy(proxy)
            if works:
                working.append(proxy)
                self.log(f"✅ {proxy} ({latency:.1f} мс)")
            else:
                self.log(f"❌ {proxy}")
            safe_gui_call(self, self.proxy_progress.set, (i + 1) / total)

        def update_list():
            self.proxy_listbox.delete(0, tk.END)
            for p in working:
                self.proxy_listbox.insert(tk.END, p)
            self.log(f"Готово. Рабочих: {len(working)} из {total}")
            self.proxy_progress.set(0)

        safe_gui_call(self, update_list)

    def apply_selected_proxy(self):
        sel = self.proxy_listbox.curselection()
        if not sel:
            messagebox.showwarning("Внимание", "Выберите прокси")
            return
        proxy = self.proxy_listbox.get(sel[0])
        # SOCKS5 прокси применяются только для текущего процесса приложения.
        os.environ["HTTP_PROXY"] = f"socks5://{proxy}"
        os.environ["HTTPS_PROXY"] = f"socks5://{proxy}"
        os.environ["ALL_PROXY"] = f"socks5://{proxy}"
        self.current_proxy = proxy
        self.status_bar.configure(text=f"● Прокси: {proxy}", text_color="lime")
        self.log(f"Подключен прокси {proxy}")

    def disable_proxy(self):
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
            os.environ.pop(var, None)
        self.current_proxy = None
        self.status_bar.configure(text="● Не подключено", text_color="gray")
        self.log("Прокси отключен")

    # ---------- VPN tab ----------
    def create_free_vpn_tab(self):
        frame = ctk.CTkFrame(self.tab_free_vpn)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Публичные OpenVPN серверы (VPNGate)", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=5)

        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(fill="x", pady=5)
        ctk.CTkButton(btn_frame, text="Загрузить список", command=self.load_vpngate_servers).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Подключиться", command=self.connect_selected_vpngate).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Отключить VPN", command=self.disconnect_vpn).pack(side="left", padx=5)

        tree_frame = ctk.CTkFrame(frame)
        tree_frame.pack(fill="both", expand=True, pady=5)

        columns = ("Country", "IP", "Score", "Ping", "Speed")
        self.vpn_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=11)
        for col in columns:
            self.vpn_tree.heading(col, text=col)
            self.vpn_tree.column(col, width=140, anchor="center")
        self.vpn_tree.pack(side="left", fill="both", expand=True)
        self.vpn_tree.bind("<Double-Button-1>", lambda e: self.connect_selected_vpngate())

        scrollbar = ctk.CTkScrollbar(tree_frame, command=self.vpn_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.vpn_tree.config(yscrollcommand=scrollbar.set)

        self.vpn_status_label = ctk.CTkLabel(frame, text="Статус VPN: не подключен", font=ctk.CTkFont(size=12), text_color="gray")
        self.vpn_status_label.pack(pady=5)

    def load_vpngate_servers(self):
        self.log("Загрузка списка серверов VPNGate...")
        threading.Thread(target=self._fetch_vpngate_thread, daemon=True).start()

    def _fetch_vpngate_thread(self):
        try:
            r = requests.get(self.vpn_gate_api, timeout=20)
            r.raise_for_status()
            lines = r.text.splitlines()
            servers = []
            for line in lines[1:]:
                if not line.strip() or line.startswith("*"):
                    continue
                parts = line.split(",")
                if len(parts) >= 15:
                    country = parts[6].strip()
                    ip = parts[1].strip()
                    score = parts[3].strip()
                    ping = parts[4].strip()
                    speed = parts[5].strip()
                    openvpn_config = parts[14].strip()
                    if ip and openvpn_config:
                        servers.append((country, ip, score, ping, speed, openvpn_config))

            def update_tree():
                self.vpn_tree.delete(*self.vpn_tree.get_children())
                for s in servers:
                    self.vpn_tree.insert("", "end", values=(s[0], s[1], s[2], s[3], s[4]), tags=(s[5],))
                self.log(f"Загружено {len(servers)} серверов")

            safe_gui_call(self, update_tree)
        except Exception as e:
            self.log(f"Ошибка парсинга VPNGate: {e}")

    def connect_selected_vpngate(self):
        sel = self.vpn_tree.selection()
        if not sel:
            messagebox.showwarning("Внимание", "Выберите сервер")
            return

        item = self.vpn_tree.item(sel[0])
        values = item.get("values", [])
        config_b64 = item.get("tags", [None])[0]
        if not config_b64:
            messagebox.showerror("Ошибка", "Нет конфигурации для этого сервера")
            return

        try:
            ovpn_data = base64.b64decode(config_b64).decode("utf-8", errors="replace")
        except Exception as e:
            self.log(f"Ошибка декодирования конфига: {e}")
            return

        temp_conf = os.path.join(tempfile.gettempdir(), "vpngate.ovpn")
        try:
            with open(temp_conf, "w", encoding="utf-8") as f:
                f.write(ovpn_data)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить конфиг:\n{e}")
            return

        self.log(f"Подключение к {values[1]} ({values[0]})...")
        self.start_openvpn(temp_conf)

    def start_openvpn(self, config_path: str):
        if self.vpn_process and self.vpn_process.poll() is None:
            self.disconnect_vpn()

        cmd = self.get_openvpn_command(config_path)
        self.log(f"Запуск OpenVPN: {' '.join(cmd)}")
        try:
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0
            self.vpn_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                creationflags=creationflags,
            )
            self.vpn_status_label.configure(text="Статус: подключается...", text_color="orange")
            threading.Thread(target=self._monitor_vpn_output, daemon=True).start()
        except Exception as e:
            self.log(f"Ошибка запуска VPN: {e}")
            messagebox.showerror("Ошибка", f"Не удалось запустить OpenVPN:\n{e}")

    def get_openvpn_command(self, config_path: str) -> List[str]:
        system = platform.system()
        if system == "Windows":
            return ["openvpn", "--config", config_path]
        return ["sudo", "openvpn", "--config", config_path]

    def _monitor_vpn_output(self):
        proc = self.vpn_process
        if not proc or not proc.stdout:
            return

        try:
            for line in iter(proc.stdout.readline, b""):
                decoded = line.decode(errors="replace").strip()
                if not decoded:
                    continue
                self.log(f"[VPN] {decoded}")
                if "Initialization Sequence Completed" in decoded:
                    self.set_vpn_status("Статус: подключен ✓", "lime")
                    self.set_status("● VPN активен", "lime")
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass

        rc = proc.wait()
        self.set_vpn_status("Статус: отключен", "gray")
        self.set_status("● Не подключено", "gray")
        self.log(f"VPN процесс завершился с кодом {rc}")

    def disconnect_vpn(self):
        if self.vpn_process and self.vpn_process.poll() is None:
            try:
                self.vpn_process.terminate()
                self.log("Отправлен сигнал завершения VPN")
                time.sleep(1)
                if self.vpn_process.poll() is None:
                    self.vpn_process.kill()
            except Exception as e:
                self.log(f"Ошибка остановки VPN: {e}")
            finally:
                self.vpn_process = None
        self.vpn_status_label.configure(text="Статус: отключен", text_color="gray")
        self.status_bar.configure(text="● Не подключено", text_color="gray")

    # ---------- preset proxy tab ----------
    def create_preset_vpn_tab(self):
        frame = ctk.CTkFrame(self.tab_preset)
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        ctk.CTkLabel(frame, text="Ваш преднастроенный SOCKS5 сервер", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        info_frame = ctk.CTkFrame(frame)
        info_frame.pack(pady=20)

        ctk.CTkLabel(info_frame, text="IP адрес:").grid(row=0, column=0, padx=10, pady=5)
        ip_entry = ctk.CTkEntry(info_frame, width=220)
        ip_entry.insert(0, self.preset_socks_ip)
        ip_entry.configure(state="disabled")
        ip_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(info_frame, text="Порт:").grid(row=1, column=0, padx=10, pady=5)
        port_entry = ctk.CTkEntry(info_frame, width=220)
        port_entry.insert(0, str(self.preset_socks_port))
        port_entry.configure(state="disabled")
        port_entry.grid(row=1, column=1, padx=10, pady=5)

        self.preset_status_label = ctk.CTkLabel(frame, text="", font=ctk.CTkFont(size=12), text_color="gray")
        self.preset_status_label.pack(pady=5)

        ctk.CTkButton(frame, text="Проверить и подключить", fg_color="green", height=40, command=self.connect_preset_proxy).pack(pady=20)
        ctk.CTkButton(frame, text="Отключить прокси", height=40, command=self.disable_proxy).pack(pady=5)

    def connect_preset_proxy(self):
        proxy_str = f"{self.preset_socks_ip}:{self.preset_socks_port}"
        self.log(f"Проверка предустановленного сервера {proxy_str}...")
        self.preset_status_label.configure(text="Проверка...", text_color="orange")
        threading.Thread(target=self._connect_preset_thread, args=(proxy_str,), daemon=True).start()

    def _connect_preset_thread(self, proxy_str: str):
        works, latency = check_socks5_proxy(proxy_str)
        if works:
            os.environ["HTTP_PROXY"] = f"socks5://{proxy_str}"
            os.environ["HTTPS_PROXY"] = f"socks5://{proxy_str}"
            os.environ["ALL_PROXY"] = f"socks5://{proxy_str}"
            self.current_proxy = proxy_str
            self.set_status(f"● Подключено к вашему серверу: {proxy_str}", "lime")
            self.log(f"✅ Успешно подключено к {proxy_str} ({latency:.1f} мс)")
            self.set_preset_status("Подключено ✓", "lime")
            self.show_instructions()
        else:
            self.log(f"❌ Сервер {proxy_str} недоступен")
            self.set_preset_status("Недоступен", "red")
            messagebox.showerror("Ошибка", "Ваш сервер временно недоступен. Попробуйте позже.")

    def disable_proxy(self):
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
            os.environ.pop(var, None)
        self.current_proxy = None
        self.status_bar.configure(text="● Не подключено", text_color="gray")
        self.log("Прокси отключен")

    def show_instructions(self):
        messagebox.showinfo(
            "Подключено",
            "Вы подключены к персональному прокси-серверу.\n\nДля отключения нажмите 'Отключить прокси'.",
        )

    # ---------- user profiles ----------
    def create_profiles_tab(self):
        frame = ctk.CTkFrame(self.tab_free_proxy)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        left = ctk.CTkFrame(frame)
        left.pack(fill="both", expand=True, side="left", padx=(0, 10))

        ctk.CTkLabel(left, text="Список профилей", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=8)
        self.profiles_search_var = tk.StringVar(value="")
        search_row = ctk.CTkFrame(left)
        search_row.pack(fill="x", padx=6, pady=(0, 6))
        ctk.CTkEntry(search_row, textvariable=self.profiles_search_var, placeholder_text="Поиск по профилям").pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(search_row, text="Фильтр", command=self.refresh_profiles_list).pack(side="left", padx=3)
        ctk.CTkButton(search_row, text="Сброс", command=self.reset_profiles_search).pack(side="left", padx=3)

        self.profile_listbox = tk.Listbox(left, bg="#343638", fg="white", selectbackground="#1f538d", height=14)
        self.profile_listbox.pack(fill="both", expand=True, padx=6, pady=5)
        self.profile_listbox.bind("<Double-Button-1>", lambda e: self.connect_selected_profile())

        right = ctk.CTkFrame(frame, width=300)
        right.pack(side="right", fill="y")
        ctk.CTkButton(right, text="Подключить выбранный", command=self.connect_selected_profile).pack(fill="x", padx=10, pady=(10, 5))
        ctk.CTkButton(right, text="Отключить VPN", command=self.disconnect_vpn).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(right, text="Удалить профиль", command=self.delete_selected_profile).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(right, text="Вкл/выкл профиль", command=self.toggle_selected_profile).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(right, text="Проверить выбранные", command=self.test_profiles_parallel).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(right, text="Открыть папку профилей", command=self.open_profiles_folder).pack(fill="x", padx=10, pady=5)

        self.profiles_counter_label = ctk.CTkLabel(right, text="Всего профилей: 0", text_color="gray")
        self.profiles_counter_label.pack(anchor="w", padx=12, pady=(12, 4))

    def _visible_profiles(self) -> List[VPNProfile]:
        q = self.profiles_search_var.get().strip().lower() if hasattr(self, "profiles_search_var") else ""
        profiles = self.free_profiles + self.custom_profiles
        if not q:
            return profiles
        return [p for p in profiles if q in p.name.lower() or q in p.source.lower() or q in p.note.lower()]

    def reset_profiles_search(self):
        self.profiles_search_var.set("")
        self.refresh_profiles_list()

    def refresh_profiles_list(self):
        if not hasattr(self, "profile_listbox"):
            return
        visible = self._visible_profiles()
        self.profile_listbox.delete(0, tk.END)
        for p in visible:
            state = "on" if p.enabled else "off"
            note = f" | {p.note}" if p.note else ""
            self.profile_listbox.insert(tk.END, f"[{state}] {p.name} — {p.kind} — {p.source}{note}")
        self.profiles_counter_label.configure(text=f"Всего профилей: {len(visible)}")

    def _selected_profile(self) -> Optional[VPNProfile]:
        sel = self.profile_listbox.curselection()
        if not sel:
            return None
        visible = self._visible_profiles()
        idx = sel[0]
        if idx < 0 or idx >= len(visible):
            return None
        return visible[idx]

    def connect_selected_profile(self):
        profile = self._selected_profile()
        if not profile:
            messagebox.showwarning("Внимание", "Выберите профиль")
            return
        if not profile.enabled:
            messagebox.showwarning("Внимание", "Профиль отключен")
            return

        def worker():
            try:
                self.set_status("● Подключение...", "orange")
                self.vpn.start(profile)
                self.log(f"Профиль выбран: {profile.name}")
                self._monitor_user_vpn_output()
            except Exception as e:
                self.log(f"Ошибка запуска VPN: {e}")
                self.set_status("● Ошибка подключения", "red")

        threading.Thread(target=worker, daemon=True).start()

    def _monitor_user_vpn_output(self):
        proc = self.vpn.proc
        if not proc or not proc.stdout:
            return
        try:
            for line in proc.stdout:
                msg = line.strip()
                if not msg:
                    continue
                self.log(f"[VPN] {msg}")
                if "Initialization Sequence Completed" in msg or "interface is up" in msg.lower():
                    self.set_vpn_status("Статус: подключен ✓", "lime")
                    self.set_status("● VPN активен", "lime")
        except Exception as e:
            self.log(f"Ошибка чтения вывода VPN: {e}")
        finally:
            try:
                rc = proc.wait()
            except Exception:
                rc = -1
            self.set_vpn_status("Статус: отключен", "gray")
            self.set_status("● Не подключено", "gray")
            self.log(f"VPN процесс завершился с кодом {rc}")

    def disconnect_vpn(self):
        if self.vpn_process and self.vpn_process.poll() is None:
            try:
                self.vpn_process.terminate()
                self.log("Отправлен сигнал завершения VPN")
                time.sleep(1)
                if self.vpn_process.poll() is None:
                    self.vpn_process.kill()
            except Exception as e:
                self.log(f"Ошибка остановки VPN: {e}")
            finally:
                self.vpn_process = None
        if self.vpn.proc and self.vpn.proc.poll() is None:
            self.vpn.stop()
        self.vpn_status_label.configure(text="Статус: отключен", text_color="gray")
        self.status_bar.configure(text="● Не подключено", text_color="gray")

    def delete_selected_profile(self):
        profile = self._selected_profile()
        if not profile:
            messagebox.showwarning("Внимание", "Выберите профиль")
            return
        if profile.source.startswith("vpngate://"):
            messagebox.showwarning("Внимание", "Встроенный бесплатный профиль нельзя удалить")
            return
        if messagebox.askyesno("Удаление", f"Удалить профиль '{profile.name}'?"):
            self.custom_profiles = [p for p in self.custom_profiles if p is not profile]
            save_profiles(self.custom_profiles)
            self.refresh_profiles_list()
            self.log(f"Профиль удалён: {profile.name}")

    def toggle_selected_profile(self):
        profile = self._selected_profile()
        if not profile:
            messagebox.showwarning("Внимание", "Выберите профиль")
            return
        profile.enabled = not profile.enabled
        save_profiles(self.custom_profiles)
        self.refresh_profiles_list()
        self.log(f"Профиль {'включён' if profile.enabled else 'выключен'}: {profile.name}")

    def test_profiles_parallel(self):
        profiles = [p for p in self._visible_profiles() if p.enabled]
        if not profiles:
            messagebox.showinfo("Информация", "Нет профилей для проверки")
            return

        def worker():
            self.set_status("● Параллельная проверка профилей...", "orange")
            results = []
            with ThreadPoolExecutor(max_workers=8) as ex:
                futures = [ex.submit(self._can_materialize_profile, p) for p in profiles[:20]]
                for fut in as_completed(futures):
                    results.append(fut.result())
            ok_count = sum(1 for _, ok in results if ok)
            self.log(f"Параллельная проверка завершена: {ok_count}/{len(results)}")
            self.set_status("● Проверка завершена", "lime" if ok_count else "red")

        threading.Thread(target=worker, daemon=True).start()

    def _can_materialize_profile(self, profile: VPNProfile) -> Tuple[str, bool]:
        try:
            if profile.kind == "vpngate":
                host, ip = parse_vpngate_ref(profile.source)
                servers = self.vpn._fetch_live_vpngate_servers()
                for s in servers:
                    if (host and s["hostname"] == host) or (ip and s["ip"] == ip):
                        return profile.name, True
                return profile.name, False
            if is_url(profile.source):
                return profile.name, True
            return profile.name, os.path.exists(profile.source)
        except Exception:
            return profile.name, False

    # ---------- add tab ----------
    def create_add_tab(self):
        frame = ctk.CTkFrame(self.tab_free_vpn)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Добавить VPN-профиль", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=8)

        form = ctk.CTkFrame(frame)
        form.pack(fill="x", padx=10, pady=10)

        self.new_name = ctk.CTkEntry(form, placeholder_text="Имя профиля")
        self.new_name.pack(fill="x", padx=10, pady=8)

        self.new_kind = ctk.CTkComboBox(form, values=["openvpn", "wireguard", "vpngate"])
        self.new_kind.set("openvpn")
        self.new_kind.pack(fill="x", padx=10, pady=8)

        self.new_source = ctk.CTkEntry(form, placeholder_text="Путь к файлу, URL или vpngate://host|ip")
        self.new_source.pack(fill="x", padx=10, pady=8)

        btns = ctk.CTkFrame(frame)
        btns.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(btns, text="Выбрать файл", command=self.pick_profile_file).pack(side="left", padx=5)
        ctk.CTkButton(btns, text="Сохранить профиль", command=self.add_profile).pack(side="left", padx=5)
        ctk.CTkButton(btns, text="Открыть папку конфигов", command=self.open_profiles_folder).pack(side="left", padx=5)

        self.add_profile_info = ctk.CTkLabel(
            frame,
            text="Поддерживаются локальные файлы .ovpn/.conf, URL и формат VPNGate.",
            justify="left",
        )
        self.add_profile_info.pack(pady=18)

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
            messagebox.showerror("Ошибка", "Поддерживаются только openvpn, wireguard и vpngate")
            return

        if kind == "vpngate":
            if not is_vpngate_ref(source):
                messagebox.showerror("Ошибка", "Для VPNGate укажи source в формате vpngate://hostname|ip")
                return
        else:
            if not is_url(source) and not os.path.exists(source):
                messagebox.showerror("Ошибка", "Укажи корректный путь к файлу или URL")
                return

        profile = VPNProfile(name=name, kind=kind, source=source)
        self.custom_profiles.append(profile)
        save_profiles(self.custom_profiles)
        self.refresh_profiles_list()
        self.new_name.delete(0, tk.END)
        self.new_source.delete(0, tk.END)
        self.log(f"Профиль добавлен: {name}")

    # ---------- free VPN tab ----------
    def create_free_vpn_tab(self):
        frame = ctk.CTkFrame(self.tab_free_vpn)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        top = ctk.CTkFrame(frame)
        top.pack(fill="x", pady=5)

        self.free_search_var = tk.StringVar(value="")
        ctk.CTkLabel(top, text="Поиск:").pack(side="left", padx=8)
        ctk.CTkEntry(top, textvariable=self.free_search_var, width=300, placeholder_text="country / host / ip / note").pack(side="left", padx=6)
        ctk.CTkButton(top, text="Фильтр", command=self.refresh_free_list).pack(side="left", padx=6)
        ctk.CTkButton(top, text="Сброс", command=self.reset_free_search).pack(side="left", padx=6)
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

    def _visible_free_profiles(self) -> List[VPNProfile]:
        q = self.free_search_var.get().strip().lower() if hasattr(self, "free_search_var") else ""
        if not q:
            return self.free_profiles[:]
        return [p for p in self.free_profiles if q in p.name.lower() or q in p.source.lower() or q in p.note.lower()]

    def reset_free_search(self):
        self.free_search_var.set("")
        self.refresh_free_list()

    def refresh_free_list(self):
        if not hasattr(self, "free_listbox"):
            return
        visible = self._visible_free_profiles()
        self.free_listbox.delete(0, tk.END)
        for p in visible:
            state = "on" if p.enabled else "off"
            self.free_listbox.insert(tk.END, f"[{state}] {p.name} — {p.source} | {p.note}")
        self.free_counter_label.configure(text=f"Бесплатных: {len(visible)}")
        self.set_preset_status(f"Статус пула: {len(visible)} показано из {len(self.free_profiles)}", "gray")

    def reload_free_from_json(self):
        def worker():
            try:
                self.set_preset_status("Статус пула: загрузка JSON...", "orange")
                self.free_profiles = load_free_profiles_from_json()
                self.refresh_free_list()
                self.set_preset_status(f"Статус пула: {len(self.free_profiles)} серверов", "lime")
                self.log(f"JSON перечитан: {len(self.free_profiles)} бесплатных профилей")
            except Exception as e:
                self.set_preset_status("Статус пула: ошибка", "red")
                self.log(f"Ошибка чтения JSON: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def refresh_free_from_web(self):
        def worker():
            try:
                self.set_preset_status("Статус пула: обновление из VPNGate...", "orange")
                free_profiles = fetch_vpngate_profiles(FREE_VPN_LIMIT)
                save_free_profiles_json(free_profiles)
                self.free_profiles = free_profiles
                self.refresh_free_list()
                self.set_preset_status(f"Статус пула: обновлено {len(free_profiles)}", "lime")
                self.log(f"Бесплатный пул обновлён из VPNGate: {len(free_profiles)} профилей")
            except Exception as e:
                self.set_preset_status("Статус пула: ошибка", "red")
                self.log(f"Ошибка обновления VPNGate: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def _selected_free(self) -> Optional[VPNProfile]:
        sel = self.free_listbox.curselection()
        if not sel:
            return None
        visible = self._visible_free_profiles()
        idx = sel[0]
        if idx < 0 or idx >= len(visible):
            return None
        return visible[idx]

    def connect_selected_free(self):
        profile = self._selected_free()
        if not profile:
            messagebox.showwarning("Внимание", "Выберите бесплатный сервер")
            return
        self.set_status("● Подключение к бесплатному VPN...", "orange")
        threading.Thread(target=lambda: self._connect_profile_worker(profile), daemon=True).start()

    def connect_best_free(self):
        visible = [p for p in self._visible_free_profiles() if p.enabled]
        if not visible:
            messagebox.showwarning("Внимание", "Список пуст")
            return
        self.set_status(f"● Подключение к {visible[0].name}", "orange")
        threading.Thread(target=lambda: self._connect_profile_worker(visible[0]), daemon=True).start()

    def _connect_profile_worker(self, profile: VPNProfile):
        try:
            self.vpn.start(profile)
            self.log(f"Выбран сервер: {profile.name}")
            self._monitor_user_vpn_output()
        except Exception as e:
            self.log(f"Ошибка подключения: {e}")
            self.set_status("● Ошибка подключения", "red")

    def refresh_all_lists(self):
        self.refresh_profiles_list()
        self.refresh_free_list()

    # ---------- other ----------
    def open_profiles_folder(self):
        try:
            open_path(VPN_DOWNLOAD_DIR)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def open_auth_file(self):
        try:
            open_path(AUTH_FILE)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def change_password(self):
        new_pwd = self.new_password_entry.get().strip()
        if len(new_pwd) < 8:
            messagebox.showwarning("Внимание", "Пароль слишком короткий")
            return
        save_auth(new_pwd)
        self.auth = load_auth()
        self.new_password_entry.delete(0, tk.END)
        self.log("Пароль пользователя обновлён")
        messagebox.showinfo("Готово", "Пароль сохранён")

    def create_settings_tab(self):
        frame = ctk.CTkFrame(self.tab_free_proxy)
        frame.pack_forget()

    # ---------- settings screen ----------
    def create_settings_tab_real(self):
        frame = ctk.CTkFrame(self.tabview.add("⚙️ Настройки"))
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Настройки пользователя", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        self.new_password_entry = ctk.CTkEntry(frame, placeholder_text="Новый пароль", width=320, show="*")
        self.new_password_entry.pack(pady=10)

        ctk.CTkButton(frame, text="Сохранить новый пароль", command=self.change_password).pack(pady=6)
        ctk.CTkButton(frame, text="Открыть auth.json", command=self.open_auth_file).pack(pady=6)
        ctk.CTkButton(frame, text="Открыть папку конфигов", command=self.open_profiles_folder).pack(pady=6)
        ctk.CTkButton(frame, text="Обновить бесплатные VPN", command=self.refresh_free_from_web).pack(pady=6)

    def create_settings_tab(self):
        frame = ctk.CTkFrame(self.tabview.add("⚙️ Настройки"))
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Настройки пользователя", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        self.new_password_entry = ctk.CTkEntry(frame, placeholder_text="Новый пароль", width=320, show="*")
        self.new_password_entry.pack(pady=10)

        ctk.CTkButton(frame, text="Сохранить новый пароль", command=self.change_password).pack(pady=6)
        ctk.CTkButton(frame, text="Открыть auth.json", command=self.open_auth_file).pack(pady=6)
        ctk.CTkButton(frame, text="Открыть папку конфигов", command=self.open_profiles_folder).pack(pady=6)
        ctk.CTkButton(frame, text="Обновить бесплатные VPN", command=self.refresh_free_from_web).pack(pady=6)

    # ---------- close ----------
    def on_closing(self):
        try:
            self.disconnect_vpn()
        except Exception:
            pass
        self.destroy()

    def run(self):
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.mainloop()


if __name__ == "__main__":
    app = UserApp()
    app.run()
