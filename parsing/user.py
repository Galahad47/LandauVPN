import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, ttk
import requests
import threading
import subprocess
import platform
import os
import json
import time
import tempfile
import queue
from typing import List, Tuple, Optional

# ================== КОНСТАНТЫ ==================
APP_NAME = "UserVPNProxy"
CONFIG_FILE = "user_config.json"
LOG_ENABLED = True
REQUEST_TIMEOUT = 15
VPN_GATE_API_DEFAULT = "http://www.vpngate.net/api/iphone/"

# ================== КОНФИГУРАЦИЯ ==================
def load_user_config() -> dict:
    default_config = {
        "user_password": "UserConnect2026!",
        "preset_socks_ip": "YOUR.VPN.SERVER.IP",
        "preset_socks_port": 1080,
        "free_proxy_sources": [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        ],
        "vpn_gate_api": VPN_GATE_API_DEFAULT,
    }

    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать {CONFIG_FILE}:\n{e}")
        return default_config

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
        for key, value in default_config.items():
            config.setdefault(key, value)
        return config
    except Exception as e:
        messagebox.showerror("Ошибка конфигурации", f"Не удалось загрузить {CONFIG_FILE}:\n{e}")
        return default_config


CONFIG = load_user_config()
USER_PASSWORD = CONFIG["user_password"]
PRESET_SOCKS_IP = CONFIG["preset_socks_ip"]
PRESET_SOCKS_PORT = CONFIG["preset_socks_port"]
FREE_PROXY_SOURCES = CONFIG["free_proxy_sources"]
VPN_GATE_API = CONFIG["vpn_gate_api"]

# ================== GUI ==================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ================== УТИЛИТЫ ==================
def safe_gui_call(widget, func, *args, **kwargs):
    """Планирует вызов UI-функции в главном потоке."""
    try:
        widget.after(0, lambda: func(*args, **kwargs))
    except Exception:
        pass


def check_socks5_proxy(proxy_str: str, timeout: int = 5) -> Tuple[bool, float]:
    try:
        proxies = {
            "http": f"socks5://{proxy_str}",
            "https": f"socks5://{proxy_str}",
        }
        start = time.time()
        r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=timeout)
        latency = (time.time() - start) * 1000
        return r.status_code == 200, latency
    except Exception:
        return False, 0.0


def set_system_proxy_env(proxy_str: str):
    os.environ["HTTP_PROXY"] = f"socks5://{proxy_str}"
    os.environ["HTTPS_PROXY"] = f"socks5://{proxy_str}"
    os.environ["ALL_PROXY"] = f"socks5://{proxy_str}"


def unset_system_proxy_env():
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
        os.environ.pop(var, None)


def is_url(text: str) -> bool:
    return text.startswith("http://") or text.startswith("https://")


# ================== ПРИЛОЖЕНИЕ ==================
class UserApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"🔑 {APP_NAME} — VPN и Proxy для пользователя")
        self.geometry("1100x760")
        self.minsize(980, 680)

        self.current_proxy = None
        self.vpn_process: Optional[subprocess.Popen] = None
        self.ui_queue: queue.Queue = queue.Queue()

        self.show_password_screen()
        self.after(100, self.process_ui_queue)

    # ---------- UI QUEUE ----------
    def process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._append_log(item[1])
                elif kind == "status":
                    _, text, color = item
                    self.status_bar.configure(text=text, text_color=color)
                elif kind == "vpn_status":
                    _, text, color = item
                    self.vpn_status_label.configure(text=text, text_color=color)
                elif kind == "preset_status":
                    _, text, color = item
                    self.preset_status_label.configure(text=text, text_color=color)
        except queue.Empty:
            pass
        self.after(100, self.process_ui_queue)

    def log(self, message: str):
        if LOG_ENABLED:
            self.ui_queue.put(("log", message))

    def _append_log(self, message: str):
        if not hasattr(self, "log_text"):
            return
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')}  {message}\n")
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)

    # ---------- ЭКРАН ПАРОЛЯ ----------
    def show_password_screen(self):
        self.pass_frame = ctk.CTkFrame(self)
        self.pass_frame.pack(fill="both", expand=True, padx=50, pady=80)

        ctk.CTkLabel(
            self.pass_frame,
            text="ВВЕДИТЕ ПАРОЛЬ ДЛЯ ДОСТУПА",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(pady=25)

        self.user_pass_entry = ctk.CTkEntry(
            self.pass_frame,
            placeholder_text="Пароль доступа",
            width=320,
            height=40,
            show="*",
        )
        self.user_pass_entry.pack(pady=15)
        self.user_pass_entry.bind("<Return>", lambda e: self.check_user_password())

        ctk.CTkButton(
            self.pass_frame,
            text="Подключиться",
            font=ctk.CTkFont(size=18),
            height=48,
            command=self.check_user_password,
        ).pack(pady=18)

        ctk.CTkLabel(
            self.pass_frame,
            text="Пароль выдаёт администратор",
            font=ctk.CTkFont(size=12),
            text_color="gray",
        ).pack(pady=10)

    def check_user_password(self):
        if self.user_pass_entry.get() == USER_PASSWORD:
            self.pass_frame.destroy()
            self.create_user_interface()
        else:
            messagebox.showerror("Ошибка доступа", "Неверный пароль")

    # ---------- ГЛАВНЫЙ ИНТЕРФЕЙС ----------
    def create_user_interface(self):
        title = ctk.CTkLabel(
            self,
            text=f"Подключение к вашему серверу\n{PRESET_SOCKS_IP}:{PRESET_SOCKS_PORT}",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        title.pack(pady=12)

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=5)

        self.tab_free_proxy = self.tabview.add("🌐 Бесплатные SOCKS5")
        self.create_free_proxy_tab()

        self.tab_free_vpn = self.tabview.add("🆓 Бесплатные VPN")
        self.create_free_vpn_tab()

        self.tab_preset = self.tabview.add("🔒 Ваш сервер")
        self.create_preset_vpn_tab()

        log_frame = ctk.CTkFrame(self)
        log_frame.pack(fill="x", padx=20, pady=(0, 6))
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=7,
            state="disabled",
            bg="#2b2b2b",
            fg="white",
            font=("Consolas", 9),
        )
        self.log_text.pack(fill="both", expand=True)

        self.status_bar = ctk.CTkLabel(
            self,
            text="● Не подключено",
            font=ctk.CTkFont(size=13),
            text_color="gray",
        )
        self.status_bar.pack(side="bottom", fill="x", padx=20, pady=8)

        self.log("Доступ разрешён ✓")

    # ---------- SOCKS5 TAB ----------
    def create_free_proxy_tab(self):
        frame = ctk.CTkFrame(self.tab_free_proxy)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        src_frame = ctk.CTkFrame(frame)
        src_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(src_frame, text="Источник списка:").pack(side="left", padx=5)

        self.proxy_source_combo = ctk.CTkComboBox(src_frame, values=FREE_PROXY_SOURCES, width=560)
        self.proxy_source_combo.pack(side="left", padx=5)
        if FREE_PROXY_SOURCES:
            self.proxy_source_combo.set(FREE_PROXY_SOURCES[0])

        ctk.CTkButton(src_frame, text="🔄 Загрузить", command=self.load_free_proxies).pack(side="left", padx=5)

        list_frame = ctk.CTkFrame(frame)
        list_frame.pack(fill="both", expand=True, pady=5)
        self.proxy_listbox = tk.Listbox(
            list_frame,
            bg="#343638",
            fg="white",
            selectbackground="#1f538d",
            height=12,
        )
        self.proxy_listbox.pack(side="left", fill="both", expand=True)

        scrollbar = ctk.CTkScrollbar(list_frame, command=self.proxy_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.proxy_listbox.config(yscrollcommand=scrollbar.set)

        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(fill="x", pady=5)
        ctk.CTkButton(btn_frame, text="✅ Проверить выбранный", command=self.test_selected_proxy).pack(side="left", padx=3)
        ctk.CTkButton(btn_frame, text="⚡ Проверить все", command=self.test_all_proxies).pack(side="left", padx=3)
        ctk.CTkButton(btn_frame, text="🔌 Подключить", command=self.apply_selected_proxy).pack(side="left", padx=3)
        ctk.CTkButton(btn_frame, text="❌ Отключить", command=self.disable_proxy).pack(side="left", padx=3)

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
        if works:
            self.log(f"✅ {proxy} — работает ({latency:.1f} мс)")
        else:
            self.log(f"❌ {proxy} — не работает")

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
        set_system_proxy_env(proxy)
        self.current_proxy = proxy
        self.status_bar.configure(text=f"● Прокси: {proxy}", text_color="lime")
        self.log(f"Подключен прокси {proxy}")

    def disable_proxy(self):
        unset_system_proxy_env()
        self.current_proxy = None
        self.status_bar.configure(text="● Не подключено", text_color="gray")
        self.log("Прокси отключен")

    # ---------- VPN TAB ----------
    def create_free_vpn_tab(self):
        frame = ctk.CTkFrame(self.tab_free_vpn)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(
            frame,
            text="Публичные OpenVPN серверы (VPNGate)",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(pady=5)

        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(fill="x", pady=5)
        ctk.CTkButton(btn_frame, text="🌍 Загрузить список", command=self.load_vpngate_servers).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🔌 Подключиться", command=self.connect_selected_vpngate).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🔓 Отключить VPN", command=self.disconnect_vpn).pack(side="left", padx=5)

        tree_frame = ctk.CTkFrame(frame)
        tree_frame.pack(fill="both", expand=True, pady=5)

        columns = ("Country", "IP", "Score", "Ping", "Speed")
        self.vpn_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=11)
        for col in columns:
            self.vpn_tree.heading(col, text=col)
            self.vpn_tree.column(col, width=140, anchor="center")
        self.vpn_tree.pack(side="left", fill="both", expand=True)

        scrollbar = ctk.CTkScrollbar(tree_frame, command=self.vpn_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.vpn_tree.config(yscrollcommand=scrollbar.set)

        self.vpn_status_label = ctk.CTkLabel(
            frame,
            text="Статус VPN: не подключен",
            font=ctk.CTkFont(size=12),
            text_color="gray",
        )
        self.vpn_status_label.pack(pady=5)

    def load_vpngate_servers(self):
        self.log("Загрузка списка серверов VPNGate...")
        threading.Thread(target=self._fetch_vpngate_thread, daemon=True).start()

    def _fetch_vpngate_thread(self):
        try:
            r = requests.get(VPN_GATE_API, timeout=20)
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
            import base64
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
                    self.ui_queue.put(("vpn_status", "Статус: подключен ✓", "lime"))
                    self.ui_queue.put(("status", "● VPN активен", "lime"))
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass

        rc = proc.wait()
        self.ui_queue.put(("vpn_status", "Статус: отключен", "gray"))
        self.ui_queue.put(("status", "● Не подключено", "gray"))
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

    # ---------- ПРЕДНАСТРОЕННЫЙ SOCKS5 ----------
    def create_preset_vpn_tab(self):
        frame = ctk.CTkFrame(self.tab_preset)
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        ctk.CTkLabel(
            frame,
            text="Ваш преднастроенный SOCKS5 сервер",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(pady=10)

        info_frame = ctk.CTkFrame(frame)
        info_frame.pack(pady=20)

        ctk.CTkLabel(info_frame, text="IP адрес:").grid(row=0, column=0, padx=10, pady=5)
        ip_entry = ctk.CTkEntry(info_frame, width=220)
        ip_entry.insert(0, PRESET_SOCKS_IP)
        ip_entry.configure(state="disabled")
        ip_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(info_frame, text="Порт:").grid(row=1, column=0, padx=10, pady=5)
        port_entry = ctk.CTkEntry(info_frame, width=220)
        port_entry.insert(0, str(PRESET_SOCKS_PORT))
        port_entry.configure(state="disabled")
        port_entry.grid(row=1, column=1, padx=10, pady=5)

        self.preset_status_label = ctk.CTkLabel(frame, text="", font=ctk.CTkFont(size=12), text_color="gray")
        self.preset_status_label.pack(pady=5)

        ctk.CTkButton(
            frame,
            text="🔍 Проверить и подключить",
            fg_color="green",
            height=40,
            command=self.connect_preset_proxy,
        ).pack(pady=20)

    def connect_preset_proxy(self):
        proxy_str = f"{PRESET_SOCKS_IP}:{PRESET_SOCKS_PORT}"
        self.log(f"Проверка предустановленного сервера {proxy_str}...")
        self.preset_status_label.configure(text="Проверка...", text_color="orange")
        threading.Thread(target=self._connect_preset_thread, args=(proxy_str,), daemon=True).start()

    def _connect_preset_thread(self, proxy_str: str):
        works, latency = check_socks5_proxy(proxy_str)
        if works:
            set_system_proxy_env(proxy_str)
            self.current_proxy = proxy_str
            self.ui_queue.put(("status", f"● Подключено к вашему серверу: {proxy_str}", "lime"))
            self.log(f"✅ Успешно подключено к {proxy_str} ({latency:.1f} мс)")
            self.ui_queue.put(("preset_status", "Подключено ✓", "lime"))
            self.show_instructions()
        else:
            self.log(f"❌ Сервер {proxy_str} недоступен")
            self.ui_queue.put(("preset_status", "Недоступен", "red"))
            messagebox.showerror(
                "Ошибка",
                "Ваш сервер временно недоступен.\nПопробуйте позже или используйте бесплатные прокси/VPN."
            )

    def show_instructions(self):
        messagebox.showinfo(
            "Подключено",
            "Вы подключены к персональному прокси-серверу.\n\n"
            "Для отключения нажмите 'Отключить' на вкладке 'Бесплатные SOCKS5'."
        )

    # ---------- ЗАВЕРШЕНИЕ ----------
    def on_closing(self):
        try:
            if self.vpn_process and self.vpn_process.poll() is None:
                self.disconnect_vpn()
        finally:
            self.destroy()

    def run(self):
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.mainloop()


if __name__ == "__main__":
    app = UserApp()
    app.run()
