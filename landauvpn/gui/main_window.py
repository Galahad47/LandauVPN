"""
LandauVPN - GUI Module
Графический интерфейс приложения
"""

import queue
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
from typing import List, Optional, Tuple

import customtkinter as ctk

from ..core.models import VPNProfile
from ..core.vpn_controller import VPNController
from ..proxy.controller import ProxyController, ProxyConfig, create_default_hostlists as create_proxy_hostlists
from ..dpi.bypasser import DPIBypasser, DPIConfig, get_dpi_bypasser, create_default_hostlists as create_dpi_hostlists
from ..mtproto.controller import MTProtoController, MTProtoConfig, get_mtproto_controller
from ..utils.config import (
    load_admin_auth, save_admin_auth, hash_password, 
    load_profiles, save_profiles, load_free_profiles_from_json, 
    save_free_profiles_json, fetch_vpngate_profiles,
    DEFAULT_ADMIN_USERNAME, FREE_VPN_JSON_FILE, VPN_PROFILES_FILE,
    VPN_DOWNLOAD_DIR, AUTH_FILE
)


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class LandauVPNGUI(ctk.CTk):
    """Основное окно приложения LandauVPN"""
    
    def __init__(self):
        super().__init__()
        self.title(f"🛡️ LandauVPN — Manager")
        self.geometry("1260x860")
        self.minsize(1140, 780)

        self.ui_queue: queue.Queue = queue.Queue()
        
        # Инициализация контроллеров
        self.vpn = VPNController(self._queue_log)
        self.proxy = ProxyController(self._queue_log)
        self.dpi = get_dpi_bypasser(self._queue_log)
        self.mtproto = get_mtproto_controller(self._queue_log)
        
        # Данные профилей
        self.custom_profiles: List[VPNProfile] = load_profiles(VPN_PROFILES_FILE)
        self.free_profiles: List[VPNProfile] = []
        self._profile_lock = threading.Lock()
        self._pending_logs: List[str] = []
        self._connected_profile: Optional[VPNProfile] = None
        
        # Создание интерфейса
        self.show_login()
        self.after(80, self._process_ui_queue)

    # ========== Очередь UI ==========
    def _queue_log(self, msg: str):
        self.ui_queue.put(("log", msg))

    def _queue_status(self, msg: str, color: str = "gray"):
        self.ui_queue.put(("status", msg, color))

    def _queue_proxy_status(self, msg: str, color: str = "gray"):
        self.ui_queue.put(("proxy_status", msg, color))

    def _process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                kind = item[0]
                if kind == "log" and hasattr(self, "log_text"):
                    self._append_log(item[1])
                elif kind == "status" and hasattr(self, "status_bar"):
                    self.status_bar.configure(text=item[1], text_color=item[2])
                elif kind == "proxy_status" and hasattr(self, "proxy_status_label"):
                    self.proxy_status_label.configure(text=item[1], text_color=item[2])
        except queue.Empty:
            pass
        self.after(80, self._process_ui_queue)

    def _append_log(self, message: str):
        if not hasattr(self, "log_text"):
            return
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} {message}\n")
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)

    def log(self, message: str):
        self._queue_log(message)

    # ========== Логин ==========
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

    # ========== Главный интерфейс ==========
    def create_main_interface(self):
        # Header
        header = ctk.CTkFrame(self)
        header.pack(fill="x", padx=20, pady=(12, 8))
        ctk.CTkLabel(header, text="LandauVPN — Управление VPN и Прокси", font=ctk.CTkFont(size=24, weight="bold")).pack(
            side="left", padx=10, pady=8
        )
        ctk.CTkButton(header, text="Обновить бесплатные", command=self.refresh_free_from_web, width=170).pack(
            side="right", padx=8
        )
        ctk.CTkButton(header, text="Перечитать JSON", command=self.reload_free_from_json, width=150).pack(
            side="right", padx=8
        )

        # Tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=10)

        self.tab_profiles = self.tabview.add("🌐 VPN профили")
        self._create_profiles_tab()
        self.tab_free = self.tabview.add("🆓 Бесплатные VPN")
        self._create_free_tab()
        self.tab_proxy = self.tabview.add("🔒 Прокси (DPI)")
        self._create_proxy_tab()
        self.tab_add = self.tabview.add("➕ Добавить профиль")
        self._create_add_tab()
        self.tab_settings = self.tabview.add("⚙️ Настройки")
        self._create_settings_tab()

        # Log
        self.log_text = scrolledtext.ScrolledText(self, height=7, state="disabled", bg="#2b2b2b", fg="white", font=("Consolas", 9))
        self.log_text.pack(fill="x", padx=20, pady=(0, 5))

        for msg in self._pending_logs:
            self._append_log(msg)
        self._pending_logs.clear()

        # Status bar
        self.status_bar = ctk.CTkLabel(self, text="● VPN не подключено", font=ctk.CTkFont(size=14), text_color="gray")
        self.status_bar.pack(side="bottom", fill="x", padx=20, pady=8)
        
        self.proxy_status_label = ctk.CTkLabel(self, text="● Прокси выключено", font=ctk.CTkFont(size=14), text_color="gray")
        self.proxy_status_label.pack(side="bottom", fill="x", padx=20, pady=(0, 8))

        self._append_log("Приложение запущено")
        self.reload_free_from_json()
        self._refresh_profiles_list()
        
        # Создание списков хостов по умолчанию для всех модулей
        create_proxy_hostlists()
        create_dpi_hostlists()

    # ========== Вкладка VPN профили ==========
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

    def _selected_profile(self) -> Optional[VPNProfile]:
        sel = self.profile_listbox.curselection()
        if not sel:
            return None
        idx = sel[0]
        visible = self._visible_free_profiles() + self._visible_custom_profiles()
        return visible[idx] if 0 <= idx < len(visible) else None

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
        """Мониторинг вывода процесса VPN"""
        proc = self.vpn.proc
        if not proc or not proc.stdout:
            self._queue_log("[VPN] Нет вывода процесса")
            return

        profile = self.vpn.current_profile
        if profile and profile.kind == "wireguard":
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
            return

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
            self._queue_status("● VPN не подключено", "gray")
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
            self._queue_status("● VPN не подключено", "gray")
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
            save_profiles(self.custom_profiles, VPN_PROFILES_FILE)
            self._refresh_profiles_list()
            self._append_log(f"Профиль удалён: {profile.name}")

    def toggle_selected_profile(self):
        profile = self._selected_profile()
        if not profile:
            return
        profile.enabled = not profile.enabled
        save_profiles(self.custom_profiles, VPN_PROFILES_FILE)
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
                from ..core.models import parse_vpngate_ref
                host, ip = parse_vpngate_ref(profile.source)
                servers = self.vpn._fetch_live_vpngate_servers()
                return profile.name, any(
                    (host and s["hostname"] == host) or (ip and s["ip"] == ip) for s in servers
                )
            from ..core.models import is_url
            if is_url(profile.source):
                return profile.name, True
            return profile.name, os.path.exists(profile.source)
        except Exception:
            return profile.name, False

    def _update_counters(self):
        if hasattr(self, "profiles_counter_label"):
            total = len(self._visible_custom_profiles()) + len(self._visible_free_profiles())
            self.profiles_counter_label.configure(text=f"Всего профилей: {total}")
        if hasattr(self, "free_counter_label"):
            self.free_counter_label.configure(text=f"Бесплатных: {len(self.free_profiles)}")
        if hasattr(self, "custom_counter_label"):
            self.custom_counter_label.configure(text=f"Локальных: {len(self.custom_profiles)}")

    # ========== Вкладка Бесплатные VPN ==========
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
        self._queue_status(f"Статус пула: {len(visible)} показано из {len(self.free_profiles)}", "gray")

    def reload_free_from_json(self):
        def worker():
            try:
                self._queue_status("Статус пула: загрузка JSON...", "orange")
                with self._profile_lock:
                    self.free_profiles = load_free_profiles_from_json(FREE_VPN_JSON_FILE)
                self._refresh_free_list()
                self._refresh_profiles_list()
                self._queue_status(f"Статус пула: {len(self.free_profiles)} серверов", "lime")
                self._queue_log(f"JSON перечитан: {len(self.free_profiles)} бесплатных профилей")
            except Exception as e:
                self._queue_status("Статус пула: ошибка", "red")
                self._queue_log(f"Ошибка чтения JSON: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def refresh_free_from_web(self):
        def worker():
            try:
                self._queue_status("Статус пула: обновление из VPNGate...", "orange")
                free_profiles = fetch_vpngate_profiles(50)
                save_free_profiles_json(free_profiles, FREE_VPN_JSON_FILE)
                with self._profile_lock:
                    self.free_profiles = free_profiles
                self._refresh_free_list()
                self._refresh_profiles_list()
                self._queue_status(f"Статус пула: обновлено {len(free_profiles)}", "lime")
                self._queue_log(f"Бесплатный пул обновлён: {len(free_profiles)} профилей")
            except Exception as e:
                self._queue_status("Статус пула: ошибка", "red")
                self._queue_log(f"Ошибка обновления VPNGate: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def _reset_free_search(self):
        self.free_search_var.set("")
        self._refresh_free_list()

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

    # ========== Вкладка Прокси ==========
    def _create_proxy_tab(self):
        frame = ctk.CTkFrame(self.tab_proxy)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="🔒 Проксирование и обход блокировок", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        
        info_text = ctk.CTkLabel(
            frame, 
            text="Три метода обхода блокировок:\n"
                 "1. Внешний прокси (zapret/goodbyedpi) - для Discord, YouTube\n"
                 "2. Встроенный DPI обходчик - аналог zapret внутри приложения\n"
                 "3. MTProto прокси - автоматическое проксирование Telegram",
            justify="left"
        )
        info_text.pack(pady=10)

        # === Раздел 1: Внешний прокси ===
        ext_frame = ctk.CTkLabelFrame(frame, text="📡 Внешний прокси (zapret/goodbyedpi)", padx=10, pady=10)
        ext_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(ext_frame, text="Режим работы:", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=10, pady=5)
        
        self.proxy_mode_var = ctk.StringVar(value="auto")
        mode_options = ["auto", "discord", "youtube", "telegram", "all"]
        self.proxy_mode_menu = ctk.CTkOptionMenu(
            ext_frame, 
            variable=self.proxy_mode_var, 
            values=mode_options,
            command=self._on_proxy_mode_change
        )
        self.proxy_mode_menu.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(ext_frame, text="Дополнительные аргументы:", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=10, pady=(15, 5))
        self.proxy_args_entry = ctk.CTkEntry(ext_frame, placeholder_text="--dpi-desync=fake --dpi-desync-autottl=2")
        self.proxy_args_entry.pack(fill="x", padx=10, pady=5)

        ext_btn_frame = ctk.CTkFrame(ext_frame)
        ext_btn_frame.pack(fill="x", padx=10, pady=15)
        
        self.proxy_start_btn = ctk.CTkButton(
            ext_btn_frame, 
            text="▶ Запустить внешний прокси", 
            command=self.start_proxy,
            fg_color="green"
        )
        self.proxy_start_btn.pack(side="left", padx=10)
        
        self.proxy_stop_btn = ctk.CTkButton(
            ext_btn_frame, 
            text="⏹ Остановить", 
            command=self.stop_proxy,
            fg_color="red"
        )
        self.proxy_stop_btn.pack(side="left", padx=10)
        
        ctk.CTkButton(ext_btn_frame, text="📁 Хосты", command=self.open_hosts_folder).pack(side="left", padx=10)

        # === Раздел 2: Встроенный DPI обходчик ===
        dpi_frame = ctk.CTkLabelFrame(frame, text="🛡️ Встроенный DPI обходчик (аналог zapret)", padx=10, pady=10)
        dpi_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(dpi_frame, text="Режим DPI обходчика:", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=10, pady=5)
        
        self.dpi_mode_var = ctk.StringVar(value="all")
        dpi_mode_options = ["auto", "youtube", "telegram", "all"]
        self.dpi_mode_menu = ctk.CTkOptionMenu(
            dpi_frame, 
            variable=self.dpi_mode_var, 
            values=dpi_mode_options
        )
        self.dpi_mode_menu.pack(fill="x", padx=10, pady=5)

        dpi_btn_frame = ctk.CTkFrame(dpi_frame)
        dpi_btn_frame.pack(fill="x", padx=10, pady=15)
        
        self.dpi_start_btn = ctk.CTkButton(
            dpi_btn_frame, 
            text="▶ Запустить DPI обходчик", 
            command=self.start_dpi,
            fg_color="green"
        )
        self.dpi_start_btn.pack(side="left", padx=10)
        
        self.dpi_stop_btn = ctk.CTkButton(
            dpi_btn_frame, 
            text="⏹ Остановить", 
            command=self.stop_dpi,
            fg_color="red"
        )
        self.dpi_stop_btn.pack(side="left", padx=10)

        # === Раздел 3: MTProto прокси для Telegram ===
        mt_frame = ctk.CTkLabelFrame(frame, text="✈️ MTProto прокси (Telegram)", padx=10, pady=10)
        mt_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(mt_frame, text="Автоматическое подключение к MTProto прокси для Telegram", 
                     font=ctk.CTkFont(size=13)).pack(anchor="w", padx=10, pady=5)
        
        self.mtproto_auto_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(mt_frame, text="Авто-выбор лучшего прокси", variable=self.mtproto_auto_var).pack(anchor="w", padx=10, pady=5)

        mt_btn_frame = ctk.CTkFrame(mt_frame)
        mt_btn_frame.pack(fill="x", padx=10, pady=15)
        
        self.mtproto_start_btn = ctk.CTkButton(
            mt_btn_frame, 
            text="▶ Запустить MTProto", 
            command=self.start_mtproto,
            fg_color="#0088cc"  # Telegram color
        )
        self.mtproto_start_btn.pack(side="left", padx=10)
        
        self.mtproto_stop_btn = ctk.CTkButton(
            mt_btn_frame, 
            text="⏹ Остановить", 
            command=self.stop_mtproto,
            fg_color="red"
        )
        self.mtproto_stop_btn.pack(side="left", padx=10)
        
        ctk.CTkButton(mt_btn_frame, text="🔄 Тест прокси", command=self.test_mtproto).pack(side="left", padx=10)

    def _on_proxy_mode_change(self, value):
        self.log(f"[Proxy] Режим изменён на: {value}")

    def start_proxy(self):
        config = ProxyConfig(
            enabled=True,
            mode=self.proxy_mode_var.get(),
            custom_args=self.proxy_args_entry.get().strip()
        )
        
        def worker():
            try:
                self._queue_proxy_status("● Прокси запускается...", "orange")
                self.proxy.start(config)
                self._queue_proxy_status(f"● Прокси активно ({config.mode})", "lime")
            except Exception as e:
                self._queue_proxy_status("● Ошибка прокси", "red")
                self._queue_log(f"[Proxy] Ошибка: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def stop_proxy(self):
        def worker():
            try:
                self.proxy.stop()
                self._queue_proxy_status("● Прокси выключено", "gray")
            except Exception as e:
                self._queue_log(f"[Proxy] Остановка: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def open_hosts_folder(self):
        from ..utils.config import CONFIG_DIR
        import subprocess
        import platform
        
        hosts_dir = CONFIG_DIR
        try:
            if platform.system() == "Windows":
                os.startfile(str(hosts_dir))
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(hosts_dir)])
            else:
                subprocess.Popen(["xdg-open", str(hosts_dir)])
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ========== Методы для DPI обходчика ==========
    def start_dpi(self):
        config = DPIConfig(
            enabled=True,
            mode=self.dpi_mode_var.get()
        )
        
        def worker():
            try:
                self._queue_proxy_status("● DPI обходчик запускается...", "orange")
                self.dpi.start(config)
                self._queue_proxy_status(f"● DPI обходчик активен ({config.mode})", "lime")
            except Exception as e:
                self._queue_proxy_status("● Ошибка DPI", "red")
                self._queue_log(f"[DPI] Ошибка: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def stop_dpi(self):
        def worker():
            try:
                self.dpi.stop()
                self._queue_proxy_status("● DPI обходчик выключен", "gray")
            except Exception as e:
                self._queue_log(f"[DPI] Остановка: {e}")

        threading.Thread(target=worker, daemon=True).start()

    # ========== Методы для MTProto прокси ==========
    def start_mtproto(self):
        config = MTProtoConfig(
            enabled=True,
            auto_detect=self.mtproto_auto_var.get()
        )
        
        def worker():
            try:
                self._queue_proxy_status("● MTProto запускается...", "orange")
                self.mtproto.start(config)
                self._queue_proxy_status("● MTProto активен", "lime")
            except Exception as e:
                self._queue_proxy_status("● Ошибка MTProto", "red")
                self._queue_log(f"[MTProto] Ошибка: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def stop_mtproto(self):
        def worker():
            try:
                self.mtproto.stop()
                self._queue_proxy_status("● MTProto выключен", "gray")
            except Exception as e:
                self._queue_log(f"[MTProto] Остановка: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def test_mtproto(self):
        def worker():
            try:
                self._queue_log("[MTProto] Тестирование прокси...")
                proxy = self.mtproto.find_best_proxy()
                if proxy:
                    self._queue_log(f"[MTProto] Найден рабочий прокси: {proxy}")
                    self._queue_proxy_status(f"● Доступен прокси: {proxy.host}:{proxy.port}", "lime")
                else:
                    self._queue_log("[MTProto] Не найдено рабочих прокси")
                    self._queue_proxy_status("● Нет доступных прокси", "red")
            except Exception as e:
                self._queue_log(f"[MTProto] Ошибка теста: {e}")

        threading.Thread(target=worker, daemon=True).start()

    # ========== Вкладка Добавить профиль ==========
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
        if kind == "vpngate" and not source.startswith("vpngate://"):
            messagebox.showerror("Ошибка", "Для VPNGate используйте формат vpngate://hostname|ip")
            return
        if kind != "vpngate" and not source.startswith(("http://", "https://")) and not os.path.exists(source):
            messagebox.showerror("Ошибка", "Укажите корректный путь к файлу или URL")
            return

        profile = VPNProfile(name=name, kind=kind, source=source)
        with self._profile_lock:
            self.custom_profiles.append(profile)
            save_profiles(self.custom_profiles, VPN_PROFILES_FILE)

        self._refresh_profiles_list()
        self._refresh_free_list()
        self.new_name.delete(0, tk.END)
        self.new_source.delete(0, tk.END)
        self._append_log(f"Профиль добавлен: {name}")

    # ========== Вкладка Настройки ==========
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

    # ========== Вспомогательные ==========
    def open_profiles_folder(self):
        import subprocess
        import platform
        
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
        import subprocess
        import platform
        
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

    # ========== Завершение ==========
    def on_closing(self):
        try:
            self.vpn.stop()
            self.proxy.stop()
        except Exception:
            pass
        self.destroy()
