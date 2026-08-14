import os
import platform
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, List, Callable
from dataclasses import dataclass

from utils.config import CONFIG_DIR


@dataclass
class ProxyConfig:
    """Конфигурация прокси"""
    enabled: bool = True
    mode: str = "auto"  # auto, discord, youtube, telegram, all
    custom_args: str = ""
    log_file: str = ""


class ProxyController:
    """
    Контроллер постоянного проксирования в стиле zapret-discord-youtube.
    Использует утилиты типа zapret, goodbyedpi, split-tunneling для обхода блокировок.
    """
    
    def __init__(self, log_func: Callable[[str], None]):
        self.log = log_func
        self.proc: Optional[subprocess.Popen] = None
        self.config = ProxyConfig()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
    def _get_zapret_path(self) -> Optional[Path]:
        """Поиск исполняемого файла zapret"""
        candidates = [
            CONFIG_DIR / "zapret" / "bin" / "zapret",
            CONFIG_DIR / "zapret" / "zapret.exe",
            Path("/usr/bin/zapret"),
            Path("/usr/local/bin/zapret"),
        ]
        
        for p in candidates:
            if p.exists() and os.access(p, os.X_OK):
                return p
        return None
    
    def _get_goodbyedpi_path(self) -> Optional[Path]:
        """Поиск исполняемого файла goodbyedpi (Windows)"""
        if platform.system() != "Windows":
            return None
            
        candidates = [
            CONFIG_DIR / "goodbyedpi" / "goodbyedpi.exe",
            Path.cwd() / "goodbyedpi.exe",
        ]
        
        for p in candidates:
            if p.exists():
                return p
        return None
    
    def _build_zapret_command(self) -> List[str]:
        """Построение команды zapret в зависимости от режима"""
        zapret_path = self._get_zapret_path()
        if not zapret_path:
            raise FileNotFoundError("zapret не найден. Установите zapret.")
        
        cmd = [str(zapret_path)]
        
        # Аргументы в зависимости от режима
        if self.config.mode == "discord":
            cmd.extend([
                "--dpi-desync=fake", 
                "--dpi-desync-autottl=2",
                "--hostlist=" + str(CONFIG_DIR / "discord_hosts.txt")
            ])
        elif self.config.mode == "youtube":
            cmd.extend([
                "--dpi-desync=fake",
                "--dpi-desync-split=1",
                "--hostlist=" + str(CONFIG_DIR / "youtube_hosts.txt")
            ])
        elif self.config.mode == "telegram":
            cmd.extend([
                "--dpi-desync=fake",
                "--dpi-desync-autottl=2",
                "--hostlist=" + str(CONFIG_DIR / "telegram_hosts.txt")
            ])
        elif self.config.mode == "all":
            cmd.extend([
                "--dpi-desync=fake",
                "--dpi-desync-autottl=2",
                "--dpi-desync-split=1"
            ])
        else:  # auto
            cmd.extend([
                "--dpi-desync=fake",
                "--dpi-desync-autottl=2"
            ])
        
        # Пользовательские аргументы
        if self.config.custom_args:
            cmd.extend(self.config.custom_args.split())
        
        # Логирование
        if self.config.log_file:
            cmd.extend([">>", self.config.log_file])
        
        return cmd
    
    def _build_goodbyedpi_command(self) -> List[str]:
        """Построение команды goodbyedpi для Windows"""
        gdpi_path = self._get_goodbyedpi_path()
        if not gdpi_path:
            raise FileNotFoundError("goodbyedpi не найден. Скачайте goodbyedpi.")
        
        cmd = [str(gdpi_path)]
        
        if self.config.mode == "discord":
            cmd.extend(["-e", "2"])
        elif self.config.mode == "youtube":
            cmd.extend(["-e", "1", "-s"])
        elif self.config.mode == "telegram":
            cmd.extend(["-e", "2", "-p"])
        else:  # all / auto
            cmd.extend(["-e", "2", "-s", "-p"])
        
        if self.config.custom_args:
            cmd.extend(self.config.custom_args.split())
        
        return cmd
    
    def _monitor_process(self):
        """Мониторинг процесса прокси"""
        while self._running and self.proc and self.proc.poll() is None:
            try:
                line = self.proc.stdout.readline()
                if line:
                    self.log(f"[Proxy] {line.strip()}")
            except Exception as e:
                self.log(f"[Proxy] Ошибка чтения вывода: {e}")
                break
        
        if self._running:
            self.log("[Proxy] Процесс завершился")
            self._running = False
    
    def start(self, config: Optional[ProxyConfig] = None):
        """Запуск постоянного проксирования"""
        if self.proc and self.proc.poll() is None:
            raise RuntimeError("Прокси уже запущено")
        
        if config:
            self.config = config
        
        if not self.config.enabled:
            self.log("[Proxy] Прокси отключено в настройках")
            return
        
        system = platform.system()
        
        try:
            if system == "Linux":
                cmd = self._build_zapret_command()
            elif system == "Windows":
                cmd = self._build_goodbyedpi_command()
            else:  # macOS
                # Для macOS можно использовать аналогичные инструменты
                cmd = self._build_zapret_command()
            
            self.log(f"[Proxy] Запуск: {' '.join(cmd)}")
            
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if system == "Windows" else 0
            
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
            
            self._running = True
            self._thread = threading.Thread(target=self._monitor_process, daemon=True)
            self._thread.start()
            
            self.log("[Proxy] Прокси запущено")
            
        except FileNotFoundError as e:
            self.log(f"[Proxy] Ошибка: {e}")
            self.log("[Proxy] Установите необходимое ПО для обхода DPI")
            raise
        except Exception as e:
            self.log(f"[Proxy] Ошибка запуска: {e}")
            raise
    
    def stop(self):
        """Остановка проксирования"""
        self._running = False
        
        if not self.proc or self.proc.poll() is not None:
            self.proc = None
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
        
        self.log("[Proxy] Прокси остановлено")
        self.proc = None
    
    def is_running(self) -> bool:
        """Проверка работы прокси"""
        return self._running and self.proc and self.proc.poll() is None
    
    def set_mode(self, mode: str):
        """Изменение режима проксирования"""
        valid_modes = ["auto", "discord", "youtube", "telegram", "all"]
        if mode not in valid_modes:
            raise ValueError(f"Недопустимый режим: {mode}. Доступны: {valid_modes}")
        
        was_running = self.is_running()
        if was_running:
            self.stop()
        
        self.config.mode = mode
        self.log(f"[Proxy] Режим изменён на: {mode}")
        
        if was_running:
            self.start()


def create_default_hostlists():
    """Создание файлов со списками хостов по умолчанию"""
    
    discord_hosts = """
discord.com
discord.gg
discordapp.com
discordapp.net
cdn.discordapp.com
gateway.discord.gg
media.discordapp.net
""".strip()
    
    youtube_hosts = """
youtube.com
www.youtube.com
youtube-nocookie.com
ytimg.com
googlevideo.com
youtubei.googleapis.com
""".strip()
    
    telegram_hosts = """
telegram.org
telegram.me
t.me
tdesktop.com
core.telegram.org
api.telegram.org
""".strip()
    
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(CONFIG_DIR / "discord_hosts.txt", "w") as f:
        f.write(discord_hosts)
    
    with open(CONFIG_DIR / "youtube_hosts.txt", "w") as f:
        f.write(youtube_hosts)
    
    with open(CONFIG_DIR / "telegram_hosts.txt", "w") as f:
        f.write(telegram_hosts)
