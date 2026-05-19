"""
LandauVPN - Встроенный DPI обходчик (аналог zapret)
Собственная реализация обхода DPI для YouTube, Telegram и других сервисов
Использует методы: TCP segmentation, TTL manipulation, Fake packets
"""

import socket
import struct
import threading
import time
import random
from typing import Optional, List, Dict, Set, Tuple
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DPIConfig:
    """Конфигурация DPI обходчика"""
    enabled: bool = True
    mode: str = "auto"  # auto, youtube, telegram, all
    ttl_value: int = 2  # TTL для fake пакетов
    split_position: int = 1  # Позиция разделения TCP пакета
    use_fake: bool = True  # Использовать fake пакеты
    use_split: bool = True  # Использовать разделение пакетов
    desync_ttl: int = 2  # Auto TTL для десинхронизации
    hostlist: Optional[Set[str]] = None  # Список хостов для обработки
    
    def __post_init__(self):
        if self.hostlist is None:
            self.hostlist = set()


class DPIBypasser:
    """
    Собственный DPI обходчик LandauVPN.
    Реализует методы обхода DPI без внешних утилит.
    
    Методы:
    - TCP Segmentation: Разделение TCP пакетов на части
    - TTL Manipulation: Подделка TTL для обхода анализа
    - Fake Packets: Отправка поддельных пакетов для дезориентации DPI
    - HTTP Header Modification: Модификация заголовков HTTP
    """
    
    def __init__(self, log_func=None):
        self.log = log_func or (lambda x: None)
        self.config = DPIConfig()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sockets: List[socket.socket] = []
        self._rules: Dict[str, dict] = {}
        
    def _log(self, msg: str):
        """Логирование сообщения"""
        self.log(f"[DPI] {msg}")
    
    def add_host(self, hostname: str, rules: Optional[dict] = None):
        """Добавление хоста в список обработки"""
        self.config.hostlist.add(hostname.lower())
        if rules:
            self._rules[hostname.lower()] = rules
        self._log(f"Добавлен хост: {hostname}")
    
    def remove_host(self, hostname: str):
        """Удаление хоста из списка"""
        hostname = hostname.lower()
        self.config.hostlist.discard(hostname)
        self._rules.pop(hostname, None)
        self._log(f"Удалён хост: {hostname}")
    
    def _should_process(self, hostname: str) -> bool:
        """Проверка, нужно ли обрабатывать хост"""
        if not self.config.hostlist:
            return True  # Если список пуст, обрабатываем всё
        return hostname.lower() in self.config.hostlist
    
    def _get_rules_for_host(self, hostname: str) -> dict:
        """Получение правил для хоста"""
        hostname = hostname.lower()
        if hostname in self._rules:
            return self._rules[hostname]
        
        # Правила по умолчанию в зависимости от режима
        if self.config.mode == "youtube":
            return {
                "split": True,
                "split_pos": 1,
                "fake": True,
                "ttl": 2,
                "desync_ttl": True
            }
        elif self.config.mode == "telegram":
            return {
                "split": True,
                "split_pos": 1,
                "fake": True,
                "ttl": 2,
                "desync_ttl": True
            }
        else:  # auto или all
            return {
                "split": True,
                "split_pos": 1,
                "fake": True,
                "ttl": 2,
                "desync_ttl": True
            }
    
    def _create_fake_packet(self, data: bytes, ttl: int = 2) -> bytes:
        """Создание fake пакета с указанным TTL"""
        # Упрощённая реализация - в production нужен полноценный TCP стек
        # Здесь мы просто возвращаем данные с метаданными для последующей обработки
        header = struct.pack('>BB', 0xFA, 0xCE)  # Magic number для fake пакета
        header += struct.pack('>H', ttl)  # TTL
        header += struct.pack('>I', len(data))  # Длина данных
        return header + data
    
    def _split_tcp_segment(self, data: bytes, position: int = 1) -> List[bytes]:
        """Разделение TCP сегмента на части"""
        if len(data) <= position:
            return [data]
        return [data[:position], data[position:]]
    
    def _modify_http_headers(self, data: bytes) -> bytes:
        """Модификация HTTP заголовков для обхода DPI"""
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Добавление пробелов в заголовок Host (метод Zapret)
            if 'Host:' in text:
                text = text.replace('Host:', 'Host: ')
            
            # Замена Case в заголовках (метод GoodbyeDPI)
            text = text.replace('Host:', 'hOsT:')
            text = text.replace('User-Agent:', 'uSer-AgEnT:')
            text = text.replace('Accept:', 'aCcEpT:')
            
            return text.encode('utf-8', errors='ignore')
        except Exception as e:
            self._log(f"Ошибка модификации HTTP: {e}")
            return data
    
    def process_outgoing(self, data: bytes, hostname: str = "") -> List[bytes]:
        """
        Обработка исходящих данных перед отправкой.
        Возвращает список пакетов для отправки.
        """
        if not self._running or not self.config.enabled:
            return [data]
        
        if hostname and not self._should_process(hostname):
            return [data]
        
        rules = self._get_rules_for_host(hostname or "default")
        result = [data]
        
        # Применение правил
        if rules.get("http_modify", True):
            result = [self._modify_http_headers(result[0])]
        
        if rules.get("fake", self.config.use_fake) and self.config.use_fake:
            # Создаем fake пакет с низким TTL
            fake_pkt = self._create_fake_packet(result[0], self.config.ttl_value)
            result.insert(0, fake_pkt)
        
        if rules.get("split", self.config.use_split) and self.config.use_split:
            split_pos = rules.get("split_pos", self.config.split_position)
            new_result = []
            for pkt in result:
                new_result.extend(self._split_tcp_segment(pkt, split_pos))
            result = new_result
        
        self._log(f"Обработано {len(data)} байт для {hostname}, результат: {len(result)} пакетов")
        return result
    
    def start(self, config: Optional[DPIConfig] = None):
        """Запуск DPI обходчика"""
        if self._running:
            raise RuntimeError("DPI обходчик уже запущен")
        
        if config:
            self.config = config
        
        if not self.config.enabled:
            self._log("DPI обходчик отключен")
            return
        
        self._running = True
        self._log(f"Запуск DPI обходчика в режиме: {self.config.mode}")
        self._log(f"Хостов в списке: {len(self.config.hostlist)}")
        
        # Запускаем фоновый поток для мониторинга
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Остановка DPI обходчика"""
        self._running = False
        self._log("Остановка DPI обходчика")
        
        # Закрываем все сокеты
        for s in self._sockets:
            try:
                s.close()
            except:
                pass
        self._sockets.clear()
        
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
    
    def _monitor_loop(self):
        """Фоновый цикл мониторинга"""
        while self._running:
            time.sleep(1)
            # Здесь можно добавить статистику, переподключение и т.д.
    
    def is_running(self) -> bool:
        """Проверка статуса работы"""
        return self._running
    
    def set_mode(self, mode: str):
        """Изменение режима работы"""
        valid_modes = ["auto", "youtube", "telegram", "all"]
        if mode not in valid_modes:
            raise ValueError(f"Недопустимый режим: {mode}")
        
        was_running = self._running
        if was_running:
            self.stop()
        
        self.config.mode = mode
        self._log(f"Режим изменён на: {mode}")
        
        # Обновляем правила для режима
        if mode == "youtube":
            self.add_host("youtube.com")
            self.add_host("www.youtube.com")
            self.add_host("googlevideo.com")
            self.add_host("ytimg.com")
        elif mode == "telegram":
            self.add_host("telegram.org")
            self.add_host("t.me")
            self.add_host("telegram.me")
        elif mode == "all":
            # Добавляем популярные заблокированные сервисы
            for host in ["youtube.com", "telegram.org", "t.me", "discord.com", "twitter.com"]:
                self.add_host(host)
        
        if was_running:
            self.start()


# Глобальный экземпляр для использования в приложении
_dpi_instance: Optional[DPIBypasser] = None


def get_dpi_bypasser(log_func=None) -> DPIBypasser:
    """Получение глобального экземпляра DPI обходчика"""
    global _dpi_instance
    if _dpi_instance is None:
        _dpi_instance = DPIBypasser(log_func)
    return _dpi_instance


def create_default_hostlists():
    """Создание файлов со списками хостов по умолчанию"""
    import sys
    from pathlib import Path
    
    # Определяем CONFIG_DIR напрямую, чтобы избежать относительного импорта
    APP_NAME = "LandauVPN"
    CONFIG_DIR = Path.home() / f".{APP_NAME}"
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    # YouTube хосты
    youtube_hosts = "\n".join([
        "youtube.com",
        "www.youtube.com",
        "youtube-nocookie.com",
        "ytimg.com",
        "googlevideo.com",
        "youtubei.googleapis.com",
        "youtu.be"
    ])
    
    # Telegram хосты
    telegram_hosts = "\n".join([
        "telegram.org",
        "telegram.me",
        "t.me",
        "tdesktop.com",
        "core.telegram.org",
        "api.telegram.org",
        "web.telegram.org"
    ])
    
    # Discord хосты
    discord_hosts = "\n".join([
        "discord.com",
        "discord.gg",
        "discordapp.com",
        "discordapp.net",
        "cdn.discordapp.com",
        "gateway.discord.gg",
        "media.discordapp.net"
    ])
    
    # Все хосты вместе
    all_hosts = "\n".join([
        "# YouTube",
        "youtube.com",
        "www.youtube.com",
        "googlevideo.com",
        "",
        "# Telegram",
        "telegram.org",
        "t.me",
        "telegram.me",
        "",
        "# Discord",
        "discord.com",
        "discord.gg",
        "discordapp.com"
    ])
    
    with open(CONFIG_DIR / "dpi_youtube_hosts.txt", "w") as f:
        f.write(youtube_hosts)
    
    with open(CONFIG_DIR / "dpi_telegram_hosts.txt", "w") as f:
        f.write(telegram_hosts)
    
    with open(CONFIG_DIR / "dpi_discord_hosts.txt", "w") as f:
        f.write(discord_hosts)
    
    with open(CONFIG_DIR / "dpi_all_hosts.txt", "w") as f:
        f.write(all_hosts)
    
    return CONFIG_DIR
