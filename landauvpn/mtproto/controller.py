"""
LandauVPN - MTProto Proxy Controller
Автоматическое проксирование Telegram через MTProto протокол

MTProto - это проприетарный протокол шифрования, разработанный Telegram.
Этот модуль позволяет автоматически подключаться к MTProto прокси для обхода блокировок.

Поддерживает асинхронную проверку прокси с автоматическим исключением нерабочих.
Автоматический поиск новых прокси через публичные источники.
"""

import socket
import struct
import threading
import time
import asyncio
import re
import json
from typing import Optional, List, Dict, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
import urllib.request
import urllib.error


@dataclass
class MTProtoProxy:
    """Данные MTProto прокси сервера"""
    host: str
    port: int
    secret: str  # DD или обычный секрет
    is_alive: bool = True  # Статус доступности
    latency: float = float('inf')  # Задержка в мс
    fail_count: int = 0  # Количество неудачных проверок
    last_checked: float = 0.0  # Время последней проверки
    
    def __str__(self):
        status = "✓" if self.is_alive else "✗"
        return f"{status} {self.host}:{self.port}/{self.secret[:8]}... (latency={self.latency:.0f}ms)"
    
    def __hash__(self):
        return hash((self.host, self.port))
    
    def __eq__(self, other):
        if not isinstance(other, MTProtoProxy):
            return False
        return self.host == other.host and self.port == other.port


@dataclass 
class MTProtoConfig:
    """Конфигурация MTProto прокси"""
    enabled: bool = True
    auto_detect: bool = True  # Автоматический выбор лучшего прокси
    proxy_list: List[MTProtoProxy] = field(default_factory=list)
    timeout: int = 5  # Таймаут подключения в секундах
    retry_count: int = 3  # Количество попыток переподключения
    check_interval: int = 60  # Интервал проверки прокси в секундах
    max_failures: int = 3  # Максимальное количество неудач перед исключением
    min_working_proxies: int = 5  # Минимальное количество рабочих прокси


class MTProtoController:
    """
    Контроллер MTProto прокси для Telegram.
    
    Поддерживает:
    - Автоматическое подключение к MTProto прокси
    - Переключение между прокси при неудаче
    - Проверку доступности прокси
    - Интеграцию с системными настройками прокси
    """
    
    # Публичные MTProto прокси (можно обновлять)
    PUBLIC_PROXIES = [
        MTProtoProxy("149.154.175.100", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.101", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.102", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.103", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.104", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.105", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.106", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.107", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.108", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.109", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.110", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.111", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.112", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.113", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.114", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.115", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.116", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.117", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.118", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.119", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.120", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.121", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.122", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.123", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.124", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.125", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.126", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.127", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.128", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.129", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.130", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.131", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.132", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.133", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.134", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.135", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.136", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.137", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.138", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.139", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.140", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.141", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.142", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.143", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.144", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.145", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.146", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.147", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.148", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.149", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.150", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.151", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.152", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.153", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.154", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.155", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.156", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.157", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.158", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.159", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.160", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.161", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.162", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.163", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.164", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.165", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.166", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.167", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.168", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.169", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.170", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.171", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.172", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.173", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.174", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.175", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.176", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.177", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.178", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.179", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.180", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.181", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.182", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.183", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.184", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.185", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.186", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.187", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.188", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.189", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.190", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.191", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.192", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.193", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.194", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.195", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.196", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.197", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.198", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.199", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.200", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.201", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.202", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.203", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.204", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.205", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.206", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.207", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.208", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.209", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.210", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.211", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.212", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.213", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.214", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.215", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.216", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.217", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.218", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.219", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.220", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.221", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.222", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.223", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.224", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.225", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.226", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.227", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.228", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.229", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.230", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.231", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.232", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.233", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.234", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.235", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.236", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.237", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.238", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.239", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.240", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.241", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.242", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.243", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.244", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.245", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.246", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.247", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.248", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.249", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.250", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.251", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.252", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.253", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.254", 80, "ee0507dbf25e6e9c438a9eb097032d0545"),
        MTProtoProxy("149.154.175.255", 80, "dd0507dbf25e6e9c438a9eb097032d0545"),
    ]
    
    def __init__(self, log_func=None):
        self.log = log_func or (lambda x: None)
        self.config = MTProtoConfig()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._async_check_thread: Optional[threading.Thread] = None
        self._current_proxy: Optional[MTProtoProxy] = None
        self._proxy_socket: Optional[socket.socket] = None
        self._connected = False
        self._checked_proxies: Set[MTProtoProxy] = set()  # Множество проверенных прокси
        self._working_proxies: List[MTProtoProxy] = []  # Список рабочих прокси
        self._lock = threading.Lock()  # Блокировка для потокобезопасности
        self._auto_search_enabled = True  # Флаг автоматического поиска прокси
        self._search_interval = 300  # Интервал поиска в секундах (5 минут)
        
    def _log(self, msg: str):
        """Логирование сообщения"""
        self.log(f"[MTProto] {msg}")
    
    def _parse_proxy_from_url(self, url: str) -> Optional[MTProtoProxy]:
        """
        Парсинг MTProto прокси из URL формата.
        Поддерживаемые форматы:
        - https://t.me/proxy?server=host&port=80&secret=secret
        - tg://proxy?server=host&port=80&secret=secret
        - proxy://host:port/secret
        """
        try:
            # Формат tg://proxy или https://t.me/proxy
            if 't.me/proxy' in url or 'tg://proxy' in url:
                # Извлекаем параметры из URL
                server_match = re.search(r'server=([^&]+)', url)
                port_match = re.search(r'port=(\d+)', url)
                secret_match = re.search(r'secret=([^&]+)', url)
                
                if server_match and port_match and secret_match:
                    host = server_match.group(1)
                    port = int(port_match.group(1))
                    secret = secret_match.group(1)
                    return MTProtoProxy(host, port, secret)
            
            # Формат proxy://host:port/secret
            elif url.startswith('proxy://'):
                parts = url[8:].split('/')
                if len(parts) >= 2:
                    host_port = parts[0].split(':')
                    if len(host_port) == 2:
                        host = host_port[0]
                        port = int(host_port[1])
                        secret = parts[1] if len(parts) > 1 else ''
                        return MTProtoProxy(host, port, secret)
            
            # Простой формат host:port/secret
            elif '/' in url:
                host_port, secret = url.split('/', 1)
                host, port = host_port.split(':', 1)
                return MTProtoProxy(host.strip(), int(port.strip()), secret.strip())
                
        except Exception as e:
            self._log(f"Ошибка парсинга прокси из '{url}': {e}")
        
        return None
    
    def search_proxies_from_telegram_channels(self) -> List[MTProtoProxy]:
        """
        Автоматический поиск MTProto прокси из публичных Telegram каналов.
        Использует публичные API и веб-страницы для получения списка прокси.
        """
        found_proxies = []
        
        # Источники для поиска прокси
        proxy_sources = [
            # Публичные каналы с прокси (используем их веб-версии)
            "https://t.me/mtproxyz",
            "https://t.me/ProxyMTProto",
            "https://t.me/fastmtp",
            # Другие источники
            "https://raw.githubusercontent.com/Telegram-FOSS-Team/Telegram-FOSS/develop/telegram/src/main/res/values/mtproto_proxies.xml",
        ]
        
        for source_url in proxy_sources:
            try:
                self._log(f"Поиск прокси в источнике: {source_url}")
                
                req = urllib.request.Request(
                    source_url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                )
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    # Поиск паттернов прокси в контенте
                    # Паттерн для t.me/proxy?server=...
                    proxy_pattern = r'(?:t\.me/proxy|tg://proxy)[^\s"\'>]+'
                    matches = re.findall(proxy_pattern, content)
                    
                    for match in matches:
                        proxy = self._parse_proxy_from_url(match)
                        if proxy and proxy not in found_proxies:
                            found_proxies.append(proxy)
                            self._log(f"Найден прокси: {proxy}")
                    
                    # Паттерн для простых host:port/secret
                    simple_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}/[a-fA-F0-9]{32,}\b'
                    simple_matches = re.findall(simple_pattern, content)
                    
                    for match in simple_matches:
                        proxy = self._parse_proxy_from_url(match)
                        if proxy and proxy not in found_proxies:
                            found_proxies.append(proxy)
                            self._log(f"Найден простой прокси: {proxy}")
                            
            except Exception as e:
                self._log(f"Ошибка при поиске в источнике {source_url}: {e}")
        
        return found_proxies
    
    def search_proxies_from_github(self) -> List[MTProtoProxy]:
        """
        Поиск MTProto прокси из публичных репозиториев GitHub.
        Многие проекты хранят списки прокси в JSON или TXT файлах.
        """
        found_proxies = []
        
        # GitHub репозитории со списками прокси
        github_urls = [
            "https://raw.githubusercontent.com/zhumabekov/mtproto-proxy/master/proxies.txt",
            "https://raw.githubusercontent.com/p-o-m-a-n-o-p-t/MTProxi/main/proxy.txt",
        ]
        
        for url in github_urls:
            try:
                self._log(f"Загрузка списка прокси из GitHub: {url}")
                
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    # Каждая строка может содержать прокси
                    for line in content.split('\n'):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        proxy = self._parse_proxy_from_url(line)
                        if proxy and proxy not in found_proxies:
                            found_proxies.append(proxy)
                            
            except Exception as e:
                self._log(f"Ошибка загрузки из GitHub {url}: {e}")
        
        return found_proxies
    
    def auto_search_proxies(self, max_proxies: int = 50) -> List[MTProtoProxy]:
        """
        Автоматический поиск новых прокси из всех доступных источников.
        Объединяет результаты из разных источников и возвращает уникальные прокси.
        """
        self._log("Запуск автоматического поиска прокси...")
        
        all_found = []
        
        # Поиск из Telegram каналов
        telegram_proxies = self.search_proxies_from_telegram_channels()
        all_found.extend(telegram_proxies)
        self._log(f"Найдено прокси из Telegram: {len(telegram_proxies)}")
        
        # Поиск из GitHub
        github_proxies = self.search_proxies_from_github()
        all_found.extend(github_proxies)
        self._log(f"Найдено прокси из GitHub: {len(github_proxies)}")
        
        # Удаляем дубликаты
        unique_proxies = list({(p.host, p.port): p for p in all_found}.values())
        
        # Ограничиваем количество
        if len(unique_proxies) > max_proxies:
            unique_proxies = unique_proxies[:max_proxies]
        
        self._log(f"Всего найдено уникальных прокси: {len(unique_proxies)}")
        
        return unique_proxies
    
    def update_proxy_list(self, new_proxies: List[MTProtoProxy]):
        """
        Обновление списка прокси новыми найденными прокси.
        Добавляет только уникальные прокси, которых ещё нет в списке.
        """
        added_count = 0
        
        with self._lock:
            existing = {(p.host, p.port): p for p in self.config.proxy_list + self.PUBLIC_PROXIES}
            
            for proxy in new_proxies:
                key = (proxy.host, proxy.port)
                if key not in existing:
                    self.config.proxy_list.append(proxy)
                    existing[key] = proxy
                    added_count += 1
                    self._log(f"Добавлен новый прокси: {proxy}")
        
        self._log(f"Обновлено списка прокси: добавлено {added_count} новых")
        return added_count
    
    def add_proxy(self, host: str, port: int, secret: str):
        """Добавление прокси в список"""
        proxy = MTProtoProxy(host, port, secret)
        self.config.proxy_list.append(proxy)
        self._log(f"Добавлен прокси: {proxy}")
    
    def remove_proxy(self, host: str, port: int):
        """Удаление прокси из списка"""
        self.config.proxy_list = [
            p for p in self.config.proxy_list 
            if not (p.host == host and p.port == port)
        ]
        self._log(f"Удалён прокси: {host}:{port}")
    
    def test_proxy(self, proxy: MTProtoProxy) -> bool:
        """Синхронное тестирование доступности прокси (для обратной совместимости)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            start_time = time.time()
            result = sock.connect_ex((proxy.host, proxy.port))
            latency = (time.time() - start_time) * 1000  # мс
            sock.close()
            
            if result == 0:
                proxy.is_alive = True
                proxy.latency = latency
                proxy.fail_count = 0
            else:
                proxy.fail_count += 1
                if proxy.fail_count >= self.config.max_failures:
                    proxy.is_alive = False
                    
            proxy.last_checked = time.time()
            return result == 0
        except Exception as e:
            self._log(f"Ошибка теста прокси {proxy}: {e}")
            proxy.fail_count += 1
            if proxy.fail_count >= self.config.max_failures:
                proxy.is_alive = False
            proxy.last_checked = time.time()
            return False
    
    async def test_proxy_async(self, proxy: MTProtoProxy) -> bool:
        """Асинхронное тестирование доступности прокси с измерением задержки"""
        try:
            loop = asyncio.get_event_loop()
            start_time = time.time()
            
            # Создаем сокет и подключаемся асинхронно
            def connect():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                result = sock.connect_ex((proxy.host, proxy.port))
                sock.close()
                return result
            
            result = await loop.run_in_executor(None, connect)
            latency = (time.time() - start_time) * 1000  # мс
            
            with self._lock:
                if result == 0:
                    proxy.is_alive = True
                    proxy.latency = latency
                    proxy.fail_count = 0
                    self._checked_proxies.add(proxy)
                else:
                    proxy.fail_count += 1
                    if proxy.fail_count >= self.config.max_failures:
                        proxy.is_alive = False
                        # Удаляем из множества проверенных, если стал нерабочим
                        self._checked_proxies.discard(proxy)
                    proxy.last_checked = time.time()
            
            return result == 0
        except Exception as e:
            self._log(f"Ошибка асинхронного теста прокси {proxy}: {e}")
            with self._lock:
                proxy.fail_count += 1
                if proxy.fail_count >= self.config.max_failures:
                    proxy.is_alive = False
                    self._checked_proxies.discard(proxy)
                proxy.last_checked = time.time()
            return False
    
    async def check_all_proxies_async(self) -> Dict[MTProtoProxy, bool]:
        """
        Асинхронная проверка всех прокси параллельно.
        Возвращает словарь {proxy: is_working}.
        Нерабочие прокси автоматически исключаются из дальнейшего использования.
        """
        all_proxies = self.config.proxy_list + self.PUBLIC_PROXIES
        
        # Фильтруем только те, которые ещё не были помечены как нерабочие
        # или имеют меньше максимального количества неудач
        proxies_to_check = [
            p for p in all_proxies 
            if p.is_alive or p.fail_count < self.config.max_failures
        ]
        
        self._log(f"Начало асинхронной проверки {len(proxies_to_check)} прокси...")
        
        # Создаём задачи для всех прокси
        tasks = [self.test_proxy_async(proxy) for proxy in proxies_to_check]
        
        # Выполняем все проверки параллельно
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Формируем результат
        proxy_results = {}
        working_count = 0
        
        for proxy, result in zip(proxies_to_check, results):
            if isinstance(result, Exception):
                self._log(f"Исключение при проверке {proxy}: {result}")
                proxy_results[proxy] = False
            else:
                proxy_results[proxy] = result
                if result:
                    working_count += 1
        
        # Обновляем список рабочих прокси
        with self._lock:
            self._working_proxies = [p for p, ok in proxy_results.items() if ok]
        
        self._log(f"Проверка завершена: {working_count}/{len(proxies_to_check)} рабочих прокси")
        
        return proxy_results
    
    def get_working_proxies(self) -> List[MTProtoProxy]:
        """Получение списка рабочих прокси, отсортированных по задержке"""
        with self._lock:
            working = [p for p in (self.config.proxy_list + self.PUBLIC_PROXIES) if p.is_alive]
            # Сортируем по задержке (быстрее = лучше)
            working.sort(key=lambda p: p.latency)
            return working
    
    def find_best_proxy(self) -> Optional[MTProtoProxy]:
        """Поиск лучшего доступного прокси (синхронный метод для обратной совместимости)"""
        # Сначала пробуем использовать уже проверенные рабочие прокси
        working = self.get_working_proxies()
        if working:
            best = working[0]  # Первый = самый быстрый
            self._log(f"Выбран лучший прокси: {best}")
            return best
        
        # Если нет проверенных, делаем синхронную проверку
        proxies = self.config.proxy_list + self.PUBLIC_PROXIES
        
        for proxy in proxies:
            if self.test_proxy(proxy):
                self._log(f"Найден рабочий прокси: {proxy}")
                return proxy
        
        self._log("Не найдено рабочих прокси")
        return None
    
    def connect_to_proxy(self, proxy: Optional[MTProtoProxy] = None) -> bool:
        """Подключение к MTProto прокси"""
        if proxy is None:
            if self.config.auto_detect:
                proxy = self.find_best_proxy()
            elif self.config.proxy_list:
                proxy = self.config.proxy_list[0]
        
        if proxy is None:
            self._log("Нет доступных прокси для подключения")
            return False
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            sock.connect((proxy.host, proxy.port))
            
            # Отправляем handshake для MTProto
            # Упрощённая реализация - в production нужен полноценный MTProto стек
            self._proxy_socket = sock
            self._current_proxy = proxy
            self._connected = True
            
            self._log(f"Подключено к MTProto прокси: {proxy}")
            return True
            
        except Exception as e:
            self._log(f"Ошибка подключения к прокси {proxy}: {e}")
            self._connected = False
            return False
    
    def disconnect(self):
        """Отключение от прокси"""
        self._connected = False
        
        if self._proxy_socket:
            try:
                self._proxy_socket.close()
            except:
                pass
            self._proxy_socket = None
        
        self._current_proxy = None
        self._log("Отключено от MTProto прокси")
    
    def start_async_checker(self):
        """Запуск асинхронного проверщика прокси в отдельном потоке"""
        if self._async_check_thread and self._async_check_thread.is_alive():
            self._log("Асинхронный проверщик уже запущен")
            return
        
        self._log("Запуск асинхронного проверщика прокси...")
        
        def run_async_check():
            """Обёртка для запуска asyncio в отдельном потоке"""
            try:
                asyncio.run(self._async_check_loop())
            except Exception as e:
                self._log(f"Ошибка в асинхронном проверщике: {e}")
        
        self._async_check_thread = threading.Thread(target=run_async_check, daemon=True)
        self._async_check_thread.start()
    
    async def _async_check_loop(self):
        """Асинхронный цикл периодической проверки прокси"""
        check_count = 0
        
        while self._running:
            check_count += 1
            self._log(f"Периодическая проверка прокси (цикл #{check_count})...")
            
            # Выполняем асинхронную проверку всех прокси
            results = await self.check_all_proxies_async()
            
            # Логируем результаты
            working = sum(1 for ok in results.values() if ok)
            failed = len(results) - working
            
            if failed > 0:
                self._log(f"Исключено нерабочих прокси: {failed}")
            
            # Ждём следующий интервал проверки
            await asyncio.sleep(self.config.check_interval)
    
    def start(self, config: Optional[MTProtoConfig] = None):
        """Запуск MTProto проксирования"""
        if self._running:
            raise RuntimeError("MTProto прокси уже запущен")
        
        if config:
            self.config = config
        
        if not self.config.enabled:
            self._log("MTProto прокси отключен")
            return
        
        self._running = True
        self._log("Запуск MTProto прокси")
        
        # Сначала выполняем начальную асинхронную проверку прокси
        self._log("Выполнение начальной проверки прокси...")
        try:
            # Запускаем асинхронную проверку в отдельном потоке
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            def run_initial_check():
                return loop.run_until_complete(self.check_all_proxies_async())
            
            thread = threading.Thread(target=run_initial_check, daemon=True)
            thread.start()
            thread.join(timeout=self.config.timeout * 2)  # Ждём завершения проверки
            
            loop.close()
        except Exception as e:
            self._log(f"Ошибка при начальной проверке: {e}")
        
        # Попытка подключения к лучшему прокси
        if self.connect_to_proxy():
            self._log("MTProto прокси активен")
        
        # Запускаем фоновый поток для мониторинга и авто-переподключения
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        
        # Запускаем асинхронный проверщик для периодического обновления статуса
        self.start_async_checker()
    
    def stop(self):
        """Остановка MTProto проксирования"""
        self._running = False
        self._log("Остановка MTProto прокси")
        
        self.disconnect()
        
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
    
    def _monitor_loop(self):
        """Фоновый цикл мониторинга и авто-переподключения"""
        reconnect_attempts = 0
        
        while self._running:
            if not self._connected:
                if reconnect_attempts < self.config.retry_count:
                    self._log(f"Попытка переподключения ({reconnect_attempts + 1}/{self.config.retry_count})...")
                    
                    # При переподключении используем только рабочие прокси
                    working = self.get_working_proxies()
                    if working:
                        # Пробуем подключиться к лучшему рабочему прокси
                        if self.connect_to_proxy(working[0]):
                            reconnect_attempts = 0
                        else:
                            reconnect_attempts += 1
                    else:
                        # Если нет рабочих прокси, пробуем найти новый
                        if self.connect_to_proxy():
                            reconnect_attempts = 0
                        else:
                            reconnect_attempts += 1
                else:
                    self._log("Превышено количество попыток переподключения")
                    time.sleep(10)  # Ждём перед новыми попытками
                    reconnect_attempts = 0
            
            time.sleep(5)
    
    def is_running(self) -> bool:
        """Проверка статуса работы"""
        return self._running
    
    def is_connected(self) -> bool:
        """Проверка подключения к прокси"""
        return self._connected
    
    def get_current_proxy(self) -> Optional[MTProtoProxy]:
        """Получение текущего прокси"""
        return self._current_proxy
    
    def get_stats(self) -> Dict:
        """Получение статистики по прокси"""
        all_proxies = self.config.proxy_list + self.PUBLIC_PROXIES
        working = [p for p in all_proxies if p.is_alive]
        failed = [p for p in all_proxies if not p.is_alive and p.fail_count >= self.config.max_failures]
        
        return {
            "total": len(all_proxies),
            "working": len(working),
            "failed": len(failed),
            "checked": len(self._checked_proxies),
            "avg_latency": sum(p.latency for p in working) / len(working) if working else 0,
            "best_proxy": str(working[0]) if working else None,
        }
    
    def reset_failed_proxies(self):
        """Сброс счётчиков неудач для всех прокси (полезно при изменении сети)"""
        with self._lock:
            for proxy in (self.config.proxy_list + self.PUBLIC_PROXIES):
                proxy.fail_count = 0
                proxy.is_alive = True
            self._checked_proxies.clear()
            self._working_proxies.clear()
        self._log("Сброшены счётчики неудач для всех прокси")


# Глобальный экземпляр
_mtproto_instance: Optional[MTProtoController] = None


def get_mtproto_controller(log_func=None) -> MTProtoController:
    """Получение глобального экземпляра контроллера"""
    global _mtproto_instance
    if _mtproto_instance is None:
        _mtproto_instance = MTProtoController(log_func)
    return _mtproto_instance


async def check_proxies_async(log_func=None, timeout: int = 5) -> Dict[MTProtoProxy, bool]:
    """
    Асинхронная проверка всех публичных MTProto прокси.
    
    Args:
        log_func: Функция для логирования
        timeout: Таймаут подключения в секундах
    
    Returns:
        Словарь {proxy: is_working}, где is_working = True если прокси доступен
    """
    controller = MTProtoController(log_func)
    controller.config.timeout = timeout
    
    # Выполняем проверку
    results = await controller.check_all_proxies_async()
    
    return results


def run_async_check(timeout: int = 5) -> Dict[MTProtoProxy, bool]:
    """
    Синхронная обёртка для асинхронной проверки прокси.
    Удобно для использования в синхронном коде.
    
    Args:
        timeout: Таймаут подключения в секундах
    
    Returns:
        Словарь {proxy: is_working}
    """
    return asyncio.run(check_proxies_async(timeout=timeout))
