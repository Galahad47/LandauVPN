import os
import platform
import subprocess
from pathlib import Path
from typing import Optional, List

from .models import VPNProfile, is_url, is_vpngate_ref, parse_vpngate_ref, safe_filename, _parse_vpngate_csv_lines
from utils.config import VPN_DOWNLOAD_DIR, REQUEST_TIMEOUT

import requests
import base64


class VPNController:
    """Контроллер для управления VPN подключениями"""
    
    def __init__(self, log_func):
        self.proc: Optional[subprocess.Popen] = None
        self.current_profile: Optional[VPNProfile] = None
        self.log = log_func

    def _fetch_live_vpngate_servers(self) -> List[dict]:
        """Получение текущего списка серверов VPNGate"""
        from .models import VPN_GATE_API
        r = requests.get(VPN_GATE_API, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return _parse_vpngate_csv_lines(r.text)

    def _download_profile_if_needed(self, profile: VPNProfile) -> str:
        """Скачивание или получение пути к конфигу профиля"""
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
                if (wanted_host and s["hostname"] == wanted_host) or (wanted_ip and s["ip"] == wanted_ip):
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
        """Построение команды запуска VPN для данной ОС"""
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
        """Специальная команда отключения WireGuard"""
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
        """Запуск VPN подключения"""
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
        """Остановка VPN подключения"""
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

    def is_connected(self) -> bool:
        """Проверка активного подключения"""
        return self.proc is not None and self.proc.poll() is None

    def get_current_profile(self) -> Optional[VPNProfile]:
        """Получение текущего профиля"""
        return self.current_profile
