"""Proxy module for DPI bypass (zapret-discord-youtube style)"""

from .controller import ProxyController, ProxyConfig, create_default_hostlists

__all__ = [
    "ProxyController",
    "ProxyConfig",
    "create_default_hostlists",
]
