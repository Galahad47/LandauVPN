"""
LandauVPN - MTProto Module
Автоматическое проксирование Telegram через MTProto
"""

from .controller import (
    MTProtoController,
    MTProtoProxy,
    MTProtoConfig,
    get_mtproto_controller
)

__all__ = [
    "MTProtoController",
    "MTProtoProxy",
    "MTProtoConfig",
    "get_mtproto_controller"
]
