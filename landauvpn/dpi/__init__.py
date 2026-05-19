"""
LandauVPN - DPI Module
Встроенный DPI обходчик
"""

from .bypasser import (
    DPIBypasser,
    DPIConfig,
    get_dpi_bypasser,
    create_default_hostlists
)

__all__ = [
    "DPIBypasser",
    "DPIConfig",
    "get_dpi_bypasser",
    "create_default_hostlists"
]
