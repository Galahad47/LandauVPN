"""Core module for VPN profiles and controller"""

from .models import (
    VPNProfile,
    is_url,
    is_vpngate_ref,
    parse_vpngate_ref,
    safe_filename,
    fetch_vpngate_profiles,
    load_profiles,
    save_profiles,
    load_free_profiles_from_json,
    save_free_profiles_json,
)

from .vpn_controller import VPNController

__all__ = [
    "VPNProfile",
    "is_url",
    "is_vpngate_ref",
    "parse_vpngate_ref",
    "safe_filename",
    "fetch_vpngate_profiles",
    "load_profiles",
    "save_profiles",
    "load_free_profiles_from_json",
    "save_free_profiles_json",
    "VPNController",
]
