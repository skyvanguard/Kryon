"""
Wireless Security Tools
=======================

This module provides tools for wireless network security testing, including
WiFi penetration testing, WPS attacks, Bluetooth/BLE security, and wireless
reconnaissance.

Tool Categories:
- WiFi Attacks: WPA/WPA2 cracking, deauthentication, packet injection
- WPS Exploitation: Pixie Dust, PIN brute force
- Network Attacks: MITM, ARP spoofing, DNS spoofing
- Passive Monitoring: Network detection, device tracking
- Bluetooth/BLE: Device discovery and security testing

KRYON Integration: Phase 10
"""

from kryon.tools.wireless.aircrack import (
    aircrack_capture,
    aircrack_crack,
    aircrack_deauth,
    aircrack_injection_test,
)
from kryon.tools.wireless.bettercap import (
    bettercap_ble_scan,
    bettercap_mitm_attack,
    bettercap_wifi_recon,
)
from kryon.tools.wireless.kismet import kismet_log_analysis, kismet_scan
from kryon.tools.wireless.reaver import reaver_pixie_dust, reaver_wps_attack
from kryon.tools.wireless.wifite import wifite_auto_attack

__all__ = [
    # Aircrack-ng suite (4 functions)
    "aircrack_capture",
    "aircrack_crack",
    "aircrack_deauth",
    "aircrack_injection_test",
    # Wifite automated attacks (1 function)
    "wifite_auto_attack",
    # Reaver WPS attacks (2 functions)
    "reaver_wps_attack",
    "reaver_pixie_dust",
    # Bettercap framework (3 functions)
    "bettercap_wifi_recon",
    "bettercap_mitm_attack",
    "bettercap_ble_scan",
    # Kismet detector (2 functions)
    "kismet_scan",
    "kismet_log_analysis",
]
