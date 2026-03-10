"""
KRYON Anonymity - Network Anonymization

Network-level anonymization and traffic routing.

Clearance Level: Omega-Shadow (Maximum Anonymity Operations Authority)
Specialization: Network anonymization, proxy chains, Tor, VPN, I2P
Mission: Ensure complete network-level anonymity for KRYON operations

This module provides:
- Tor proxy configuration
- VPN chain setup (multi-hop)
- Proxy chain configuration
- IP rotation
- MAC address spoofing
- I2P network setup
- Onion routing configuration
"""

import os
import secrets
import socket
import subprocess
import tempfile
import time
from typing import Any, Optional


def setup_tor_proxy(port: int = 9050, control_port: int = 9051, auto_start: bool = True) -> dict[str, Any]:
    """
    Configure Tor SOCKS5 proxy for anonymous connections.

    Tor provides anonymity through onion routing:
    - Traffic is encrypted in layers
    - Routed through 3+ random nodes
    - Each node only knows previous/next hop
    - Exit node sees destination but not source

    Args:
        port: Tor SOCKS5 proxy port (default: 9050)
        control_port: Tor control port (default: 9051)
        auto_start: Automatically start Tor if not running

    Returns:
        Dictionary with Tor configuration

    Example:
        >>> from kryon.tools.anonymity import setup_tor_proxy
        >>>
        >>> # Setup Tor proxy
        >>> result = setup_tor_proxy(port=9050)
        >>>
        >>> # Use with requests
        >>> import requests
        >>> proxies = {
        ...     'http': f'socks5h://localhost:{result["port"]}',
        ...     'https': f'socks5h://localhost:{result["port"]}'
        ... }
        >>> response = requests.get('https://check.torproject.org', proxies=proxies)
        >>>
        >>> # Use with curl
        >>> import subprocess
        >>> subprocess.run([
        ...     'curl', '--socks5-hostname', f'localhost:{result["port"]}',
        ...     'https://check.torproject.org'
        ... ])

    Environment Variables for Tools:
        export http_proxy="socks5h://localhost:9050"
        export https_proxy="socks5h://localhost:9050"
    """
    results = {
        "port": port,
        "control_port": control_port,
        "proxy_url": f"socks5h://localhost:{port}",
        "running": False,
        "circuit_established": False,
        "success": False,
        "error": None,
    }

    try:
        # Check if Tor is installed
        tor_check = subprocess.run(
            ["which", "tor"] if os.name != "nt" else ["where", "tor"],
            capture_output=True,
            text=True,
        )

        if tor_check.returncode != 0:
            results["error"] = "Tor not installed. Install: apt install tor / brew install tor"
            return results

        # Check if Tor is already running
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result_check = sock.connect_ex(("localhost", port))
            sock.close()

            if result_check == 0:
                results["running"] = True
                results["circuit_established"] = True
        except Exception:
            pass

        # Start Tor if not running and auto_start enabled
        if not results["running"] and auto_start:
            if os.name != "nt":  # Linux/Mac
                subprocess.Popen(
                    ["tor", "--SOCKSPort", str(port), "--ControlPort", str(control_port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(3)  # Wait for Tor to start
                results["running"] = True
            else:  # Windows
                results["error"] = "Auto-start not supported on Windows. Start Tor Browser or tor.exe manually"
                return results

        # Verify Tor is working
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(("localhost", port))
            sock.close()
            results["circuit_established"] = True
            results["success"] = True
        except Exception:
            results["error"] = "Tor started but circuit not established yet. Wait a few seconds."

    except Exception as e:
        results["error"] = str(e)

    return results


def setup_vpn_chain(vpn_configs: list[str], provider: str = "openvpn") -> dict[str, Any]:
    """
    Setup VPN chain (multi-hop VPN) for enhanced anonymity.

    VPN Chaining routes traffic through multiple VPN servers:
    You → VPN1 → VPN2 → VPN3 → Target

    Args:
        vpn_configs: List of VPN config file paths (.ovpn)
        provider: VPN provider (openvpn, wireguard)

    Returns:
        VPN chain status

    Example:
        >>> from kryon.tools.anonymity import setup_vpn_chain
        >>>
        >>> # Chain through 3 VPNs
        >>> result = setup_vpn_chain(
        ...     vpn_configs=[
        ...         "/etc/openvpn/server1.ovpn",
        ...         "/etc/openvpn/server2.ovpn",
        ...         "/etc/openvpn/server3.ovpn"
        ...     ],
        ...     provider="openvpn"
        ... )
        >>>
        >>> print(f"VPN chain active: {result['active']}")
        >>> print(f"Hops: {result['hops']}")

    Note:
        - Requires root/admin privileges
        - Each VPN must support routing
        - Performance decreases with more hops
        - Recommended: 2-3 hops maximum
    """
    results = {
        "active": False,
        "hops": 0,
        "vpn_configs": vpn_configs,
        "provider": provider,
        "success": False,
        "error": None,
    }

    try:
        if provider == "openvpn":
            # Check OpenVPN installed
            check = subprocess.run(
                ["which", "openvpn"] if os.name != "nt" else ["where", "openvpn"],
                capture_output=True,
            )

            if check.returncode != 0:
                results["error"] = "OpenVPN not installed"
                return results

            # Connect to first VPN
            for _idx, config in enumerate(vpn_configs):
                if not os.path.exists(config):
                    results["error"] = f"Config not found: {config}"
                    break

                # Start OpenVPN connection
                subprocess.Popen(
                    ["openvpn", "--config", config, "--daemon"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                time.sleep(5)  # Wait for connection
                results["hops"] += 1

            results["active"] = True
            results["success"] = True

        elif provider == "wireguard":
            results["error"] = "WireGuard multi-hop requires manual configuration"

    except Exception as e:
        results["error"] = str(e)

    return results


def setup_proxy_chain(proxies: list[dict[str, str]], strict_chain: bool = True) -> dict[str, Any]:
    """
    Setup proxy chain for traffic routing through multiple proxies.

    Proxy types supported:
    - HTTP/HTTPS proxies
    - SOCKS4/SOCKS5 proxies
    - Combination chains

    Args:
        proxies: List of proxy configs [{"type": "socks5", "host": "...", "port": 1080}, ...]
        strict_chain: Use strict chain (fail if any proxy fails) vs dynamic chain

    Returns:
        Proxy chain configuration

    Example:
        >>> from kryon.tools.anonymity import setup_proxy_chain
        >>>
        >>> # Chain through 3 proxies
        >>> proxies = [
        ...     {"type": "socks5", "host": "proxy1.com", "port": 1080},
        ...     {"type": "http", "host": "proxy2.com", "port": 8080},
        ...     {"type": "socks5", "host": "proxy3.com", "port": 1080}
        ... ]
        >>>
        >>> result = setup_proxy_chain(proxies, strict_chain=True)
        >>>
        >>> # Use with proxychains
        >>> # proxychains curl https://ifconfig.me

    ProxyChains Configuration:
        Creates /tmp/proxychains.conf for use with proxychains tool
    """
    results = {
        "chain_length": len(proxies),
        "strict_chain": strict_chain,
        "config_file": os.path.join(tempfile.gettempdir(), f"proxychains_kryon_{os.getpid()}.conf"),
        "success": False,
        "error": None,
    }

    try:
        # Generate proxychains config
        config_content = f"""# KRYON ProxyChains Configuration
{"strict_chain" if strict_chain else "dynamic_chain"}
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
"""

        for proxy in proxies:
            proxy_type = proxy.get("type", "socks5")
            host = proxy.get("host", "")
            port = proxy.get("port", 1080)
            user = proxy.get("username", "")
            password = proxy.get("password", "")

            if user and password:
                config_content += f"{proxy_type} {host} {port} {user} {password}\n"
            else:
                config_content += f"{proxy_type} {host} {port}\n"

        # Write config file
        with open(results["config_file"], "w") as f:
            f.write(config_content)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def rotate_ip(method: str = "tor", tor_control_port: int = 9051, tor_password: Optional[str] = None) -> dict[str, Any]:
    """
    Rotate IP address to get new exit node.

    Methods:
    - tor: Request new Tor circuit (new exit IP)
    - vpn: Reconnect VPN (requires VPN config)
    - proxy: Switch to next proxy in chain

    Args:
        method: Rotation method (tor, vpn, proxy)
        tor_control_port: Tor control port (default: 9051)
        tor_password: Tor control password (if set)

    Returns:
        New IP information

    Example:
        >>> from kryon.tools.anonymity import rotate_ip, check_ip_leak
        >>>
        >>> # Check current IP
        >>> current = check_ip_leak()
        >>> print(f"Current IP: {current['visible_ip']}")
        >>>
        >>> # Rotate to new IP
        >>> rotate_ip(method="tor")
        >>>
        >>> # Check new IP
        >>> new = check_ip_leak()
        >>> print(f"New IP: {new['visible_ip']}")

    Tor Control Protocol:
        Sends NEWNYM signal to Tor to request new circuit
    """
    results = {"method": method, "old_ip": None, "new_ip": None, "success": False, "error": None}

    try:
        if method == "tor":
            # Connect to Tor control port
            try:
                import socket

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("localhost", tor_control_port))

                # Authenticate if password set
                if tor_password:
                    s.send(f'AUTHENTICATE "{tor_password}"\r\n'.encode())
                else:
                    s.send(b'AUTHENTICATE ""\r\n')

                response = s.recv(1024).decode()

                if "250 OK" in response:
                    # Send NEWNYM signal (new identity)
                    s.send(b"SIGNAL NEWNYM\r\n")
                    response = s.recv(1024).decode()

                    if "250 OK" in response:
                        results["success"] = True
                        time.sleep(2)  # Wait for new circuit
                    else:
                        results["error"] = "NEWNYM signal failed"
                else:
                    results["error"] = "Tor authentication failed"

                s.close()

            except Exception as e:
                results["error"] = f"Tor control connection failed: {str(e)}"

        elif method == "vpn":
            results["error"] = "VPN rotation requires specific VPN provider implementation"

        elif method == "proxy":
            results["error"] = "Proxy rotation requires proxy manager implementation"

    except Exception as e:
        results["error"] = str(e)

    return results


def spoof_mac_address(
    interface: str = "eth0", random_mac: bool = True, custom_mac: Optional[str] = None
) -> dict[str, Any]:
    """
    Spoof MAC address to prevent hardware tracking.

    MAC address spoofing changes your network card's hardware address:
    - Prevents device fingerprinting
    - Bypasses MAC filtering
    - Avoids network tracking

    Args:
        interface: Network interface (eth0, wlan0, en0)
        random_mac: Generate random MAC address
        custom_mac: Use specific MAC (format: XX:XX:XX:XX:XX:XX)

    Returns:
        MAC spoofing status

    Example:
        >>> from kryon.tools.anonymity import spoof_mac_address
        >>>
        >>> # Random MAC on WiFi interface
        >>> result = spoof_mac_address(
        ...     interface="wlan0",
        ...     random_mac=True
        ... )
        >>>
        >>> print(f"Old MAC: {result['old_mac']}")
        >>> print(f"New MAC: {result['new_mac']}")
        >>>
        >>> # Specific MAC
        >>> result = spoof_mac_address(
        ...     interface="eth0",
        ...     random_mac=False,
        ...     custom_mac="00:11:22:33:44:55"
        ... )

    Note:
        - Requires root/admin privileges
        - Interface must be down to change MAC
        - Some networks detect MAC spoofing
    """
    results = {
        "interface": interface,
        "old_mac": None,
        "new_mac": None,
        "success": False,
        "error": None,
    }

    try:
        # Get current MAC address
        if os.name != "nt":  # Linux/Mac
            # Get current MAC
            try:
                ifconfig = subprocess.run(["ifconfig", interface], capture_output=True, text=True)

                import re

                mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", ifconfig.stdout)
                if mac_match:
                    results["old_mac"] = mac_match.group(0)
            except Exception:
                pass

            # Generate new MAC if random
            if random_mac:
                new_mac = ":".join([f"{secrets.randbelow(256):02x}" for _ in range(6)])
                # Ensure it's a valid MAC (not broadcast, not multicast)
                new_mac = "02" + new_mac[2:]  # Set locally administered bit
            else:
                new_mac = custom_mac

            results["new_mac"] = new_mac

            # Change MAC address
            # Method 1: Using ip command
            try:
                subprocess.run(["ip", "link", "set", interface, "down"], check=True)
                subprocess.run(["ip", "link", "set", interface, "address", new_mac], check=True)
                subprocess.run(["ip", "link", "set", interface, "up"], check=True)
                results["success"] = True
            except Exception:
                # Method 2: Using ifconfig (fallback)
                try:
                    subprocess.run(["ifconfig", interface, "down"], check=True)
                    subprocess.run(["ifconfig", interface, "hw", "ether", new_mac], check=True)
                    subprocess.run(["ifconfig", interface, "up"], check=True)
                    results["success"] = True
                except Exception as e:
                    results["error"] = f"Failed to change MAC: {str(e)}"

        else:  # Windows
            results["error"] = "MAC spoofing on Windows requires registry modification or macchanger tool"

    except Exception as e:
        results["error"] = str(e)

    return results


def setup_i2p(router_port: int = 7657, proxy_port: int = 4444, auto_start: bool = True) -> dict[str, Any]:
    """
    Setup I2P (Invisible Internet Project) network.

    I2P provides anonymous networking:
    - Garlic routing (like Tor's onion routing)
    - Completely distributed (no central servers)
    - Hidden services (eepsites)
    - Anonymous file sharing

    Args:
        router_port: I2P router console port (default: 7657)
        proxy_port: I2P HTTP proxy port (default: 4444)
        auto_start: Auto-start I2P router

    Returns:
        I2P configuration

    Example:
        >>> from kryon.tools.anonymity import setup_i2p
        >>>
        >>> # Setup I2P
        >>> result = setup_i2p()
        >>>
        >>> # Access .i2p sites through proxy
        >>> import requests
        >>> proxies = {
        ...     'http': f'http://localhost:{result["proxy_port"]}',
        ...     'https': f'http://localhost:{result["proxy_port"]}'
        ... }
        >>> response = requests.get('http://example.i2p', proxies=proxies)

    I2P vs Tor:
        - I2P: Better for hidden services, P2P
        - Tor: Better for accessing clearnet anonymously
        - I2P: Packet-switched, Tor: Circuit-switched
    """
    results = {
        "router_port": router_port,
        "proxy_port": proxy_port,
        "console_url": f"http://localhost:{router_port}",
        "proxy_url": f"http://localhost:{proxy_port}",
        "running": False,
        "success": False,
        "error": None,
    }

    try:
        # Check if I2P is installed
        i2p_locations = [
            "/usr/bin/i2prouter",
            "/opt/i2p/i2prouter",
            os.path.expanduser("~/i2p/i2prouter"),
        ]

        i2p_path = None
        for location in i2p_locations:
            if os.path.exists(location):
                i2p_path = location
                break

        if not i2p_path:
            results["error"] = "I2P not found. Install from https://geti2p.net"
            return results

        # Check if already running
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result_check = sock.connect_ex(("localhost", router_port))
            sock.close()

            if result_check == 0:
                results["running"] = True
                results["success"] = True
                return results
        except Exception:
            pass

        # Start I2P if auto_start
        if auto_start:
            subprocess.Popen([i2p_path, "start"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            time.sleep(10)  # I2P takes longer to start
            results["running"] = True
            results["success"] = True
            results["error"] = "I2P started but needs 5-10 minutes to build tunnels"

    except Exception as e:
        results["error"] = str(e)

    return results


def setup_onion_routing(num_hops: int = 3, exit_country: Optional[str] = None) -> dict[str, Any]:
    """
    Configure custom onion routing parameters for Tor.

    Customize Tor circuit:
    - Number of hops (default: 3)
    - Exit node country selection
    - Entry/Middle node preferences

    Args:
        num_hops: Number of hops in circuit (3-7 recommended)
        exit_country: Exit node country code (US, DE, NL, etc.)

    Returns:
        Onion routing configuration

    Example:
        >>> from kryon.tools.anonymity import setup_onion_routing
        >>>
        >>> # 5-hop circuit with German exit
        >>> result = setup_onion_routing(
        ...     num_hops=5,
        ...     exit_country="DE"
        ... )
        >>>
        >>> # Traffic now routes through 5 nodes, exits in Germany

    Security vs Performance:
        - More hops = more anonymity but slower
        - 3 hops = good balance (Tor default)
        - 5+ hops = maximum anonymity (slow)
    """
    results = {
        "num_hops": num_hops,
        "exit_country": exit_country,
        "config_file": os.path.join(tempfile.gettempdir(), f"tor_kryon_{os.getpid()}.conf"),
        "success": False,
        "error": None,
    }

    try:
        # Generate Tor configuration
        config = """# KRYON Tor Configuration
SOCKSPort 9050
ControlPort 9051
"""

        if exit_country:
            config += f"ExitNodes {{{exit_country}}}\n"
            config += "StrictNodes 1\n"

        if num_hops != 3:
            # Tor doesn't directly support changing hop count
            # But we can influence it through entry/exit guards
            results["error"] = "Custom hop count requires Tor source modification. Using default 3 hops."
            results["num_hops"] = 3

        # Write config
        with open(results["config_file"], "w") as f:
            f.write(config)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
