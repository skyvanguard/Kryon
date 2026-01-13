"""
Kismet - Wireless Network Detector and IDS
===========================================

Kismet is a wireless network and device detector, sniffer, wardriving tool,
and WIDS (wireless intrusion detection system). Passive monitoring with
comprehensive device tracking.

PERFORMANCE: Passive scans are cached for 1 hour as they represent network
survey data that remains relatively stable over short periods.
"""

from skynet.cache import cache_scan_result
from skynet.sdk.agents import function_tool
from skynet.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="wireless_survey", ttl=3600)
def kismet_scan(
    interface: str = "",
    channel_hop: bool = True,
    channels: str = "",
    output_prefix: str = "kismet",
    duration: int = 300,
    gps_enabled: bool = False,
    ctf=None,
) -> str:
    """
    Passive wireless network detection and monitoring.

    Kismet provides comprehensive passive wireless monitoring, detecting
    WiFi, Bluetooth, and other wireless protocols without transmitting
    any packets. Excellent for stealthy reconnaissance.

    Args:
        interface: Wireless interface (auto-detects if not specified)
        channel_hop: Enable channel hopping
        channels: Specific channels to monitor (e.g., "1,6,11,36,40")
        output_prefix: Output file prefix for logs
        duration: Scan duration in seconds (0 = continuous)
        gps_enabled: Enable GPS tracking for wardriving
        ctf: CTF context for execution

    Returns:
        str: Detected networks, devices, and statistics

    Examples:
        # Quick passive scan
        kismet_scan(
            interface="wlan0",
            duration=60
        )

        # Comprehensive survey
        kismet_scan(
            interface="wlan0",
            channel_hop=True,
            duration=600,
            output_prefix="/tmp/site-survey"
        )

        # Specific channels only
        kismet_scan(
            interface="wlan0",
            channels="1,6,11",
            duration=300
        )

        # Wardriving with GPS
        kismet_scan(
            interface="wlan0",
            gps_enabled=True,
            duration=3600,
            output_prefix="/tmp/wardriving"
        )

        # 5GHz scan
        kismet_scan(
            interface="wlan0",
            channels="36,40,44,48,149,153,157,161",
            duration=300
        )

    Detected Information:

    Networks (Access Points):
        - SSID (network name)
        - BSSID (MAC address)
        - Channel
        - Encryption type
        - Signal strength (RSSI)
        - Manufacturer (OUI)
        - First/last seen timestamps
        - Packet counts
        - Data rates

    Clients (Devices):
        - MAC addresses
        - Associated AP
        - Probe requests
        - Device manufacturer
        - Signal strength
        - Connection history

    Security Analysis:
        - Encryption methods (WEP/WPA/WPA2/WPA3)
        - Open networks
        - WPS enabled
        - Hidden SSIDs
        - MAC filtering
        - Rogue APs

    Output Files:
        kismet-YYYYMMDD-HH-MM-SS-1.kismet    # Primary database
        kismet-YYYYMMDD-HH-MM-SS-1.pcapng    # Packet capture
        kismet-YYYYMMDD-HH-MM-SS-1.log       # Text log

    Channel Coverage:

    2.4 GHz (802.11b/g/n):
        US: 1-11
        Europe: 1-13
        Japan: 1-14
        Common: 1,6,11 (non-overlapping)

    5 GHz (802.11a/n/ac):
        Low: 36,40,44,48
        Mid: 52,56,60,64
        High: 149,153,157,161,165

    Passive vs Active:

    Passive (Kismet):
        + Undetectable (no transmissions)
        + Complete traffic capture
        + No authorization handshakes
        + Legal gray area is safer
        - Slower discovery
        - Requires patience
        - May miss hidden networks

    Active (Airodump):
        + Faster discovery
        + Probe hidden networks
        + Trigger responses
        - Detectable (sends probes)
        - Leaves traces
        - Higher legal risk

    Use Cases:

    Site Survey:
        - Identify all networks in area
        - Signal strength mapping
        - Channel utilization
        - Interference analysis

    Security Assessment:
        - Find rogue access points
        - Detect unauthorized devices
        - Identify weak encryption
        - Monitor for attacks

    Wardriving:
        - Map wireless networks geographically
        - Create coverage maps
        - Identify security issues at scale

    WIDS (Intrusion Detection):
        - Detect deauth attacks
        - Identify MAC spoofing
        - Monitor for rogue APs
        - Alert on suspicious activity

    Integration:

    Analysis Tools:
        # Convert to Wigle CSV
        kismet_to_wigle kismet-*.kismet

        # Extract to KML (Google Earth)
        kismet_to_kml kismet-*.kismet

        # Query database
        sqlite3 kismet-*.kismet "SELECT ssid,bssid FROM devices"

    Wireshark:
        # Open PCAP in Wireshark
        wireshark kismet-*.pcapng

    Performance:
        - Low CPU usage
        - Minimal battery impact
        - Can run for hours/days
        - Minimal storage requirements

    Privacy Note:
        Kismet captures wireless traffic which may include:
        - Personal device identifiers
        - Probe requests (location history)
        - Network usage patterns
        - MAC addresses

        Handle captured data responsibly and in accordance with
        privacy laws. Delete unnecessary captures promptly.

    Security Note:
        Passive monitoring is generally legal for monitoring your own
        networks or public spectrum. However, capturing packet contents
        may have legal implications. Consult local laws and obtain
        authorization before monitoring.
    """
    cmd_parts = ["kismet"]

    # Non-interactive mode
    cmd_parts.append("--no-ncurses")

    # Interface
    if interface:
        cmd_parts.extend(["-c", interface])

    # Channel configuration
    if not channel_hop:
        cmd_parts.append("--override-channel-hop=false")

    if channels:
        cmd_parts.extend(["--channel", channels])

    # Output configuration
    cmd_parts.extend(["--prefix", output_prefix])

    # GPS
    if gps_enabled:
        cmd_parts.append("--use-gpsd")

    # Duration
    if duration > 0:
        command = f"timeout {duration} " + " ".join(cmd_parts)
    else:
        command = " ".join(cmd_parts)

    return run_command(command, ctf=ctf)


@function_tool
def kismet_log_analysis(
    kismet_db: str,
    query_type: str = "summary",
    filter_encryption: str = "",
    filter_ssid: str = "",
    min_signal: int = -100,
    ctf=None,
) -> str:
    """
    Analyze Kismet capture database for intelligence.

    Query and analyze Kismet SQLite database to extract specific
    information about detected networks and devices.

    Args:
        kismet_db: Path to Kismet .kismet database file
        query_type: Type of query (summary, networks, clients, open, wep, probes)
        filter_encryption: Filter by encryption (open, wep, wpa, wpa2, wpa3)
        filter_ssid: Filter by SSID pattern
        min_signal: Minimum signal strength (dBm)
        ctf: CTF context for execution

    Returns:
        str: Query results

    Examples:
        # Network summary
        kismet_log_analysis(
            kismet_db="kismet-20250122-01.kismet",
            query_type="summary"
        )

        # Find open networks
        kismet_log_analysis(
            kismet_db="kismet-20250122-01.kismet",
            query_type="open"
        )

        # Find WEP networks
        kismet_log_analysis(
            kismet_db="kismet-20250122-01.kismet",
            query_type="wep"
        )

        # Strong signal networks
        kismet_log_analysis(
            kismet_db="kismet-20250122-01.kismet",
            query_type="networks",
            min_signal=-50
        )

        # Client probes
        kismet_log_analysis(
            kismet_db="kismet-20250122-01.kismet",
            query_type="probes"
        )

        # Specific SSID
        kismet_log_analysis(
            kismet_db="kismet-20250122-01.kismet",
            query_type="networks",
            filter_ssid="TargetCorp%"
        )

    Query Types:

    summary:
        Total networks, clients, and statistics

    networks:
        All detected access points with details

    clients:
        All detected client devices

    open:
        Networks with no encryption (security risk)

    wep:
        Networks using WEP (obsolete, crackable)

    wpa:
        Networks using WPA/WPA2/WPA3

    probes:
        Client probe requests (devices searching for networks)

    hidden:
        Hidden SSID networks

    SQL Queries:

    Networks:
        SELECT ssid, bssid, channel, encryption
        FROM devices
        WHERE type = 'Wi-Fi AP'

    Clients:
        SELECT mac, manufacturer, first_seen, last_seen
        FROM devices
        WHERE type = 'Wi-Fi Device'

    Open Networks:
        SELECT ssid, bssid, signal_dbm
        FROM devices
        WHERE encryption = 'None'

    Strong Signals:
        SELECT ssid, bssid, signal_dbm
        FROM devices
        WHERE signal_dbm > -50

    Intelligence Extraction:

    Target Selection:
        - Strongest signals (easiest to attack)
        - Weakest encryption (fastest to crack)
        - Most clients (more handshake opportunities)
        - Corporate SSIDs (high-value targets)

    Reconnaissance:
        - Device manufacturers (identify IoT/printers)
        - Probe requests (user behavior)
        - Hidden networks (security through obscurity)
        - Rogue APs (unauthorized access points)

    Security Assessment:
        - Open networks (no security)
        - WEP networks (obsolete encryption)
        - WPS enabled (vulnerable to Reaver)
        - Old WPA (vulnerable to various attacks)

    Security Note:
        Kismet databases contain sensitive information about networks
        and devices. Store securely and delete when no longer needed.
        May contain personally identifiable information.
    """
    # Build SQL query based on type
    queries = {
        "summary": "SELECT COUNT(DISTINCT ssid) as networks, COUNT(DISTINCT bssid) as aps FROM devices WHERE type='Wi-Fi AP'",
        "networks": "SELECT ssid, bssid, channel, encryption, signal_dbm FROM devices WHERE type='Wi-Fi AP'",
        "clients": "SELECT mac, manufacturer, first_seen, last_seen FROM devices WHERE type='Wi-Fi Device'",
        "open": "SELECT ssid, bssid, channel, signal_dbm FROM devices WHERE type='Wi-Fi AP' AND encryption='None'",
        "wep": "SELECT ssid, bssid, channel, signal_dbm FROM devices WHERE type='Wi-Fi AP' AND encryption LIKE '%WEP%'",
        "wpa": "SELECT ssid, bssid, channel, encryption, signal_dbm FROM devices WHERE type='Wi-Fi AP' AND encryption LIKE '%WPA%'",
        "probes": "SELECT DISTINCT ssid, COUNT(*) as count FROM probes GROUP BY ssid ORDER BY count DESC",
        "hidden": "SELECT bssid, channel, signal_dbm FROM devices WHERE type='Wi-Fi AP' AND (ssid='' OR ssid IS NULL)",
    }

    query = queries.get(query_type, queries["summary"])

    # Add filters
    conditions = []
    if filter_encryption:
        conditions.append(f"encryption LIKE '%{filter_encryption}%'")
    if filter_ssid:
        conditions.append(f"ssid LIKE '{filter_ssid}'")
    if min_signal > -100:
        conditions.append(f"signal_dbm >= {min_signal}")

    if conditions and query_type in ["networks", "wpa"]:
        query += " AND " + " AND ".join(conditions)

    command = f'sqlite3 {kismet_db} "{query}"'
    return run_command(command, ctf=ctf)
