"""
Aircrack-ng Suite - WiFi Security Auditing
===========================================

Aircrack-ng is a complete suite of tools to assess WiFi network security.
Includes packet capture, WPA/WPA2 cracking, deauthentication attacks, and
injection testing.

PERFORMANCE: Wireless attacks are NOT cached as they involve live wireless
operations that must be executed fresh each time.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def aircrack_capture(
    interface: str,
    bssid: str = "",
    channel: str = "",
    output_file: str = "capture",
    duration: int = 0,
    write_interval: int = 1,
    ctf=None
) -> str:
    """
    Capture WiFi packets for analysis and cracking.

    Use airodump-ng to capture wireless packets from networks. Essential
    first step for WPA/WPA2 cracking - captures handshakes and traffic.

    Args:
        interface: Wireless interface in monitor mode (e.g., wlan0mon)
        bssid: Target access point MAC address (filter specific AP)
        channel: WiFi channel to monitor (1-14, or auto)
        output_file: Output file prefix (captures saved as .cap files)
        duration: Capture duration in seconds (0 = continuous)
        write_interval: Write captured packets every N seconds
        ctf: CTF context for execution

    Returns:
        str: Capture results and statistics

    Examples:
        # Scan all networks (reconnaissance)
        aircrack_capture(
            interface="wlan0mon",
            output_file="survey",
            duration=60
        )

        # Target specific AP and channel
        aircrack_capture(
            interface="wlan0mon",
            bssid="00:11:22:33:44:55",
            channel="6",
            output_file="target-capture"
        )

        # Capture for WPA handshake
        aircrack_capture(
            interface="wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            channel="11",
            output_file="handshake-capture",
            duration=300  # 5 minutes
        )

        # Long-term monitoring
        aircrack_capture(
            interface="wlan0mon",
            output_file="longterm",
            write_interval=5,
            duration=3600  # 1 hour
        )

    Monitor Mode Setup:
        # Enable monitor mode first
        airmon-ng start wlan0
        # This creates wlan0mon interface

        # Kill interfering processes
        airmon-ng check kill

        # Disable monitor mode when done
        airmon-ng stop wlan0mon

    Capture Files:
        output-01.cap     # Packet capture
        output-01.csv     # Network list
        output-01.kismet.csv  # Kismet format
        output-01.kismet.netxml  # Kismet XML

    Finding Handshakes:
        Look for "WPA handshake: AA:BB:CC:DD:EE:FF" in output
        Handshake capture triggered by client reconnection

    Security Note:
        Packet capture is passive and legal for owned networks.
        Capturing traffic from unauthorized networks may be illegal.
        Always obtain authorization before testing.
    """
    cmd_parts = ["airodump-ng"]

    # Target-specific capture
    if bssid:
        cmd_parts.extend(["--bssid", bssid])

    if channel:
        cmd_parts.extend(["--channel", channel])

    # Output configuration
    cmd_parts.extend(["-w", output_file])
    cmd_parts.extend(["--write-interval", str(write_interval)])

    # Interface (must be last)
    cmd_parts.append(interface)

    # Add timeout if duration specified
    command = " ".join(cmd_parts)
    if duration > 0:
        command = f"timeout {duration} {command}"

    return run_command(command, ctf=ctf)


@function_tool
def aircrack_crack(
    capture_file: str,
    wordlist: str,
    bssid: str = "",
    essid: str = "",
    threads: int = 1,
    ctf=None
) -> str:
    """
    Crack WPA/WPA2 pre-shared key from capture file.

    Performs dictionary attack against captured WPA/WPA2 handshake using
    wordlist. Requires valid 4-way handshake in capture file.

    Args:
        capture_file: Packet capture file (.cap) with handshake
        wordlist: Dictionary file for password cracking
        bssid: Target access point MAC address
        essid: Target network name (SSID)
        threads: Number of CPU cores to use
        ctf: CTF context for execution

    Returns:
        str: Cracking results with password if found

    Examples:
        # Crack with rockyou wordlist
        aircrack_crack(
            capture_file="handshake-01.cap",
            wordlist="/usr/share/wordlists/rockyou.txt",
            bssid="00:11:22:33:44:55"
        )

        # Crack specific ESSID
        aircrack_crack(
            capture_file="capture.cap",
            wordlist="/usr/share/wordlists/wifi-passwords.txt",
            essid="TargetNetwork"
        )

        # Multi-threaded cracking
        aircrack_crack(
            capture_file="handshake.cap",
            wordlist="/usr/share/wordlists/rockyou.txt",
            bssid="AA:BB:CC:DD:EE:FF",
            threads=4
        )

        # Custom wordlist
        aircrack_crack(
            capture_file="capture-01.cap",
            wordlist="/tmp/custom-passwords.txt",
            bssid="11:22:33:44:55:66"
        )

    Handshake Verification:
        # Check if capture has valid handshake
        aircrack-ng capture-01.cap
        # Look for "1 handshake" in output

    Wordlist Recommendations:
        Small (fast):
            /usr/share/wordlists/fasttrack.txt (~220 passwords)
            /usr/share/wordlists/john.lst (~3,500 passwords)

        Medium:
            /usr/share/wordlists/wifite.txt (~4,800 passwords)
            Custom WiFi wordlists (~10k-100k)

        Large (comprehensive):
            /usr/share/wordlists/rockyou.txt (~14M passwords)
            /usr/share/wordlists/crackstation.txt (~1.5B passwords)

    Performance:
        - ~1,000-5,000 passwords/second (CPU dependent)
        - Multi-threading provides linear speedup
        - rockyou.txt takes ~45-60 minutes on average CPU
        - WPA/WPA2 cracking is CPU-intensive

    Success Indicators:
        KEY FOUND! [ password123 ]
        Master Key     : XX XX XX ...
        Transient Key  : XX XX XX ...

    Security Note:
        WPA/WPA2 cracking requires valid handshake capture.
        Success depends entirely on password being in wordlist.
        Strong random passwords are essentially uncrackable.
    """
    cmd_parts = ["aircrack-ng"]

    # Wordlist
    cmd_parts.extend(["-w", wordlist])

    # Target specification
    if bssid:
        cmd_parts.extend(["-b", bssid])

    if essid:
        cmd_parts.extend(["-e", essid])

    # Performance
    if threads > 1:
        cmd_parts.extend(["-t", str(threads)])

    # Capture file (must be last)
    cmd_parts.append(capture_file)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def aircrack_deauth(
    interface: str,
    bssid: str,
    client: str = "",
    count: int = 1,
    reason_code: int = 7,
    ctf=None
) -> str:
    """
    Send deauthentication packets to disconnect clients.

    Forces clients to disconnect from AP, triggering reconnection and
    handshake capture. Essential for WPA/WPA2 handshake capture.

    Args:
        interface: Wireless interface in monitor mode
        bssid: Target access point MAC address
        client: Target client MAC (empty = broadcast to all clients)
        count: Number of deauth packets (0 = continuous)
        reason_code: Deauth reason code (7 = class 3 frame from nonassociated STA)
        ctf: CTF context for execution

    Returns:
        str: Deauthentication attack results

    Examples:
        # Deauth all clients (broadcast)
        aircrack_deauth(
            interface="wlan0mon",
            bssid="00:11:22:33:44:55",
            count=5
        )

        # Deauth specific client
        aircrack_deauth(
            interface="wlan0mon",
            bssid="00:11:22:33:44:55",
            client="AA:BB:CC:DD:EE:FF",
            count=10
        )

        # Continuous deauth (DoS)
        aircrack_deauth(
            interface="wlan0mon",
            bssid="00:11:22:33:44:55",
            count=0  # Continuous until stopped
        )

        # Single deauth packet
        aircrack_deauth(
            interface="wlan0mon",
            bssid="11:22:33:44:55:66",
            client="77:88:99:AA:BB:CC",
            count=1
        )

    Deauth Attack Strategy:
        1. Start packet capture (aircrack_capture)
        2. Wait 10-15 seconds for capture to initialize
        3. Send deauth packets (aircrack_deauth)
        4. Client disconnects and reconnects
        5. Handshake captured during reconnection
        6. Stop capture after handshake obtained

    Reason Codes:
        1: Unspecified reason
        2: Previous authentication no longer valid
        3: Deauthenticated because sending STA is leaving
        4: Disassociated due to inactivity
        6: Class 2 frame received from nonauthenticated STA
        7: Class 3 frame received from nonassociated STA (most common)
        8: Disassociated because sending STA is leaving

    Detection Risk:
        - Generates noticeable network disruption
        - Detected by wireless IDS/IPS systems
        - Visible in wireless monitoring tools
        - Use minimal count (1-5 packets) for stealth

    Legal Considerations:
        - Deauthentication attacks are disruptive
        - May be illegal without authorization
        - Can constitute denial of service
        - Only use on networks you own or have authorization

    Security Note:
        Deauth attacks exploit lack of encryption in management frames.
        Protected Management Frames (802.11w) prevents this attack.
        Modern WPA3 networks are not vulnerable to deauth attacks.
    """
    cmd_parts = ["aireplay-ng"]

    # Deauthentication attack mode
    cmd_parts.append("--deauth")
    cmd_parts.append(str(count))

    # Target AP
    cmd_parts.extend(["-a", bssid])

    # Target client (optional)
    if client:
        cmd_parts.extend(["-c", client])

    # Reason code
    cmd_parts.extend(["--ignore-negative-one"])

    # Interface
    cmd_parts.append(interface)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def aircrack_injection_test(
    interface: str,
    bssid: str = "",
    essid: str = "",
    ctf=None
) -> str:
    """
    Test wireless injection capabilities and AP response.

    Verifies that wireless adapter supports packet injection and tests
    connectivity with target AP. Essential pre-check before attacks.

    Args:
        interface: Wireless interface in monitor mode
        bssid: Target access point MAC address
        essid: Target network name (SSID)
        ctf: CTF context for execution

    Returns:
        str: Injection test results and statistics

    Examples:
        # Test injection capability
        aircrack_injection_test(
            interface="wlan0mon"
        )

        # Test against specific AP
        aircrack_injection_test(
            interface="wlan0mon",
            bssid="00:11:22:33:44:55"
        )

        # Test with ESSID
        aircrack_injection_test(
            interface="wlan0mon",
            essid="TargetNetwork"
        )

        # Full test
        aircrack_injection_test(
            interface="wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            essid="TestNet"
        )

    Test Results:
        30/30: 100% - Injection is working!
        - Perfect injection capability

        0/30: 0% - Injection does not work
        - Card doesn't support injection
        - Wrong driver or firmware

        15/30: 50% - Partial injection
        - Possible driver issues
        - May work but unreliable

    Common Issues:
        No Injection:
            - Adapter doesn't support injection
            - Wrong driver (use proper ath9k/rt2800usb/etc.)
            - Firmware issues

        Partial Injection:
            - Distance too far from AP
            - Interference or signal issues
            - Driver compatibility problems

    Recommended Adapters (Good Injection Support):
        - Alfa AWUS036NHA (Atheros AR9271)
        - Alfa AWUS036NH (Ralink RT3070)
        - TP-Link TL-WN722N v1 (Atheros AR9271)
        - Panda PAU05 (Ralink RT5372)
        - Alfa AWUS036ACH (Realtek RTL8812AU)

    Troubleshooting:
        # Check adapter chipset
        lsusb
        airmon-ng

        # Verify monitor mode active
        iwconfig

        # Kill interfering processes
        airmon-ng check kill

        # Restart network services if needed
        systemctl restart NetworkManager

    Security Note:
        Injection testing sends probe requests and broadcasts.
        Relatively low detection risk but visible to wireless monitoring.
        Test in authorized environments only.
    """
    cmd_parts = ["aireplay-ng", "--test"]

    # Target specification
    if bssid:
        cmd_parts.extend(["-a", bssid])

    if essid:
        cmd_parts.extend(["-e", essid])

    # Interface
    cmd_parts.append(interface)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
