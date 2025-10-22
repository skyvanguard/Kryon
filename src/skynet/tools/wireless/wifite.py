"""
Wifite - Automated WiFi Penetration Testing
============================================

Wifite is an automated wireless auditor that attacks multiple WEP, WPA, and WPS
encrypted networks in a row. Provides fully automated WiFi cracking with minimal
user interaction.

PERFORMANCE: Wireless attacks are NOT cached as they involve live wireless
operations that must be executed fresh each time.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def wifite_auto_attack(
    interface: str = "",
    target_bssid: str = "",
    channel: str = "",
    attack_wep: bool = True,
    attack_wpa: bool = True,
    attack_wps: bool = True,
    wordlist: str = "",
    timeout: int = 600,
    max_targets: int = 0,
    min_power: int = 0,
    wps_pixie: bool = True,
    wps_pin: bool = True,
    require_fakeauth: bool = False,
    no_deauth: bool = False,
    verbose: bool = False,
    ctf=None
) -> str:
    """
    Automated WiFi penetration testing with minimal interaction.

    Wifite automatically discovers networks, selects vulnerable targets,
    captures handshakes, and attempts cracking. Handles WEP, WPA/WPA2,
    and WPS attacks with intelligent target selection.

    Args:
        interface: Wireless interface (auto-detects if not specified)
        target_bssid: Attack only this BSSID (MAC address)
        channel: Scan only this channel
        attack_wep: Enable WEP attacks
        attack_wpa: Enable WPA/WPA2 attacks
        attack_wps: Enable WPS attacks
        wordlist: Custom wordlist for WPA cracking
        timeout: Seconds to wait for handshake capture (default: 600)
        max_targets: Maximum targets to attack (0 = no limit)
        min_power: Minimum signal power (dB) to attack
        wps_pixie: Try WPS Pixie Dust attack
        wps_pin: Try WPS PIN attack
        require_fakeauth: Require fake authentication (for WEP)
        no_deauth: Skip deauthentication attacks
        verbose: Enable verbose output
        ctf: CTF context for execution

    Returns:
        str: Attack results with cracked passwords

    Examples:
        # Fully automated attack (default)
        wifite_auto_attack()

        # Attack specific network
        wifite_auto_attack(
            target_bssid="00:11:22:33:44:55",
            attack_wpa=True,
            wordlist="/usr/share/wordlists/rockyou.txt"
        )

        # WPS-only attack
        wifite_auto_attack(
            attack_wep=False,
            attack_wpa=False,
            attack_wps=True,
            wps_pixie=True
        )

        # Attack strong signals only
        wifite_auto_attack(
            min_power=50,
            attack_wpa=True,
            timeout=300
        )

        # Specific channel scan
        wifite_auto_attack(
            channel="6",
            attack_wpa=True,
            attack_wps=True
        )

        # Limited target attack
        wifite_auto_attack(
            max_targets=3,
            timeout=180,
            wps_pixie=True
        )

        # Custom wordlist WPA attack
        wifite_auto_attack(
            target_bssid="AA:BB:CC:DD:EE:FF",
            attack_wep=False,
            attack_wps=False,
            attack_wpa=True,
            wordlist="/tmp/custom-wifi-passwords.txt"
        )

        # Stealth mode (no deauth)
        wifite_auto_attack(
            attack_wpa=True,
            no_deauth=True,
            timeout=900  # Wait longer without forcing disconnects
        )

    Attack Methods:

    WPS Attacks:
        Pixie Dust:
            - Exploits weak random number generation
            - Very fast (seconds to minutes)
            - Works on vulnerable routers
            - Try first, high success rate on old routers

        PIN Brute Force:
            - Tests WPS PIN space
            - Takes hours (10,000-11,000 PINs)
            - May trigger AP lockout
            - Last resort for WPS

    WPA/WPA2 Attacks:
        1. Capture handshake via deauth
        2. Dictionary attack with wordlist
        3. Success depends on password strength

    WEP Attacks:
        - Capture sufficient IVs (~20,000-50,000)
        - Crack using statistical attacks
        - Fast cracking (~5-10 minutes)
        - WEP is obsolete but still found

    Attack Workflow:
        1. Enable monitor mode
        2. Scan for networks
        3. Sort by power/channel/encryption
        4. Attack each target:
           - Try WPS Pixie Dust (if enabled)
           - Try WPS PIN (if enabled)
           - Capture WPA handshake (if enabled)
           - Crack WPA with wordlist
           - Attack WEP (if enabled)
        5. Display results

    Success Indicators:
        [+] cracked WPA handshake!
        [+] cracked WPS PIN: 12345670
        [+] cracked WEP key: 1A:2B:3C:4D:5E

    Output Files:
        hs/handshake_ESSID_BSSID.cap  # Captured handshakes
        hs/cracked.txt                # Cracked passwords

    Performance Tips:
        Fast Scan:
            - target_bssid specified
            - channel specified
            - Small wordlist or WPS-only

        Thorough Scan:
            - No target specified
            - All attack types enabled
            - Large wordlist (rockyou.txt)

        Stealth:
            - no_deauth=True
            - Single target
            - Longer timeout
            - WPS Pixie Dust only

    Common Issues:
        No handshake captured:
            - Increase timeout
            - No clients connected to AP
            - Strong signal required (min_power)

        WPS locked out:
            - AP limits WPS attempts
            - Wait 5-10 minutes
            - Try different AP

        No vulnerable networks:
            - Modern routers have WPS disabled
            - Strong WPA2 passwords
            - Try different location/time

    Security Note:
        Wifite is very noisy - generates deauth attacks, WPS probes,
        and continuous packet injection. Easily detected by wireless IDS.
        Use only on authorized networks. Some attacks may disrupt
        network service (DoS effect).
    """
    cmd_parts = ["wifite"]

    # Interface
    if interface:
        cmd_parts.extend(["-i", interface])

    # Target specification
    if target_bssid:
        cmd_parts.extend(["--bssid", target_bssid])

    if channel:
        cmd_parts.extend(["-c", channel])

    # Attack types
    if not attack_wep:
        cmd_parts.append("--no-wep")

    if not attack_wpa:
        cmd_parts.append("--no-wpa")

    if not attack_wps:
        cmd_parts.append("--no-wps")

    # WPS attack modes
    if not wps_pixie:
        cmd_parts.append("--no-pixie")

    if not wps_pin:
        cmd_parts.append("--no-pin")

    # WPA options
    if wordlist:
        cmd_parts.extend(["--dict", wordlist])

    if no_deauth:
        cmd_parts.append("--no-deauth")

    # Timeout
    cmd_parts.extend(["--wpat", str(timeout)])
    cmd_parts.extend(["--wps-timeout", str(min(timeout, 660))])  # WPS max 660s

    # Filtering
    if min_power > 0:
        cmd_parts.extend(["--pow", str(min_power)])

    if max_targets > 0:
        cmd_parts.extend(["--num-targets", str(max_targets)])

    # WEP options
    if require_fakeauth:
        cmd_parts.append("--require-fakeauth")

    # Verbose
    if verbose:
        cmd_parts.append("-v")

    # Non-interactive mode
    cmd_parts.append("--kill")  # Kill interfering processes

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
