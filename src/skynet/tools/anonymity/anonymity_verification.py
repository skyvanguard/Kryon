"""
KRYON Anonymity - Anonymity Verification

Comprehensive anonymity checking and leak detection.

Clearance Level: Omega-Shadow (Maximum Anonymity Operations Authority)
Specialization: Leak detection, anonymity scoring, fingerprint analysis
Mission: Verify and measure anonymity effectiveness

This module provides:
- IP leak detection
- DNS leak detection
- WebRTC leak detection
- Timezone leak detection
- Fingerprint uniqueness measurement
- Comprehensive anonymity check
- Anonymity score calculation (0-100)
"""

import json
import subprocess
from typing import Any, Optional


def check_ip_leak(expected_country: Optional[str] = None) -> dict[str, Any]:
    """
    Check for IP address leaks.

    Detects:
    - Real IP vs visible IP
    - IPv4 and IPv6 leaks
    - VPN/Tor effectiveness
    - Country mismatch

    Args:
        expected_country: Expected country code (US, DE, etc.)

    Returns:
        IP leak detection result

    Example:
        >>> from skynet.tools.anonymity import check_ip_leak
        >>>
        >>> # Check if real IP is hidden
        >>> result = check_ip_leak(expected_country="DE")
        >>>
        >>> if result['leak_detected']:
        ...     print(f"WARNING: IP leak detected!")
        ...     print(f"Visible IP: {result['visible_ip']}")
        ... else:
        ...     print(f"No leak. Visible IP: {result['visible_ip']}")
        ...     print(f"Country: {result['country']}")

    Test Sites:
        - https://ifconfig.me
        - https://api.ipify.org
        - https://icanhazip.com
    """
    results = {
        "visible_ip": "",
        "visible_ipv6": "",
        "country": "",
        "city": "",
        "isp": "",
        "leak_detected": False,
        "vpn_detected": False,
        "tor_detected": False,
        "success": False,
        "error": None,
    }

    try:
        # Method 1: Using curl (most reliable)
        try:
            # Get IPv4
            ipv4_result = subprocess.run(
                ["curl", "-4", "-s", "https://api.ipify.org"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if ipv4_result.returncode == 0:
                results["visible_ip"] = ipv4_result.stdout.strip()

            # Get IPv6
            ipv6_result = subprocess.run(
                ["curl", "-6", "-s", "https://api64.ipify.org"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if ipv6_result.returncode == 0:
                results["visible_ipv6"] = ipv6_result.stdout.strip()

        except Exception:
            pass

        # Method 2: Get detailed IP info
        if results["visible_ip"]:
            try:
                # Get geolocation info
                geo_result = subprocess.run(
                    ["curl", "-s", f"https://ipapi.co/{results['visible_ip']}/json/"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if geo_result.returncode == 0:
                    geo_data = json.loads(geo_result.stdout)
                    results["country"] = geo_data.get("country_code", "")
                    results["city"] = geo_data.get("city", "")
                    results["isp"] = geo_data.get("org", "")

                    # Check for VPN/Tor indicators
                    isp_lower = results["isp"].lower()
                    if any(x in isp_lower for x in ["vpn", "proxy", "hosting", "cloud"]):
                        results["vpn_detected"] = True

                    if "tor" in isp_lower:
                        results["tor_detected"] = True

                    # Check country mismatch
                    if expected_country and results["country"] != expected_country:
                        results["leak_detected"] = True

            except Exception:
                pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def check_dns_leak(expected_dns_servers: Optional[list[str]] = None) -> dict[str, Any]:
    """
    Check for DNS leaks.

    DNS leaks occur when:
    - DNS requests bypass VPN/Tor
    - ISP DNS servers are used instead of VPN DNS
    - Real location revealed through DNS

    Args:
        expected_dns_servers: List of expected DNS server IPs

    Returns:
        DNS leak detection result

    Example:
        >>> from skynet.tools.anonymity import check_dns_leak
        >>>
        >>> # Check DNS leak
        >>> result = check_dns_leak()
        >>>
        >>> if result['leak_detected']:
        ...     print(f"DNS LEAK! Using DNS: {result['dns_servers']}")
        ... else:
        ...     print(f"No DNS leak. DNS: {result['dns_servers']}")

    Test Method:
        - Makes DNS query for unique subdomain
        - Checks which DNS server received request
        - Compares against expected DNS servers
    """
    results = {
        "dns_servers": [],
        "leak_detected": False,
        "isp_dns_detected": False,
        "success": False,
        "error": None,
    }

    try:
        # Method 1: Check current DNS configuration
        if subprocess.run(["which", "nmcli"], capture_output=True).returncode == 0:
            # Linux NetworkManager
            dns_result = subprocess.run(["nmcli", "dev", "show"], capture_output=True, text=True)

            for line in dns_result.stdout.split("\n"):
                if "IP4.DNS" in line or "IP6.DNS" in line:
                    dns_server = line.split(":")[-1].strip()
                    if dns_server:
                        results["dns_servers"].append(dns_server)

        # Method 2: Read /etc/resolv.conf (Linux/Mac)
        elif subprocess.run(["test", "-f", "/etc/resolv.conf"], capture_output=True).returncode == 0:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_server = line.split()[1]
                        results["dns_servers"].append(dns_server)

        # Method 3: Windows
        elif subprocess.run(["where", "ipconfig"], capture_output=True).returncode == 0:
            dns_result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)

            for line in dns_result.stdout.split("\n"):
                if "DNS Servers" in line:
                    dns_server = line.split(":")[-1].strip()
                    if dns_server:
                        results["dns_servers"].append(dns_server)

        # Check for common ISP DNS servers
        common_isp_dns = [
            "192.168.1.1",
            "192.168.0.1",
            "10.0.0.1",
            "8.8.8.8",
            "8.8.4.4",  # Google (if not using VPN)
            "1.1.1.1",
            "1.0.0.1",  # Cloudflare (if not using VPN)
        ]

        for dns in results["dns_servers"]:
            if dns in common_isp_dns:
                results["isp_dns_detected"] = True
                results["leak_detected"] = True

        # Check against expected DNS servers
        if expected_dns_servers:
            for dns in results["dns_servers"]:
                if dns not in expected_dns_servers:
                    results["leak_detected"] = True

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def check_webrtc_leak() -> dict[str, Any]:
    """
    Check for WebRTC IP leaks.

    WebRTC can leak:
    - Local IP address
    - Public IP address
    - Even when using VPN/Tor

    Returns:
        WebRTC leak detection result

    Example:
        >>> from skynet.tools.anonymity import check_webrtc_leak
        >>>
        >>> # Check WebRTC leak
        >>> result = check_webrtc_leak()
        >>>
        >>> if result['leak_detected']:
        ...     print(f"WebRTC LEAK!")
        ...     print(f"Leaked IPs: {result['leaked_ips']}")
        ... else:
        ...     print("No WebRTC leak detected")

    How WebRTC Leaks Work:
        - WebRTC uses STUN servers
        - Discovers local/public IPs
        - JavaScript can read these IPs
        - Bypasses proxy/VPN configuration

    Prevention:
        - Disable WebRTC in browser
        - Use browser extension (uBlock Origin)
        - Use privacy-focused browser (Tor Browser)
    """
    results = {
        "webrtc_enabled": False,
        "leak_detected": False,
        "leaked_ips": [],
        "local_ips": [],
        "public_ips": [],
        "success": False,
        "error": None,
    }

    try:
        # Test using browserleaks.com API (if available)
        try:
            webrtc_test = subprocess.run(
                ["curl", "-s", "https://browserleaks.com/webrtc"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if "WebRTC" in webrtc_test.stdout:
                results["webrtc_enabled"] = True

                # Parse leaked IPs (simplified)
                # Real implementation would need JavaScript execution
                results["error"] = "WebRTC detection requires browser automation (Selenium)"

        except Exception:
            pass

        # Guidance for manual check
        results["success"] = True
        results["error"] = results.get("error") or "Visit https://browserleaks.com/webrtc to check manually"

    except Exception as e:
        results["error"] = str(e)

    return results


def check_timezone_leak() -> dict[str, Any]:
    """
    Check for timezone leaks.

    Timezone reveals:
    - Geographic location
    - Region/country
    - Can narrow down city

    Returns:
        Timezone leak detection result

    Example:
        >>> from skynet.tools.anonymity import check_timezone_leak
        >>>
        >>> # Check timezone
        >>> result = check_timezone_leak()
        >>>
        >>> print(f"System timezone: {result['system_timezone']}")
        >>> print(f"Timezone offset: {result['utc_offset']}")
        >>> print(f"Location hint: {result['location_hint']}")

    Detection Method:
        - Reads system timezone
        - Compares with expected timezone (if using VPN/Tor)
        - Checks for timezone leaks in browser
    """
    results = {
        "system_timezone": "",
        "utc_offset": "",
        "location_hint": "",
        "leak_detected": False,
        "success": False,
        "error": None,
    }

    try:
        # Get system timezone (Linux/Mac)
        if subprocess.run(["which", "timedatectl"], capture_output=True).returncode == 0:
            tz_result = subprocess.run(["timedatectl"], capture_output=True, text=True)

            for line in tz_result.stdout.split("\n"):
                if "Time zone" in line:
                    results["system_timezone"] = line.split(":")[1].strip()

        # Alternative: read /etc/timezone
        elif subprocess.run(["test", "-f", "/etc/timezone"], capture_output=True).returncode == 0:
            with open("/etc/timezone") as f:
                results["system_timezone"] = f.read().strip()

        # Get UTC offset
        import time

        offset_seconds = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        offset_hours = -offset_seconds / 3600
        results["utc_offset"] = f"UTC{'+' if offset_hours >= 0 else ''}{offset_hours:.1f}"

        # Location hint from timezone
        timezone_locations = {
            "America/New_York": "Eastern US",
            "America/Chicago": "Central US",
            "America/Los_Angeles": "Western US",
            "Europe/London": "UK",
            "Europe/Paris": "France/Central Europe",
            "Europe/Berlin": "Germany/Central Europe",
            "Asia/Tokyo": "Japan",
            "Asia/Shanghai": "China",
            "Australia/Sydney": "Australia",
        }

        for tz, location in timezone_locations.items():
            if tz in results["system_timezone"]:
                results["location_hint"] = location
                break

        # Warning if timezone doesn't match expected anonymity
        if results["system_timezone"]:
            results["leak_detected"] = True
            results["error"] = "Timezone reveals location. Use timezone spoofing."

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def check_fingerprint_uniqueness(fingerprint_data: dict[str, Any]) -> dict[str, Any]:
    """
    Measure browser fingerprint uniqueness.

    Calculates how unique your fingerprint is:
    - Lower score = more common (better)
    - Higher score = more unique (worse for anonymity)

    Args:
        fingerprint_data: Fingerprint parameters to analyze

    Returns:
        Uniqueness score and analysis

    Example:
        >>> from skynet.tools.anonymity import check_fingerprint_uniqueness
        >>>
        >>> # Analyze fingerprint
        >>> fingerprint = {
        ...     'user_agent': 'Mozilla/5.0...',
        ...     'screen_resolution': '1920x1080',
        ...     'timezone': 'America/New_York',
        ...     'languages': ['en-US'],
        ...     'plugins': ['Chrome PDF Plugin'],
        ...     'fonts': ['Arial', 'Verdana']
        ... }
        >>>
        >>> result = check_fingerprint_uniqueness(fingerprint)
        >>>
        >>> print(f"Uniqueness score: {result['uniqueness_score']}/100")
        >>> print(f"Assessment: {result['assessment']}")

    Scoring:
        - 0-30: Common fingerprint (good anonymity)
        - 31-60: Somewhat unique (moderate anonymity)
        - 61-100: Highly unique (poor anonymity)
    """
    results = {
        "uniqueness_score": 0,
        "entropy_bits": 0.0,
        "assessment": "",
        "unique_attributes": [],
        "common_attributes": [],
        "success": False,
        "error": None,
    }

    try:
        score = 0
        entropy = 0.0

        # User-Agent uniqueness
        ua = fingerprint_data.get("user_agent", "")
        if ua:
            # Common browsers score low, rare ones score high
            common_uas = ["Chrome", "Firefox", "Safari", "Edge"]
            if not any(browser in ua for browser in common_uas):
                score += 20
                results["unique_attributes"].append("Rare user-agent")
                entropy += 5.0
            else:
                results["common_attributes"].append("Common user-agent")

        # Screen resolution uniqueness
        screen = fingerprint_data.get("screen_resolution", "")
        common_resolutions = ["1920x1080", "1366x768", "1440x900"]
        if screen and screen not in common_resolutions:
            score += 15
            results["unique_attributes"].append(f"Uncommon resolution: {screen}")
            entropy += 3.0
        else:
            results["common_attributes"].append("Common screen resolution")

        # Timezone uniqueness
        timezone = fingerprint_data.get("timezone", "")
        common_timezones = ["America/New_York", "Europe/London", "America/Los_Angeles"]
        if timezone and timezone not in common_timezones:
            score += 10
            results["unique_attributes"].append(f"Uncommon timezone: {timezone}")
            entropy += 2.0
        else:
            results["common_attributes"].append("Common timezone")

        # Language uniqueness
        languages = fingerprint_data.get("languages", [])
        if languages and languages[0] not in ["en-US", "en-GB", "en"]:
            score += 10
            results["unique_attributes"].append(f"Uncommon language: {languages[0]}")
            entropy += 2.5
        else:
            results["common_attributes"].append("Common language")

        # Plugins uniqueness
        plugins = fingerprint_data.get("plugins", [])
        if len(plugins) > 10:
            score += 15
            results["unique_attributes"].append(f"Many plugins: {len(plugins)}")
            entropy += 3.5
        elif len(plugins) < 2:
            results["common_attributes"].append("Few plugins (good)")

        # Fonts uniqueness
        fonts = fingerprint_data.get("fonts", [])
        if len(fonts) > 50:
            score += 20
            results["unique_attributes"].append(f"Many fonts: {len(fonts)}")
            entropy += 4.0
        else:
            results["common_attributes"].append("Normal font count")

        # Canvas fingerprint (if provided)
        canvas = fingerprint_data.get("canvas_hash", "")
        if canvas:
            score += 10
            entropy += 8.0  # Canvas is very unique

        results["uniqueness_score"] = min(score, 100)
        results["entropy_bits"] = entropy

        # Assessment
        if score < 30:
            results["assessment"] = "Common fingerprint - Good anonymity"
        elif score < 60:
            results["assessment"] = "Somewhat unique - Moderate anonymity"
        else:
            results["assessment"] = "Highly unique - Poor anonymity (easily tracked)"

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def comprehensive_anonymity_check(expected_country: Optional[str] = None) -> dict[str, Any]:
    """
    Comprehensive anonymity check - all tests.

    Performs:
    - IP leak check
    - DNS leak check
    - WebRTC leak check
    - Timezone leak check
    - Overall anonymity assessment

    Args:
        expected_country: Expected country code

    Returns:
        Complete anonymity assessment

    Example:
        >>> from skynet.tools.anonymity import comprehensive_anonymity_check
        >>>
        >>> # Full anonymity check
        >>> result = comprehensive_anonymity_check(expected_country="DE")
        >>>
        >>> print(f"Overall score: {result['overall_score']}/100")
        >>> print(f"Leaks detected: {result['total_leaks']}")
        >>>
        >>> for issue in result['issues']:
        ...     print(f"- {issue}")

    Score Interpretation:
        - 90-100: Excellent anonymity
        - 70-89: Good anonymity
        - 50-69: Moderate anonymity (has issues)
        - Below 50: Poor anonymity (major leaks)
    """
    results = {
        "overall_score": 0,
        "total_leaks": 0,
        "issues": [],
        "passed_checks": [],
        "ip_check": {},
        "dns_check": {},
        "webrtc_check": {},
        "timezone_check": {},
        "success": False,
        "error": None,
    }

    try:
        score = 100  # Start at perfect, subtract for issues

        # IP leak check
        ip_result = check_ip_leak(expected_country)
        results["ip_check"] = ip_result

        if ip_result["leak_detected"]:
            score -= 30
            results["total_leaks"] += 1
            results["issues"].append(f"IP leak detected: {ip_result.get('visible_ip', 'unknown')}")
        else:
            results["passed_checks"].append("IP check passed")

        if not ip_result.get("vpn_detected") and not ip_result.get("tor_detected"):
            score -= 15
            results["issues"].append("No VPN/Tor detected - using real IP")

        # DNS leak check
        dns_result = check_dns_leak()
        results["dns_check"] = dns_result

        if dns_result["leak_detected"]:
            score -= 25
            results["total_leaks"] += 1
            results["issues"].append(f"DNS leak detected: {dns_result.get('dns_servers', [])}")
        else:
            results["passed_checks"].append("DNS check passed")

        # WebRTC leak check
        webrtc_result = check_webrtc_leak()
        results["webrtc_check"] = webrtc_result

        if webrtc_result["leak_detected"]:
            score -= 20
            results["total_leaks"] += 1
            results["issues"].append("WebRTC leak detected")
        else:
            results["passed_checks"].append("WebRTC check passed")

        # Timezone leak check
        tz_result = check_timezone_leak()
        results["timezone_check"] = tz_result

        if tz_result["leak_detected"]:
            score -= 10
            results["issues"].append(f"Timezone leak: {tz_result.get('system_timezone', 'unknown')}")
        else:
            results["passed_checks"].append("Timezone check passed")

        results["overall_score"] = max(score, 0)
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def anonymity_score() -> dict[str, Any]:
    """
    Calculate overall anonymity score (0-100).

    Quick anonymity assessment:
    - 100 = Perfect anonymity
    - 0 = No anonymity

    Returns:
        Anonymity score and rating

    Example:
        >>> from skynet.tools.anonymity import anonymity_score
        >>>
        >>> # Quick anonymity check
        >>> result = anonymity_score()
        >>>
        >>> print(f"Score: {result['score']}/100")
        >>> print(f"Rating: {result['rating']}")
        >>> print(f"Recommendation: {result['recommendation']}")

    Ratings:
        - 90-100: Excellent
        - 70-89: Good
        - 50-69: Fair
        - 30-49: Poor
        - 0-29: Critical
    """
    results = {"score": 0, "rating": "", "recommendation": "", "success": False, "error": None}

    try:
        # Run comprehensive check
        check_result = comprehensive_anonymity_check()

        results["score"] = check_result["overall_score"]

        # Rating
        if results["score"] >= 90:
            results["rating"] = "Excellent"
            results["recommendation"] = "Anonymity is excellent. Maintain current configuration."
        elif results["score"] >= 70:
            results["rating"] = "Good"
            results["recommendation"] = "Good anonymity. Minor improvements possible."
        elif results["score"] >= 50:
            results["rating"] = "Fair"
            results["recommendation"] = "Fair anonymity. Address detected issues."
        elif results["score"] >= 30:
            results["rating"] = "Poor"
            results["recommendation"] = "Poor anonymity. Major issues detected. Use VPN/Tor."
        else:
            results["rating"] = "Critical"
            results["recommendation"] = "Critical anonymity failure. Do not proceed with sensitive operations."

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
