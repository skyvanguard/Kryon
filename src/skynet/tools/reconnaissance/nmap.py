"""
Nmap - Network Mapper
======================

Nmap is the industry-standard network scanner for port discovery,
service detection, OS fingerprinting, and security auditing.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
port scans and improve response times by 10-30x for repeated scans.
"""

from skynet.cache import cache_scan_result
from skynet.sdk.agents import function_tool
from skynet.tools.common import run_command  # pylint: disable=E0401


@function_tool
@cache_scan_result(scan_type="port_scan", ttl=14400)  # Cache for 4 hours
def nmap(args: str, target: str, ctf=None) -> str:
    """
    Network scanner for port discovery, service detection, and OS fingerprinting.

    CACHED: Results cached for 4 hours to avoid redundant port scans.
    Expected performance improvement: 10-30x for repeated scans.

    Nmap is the industry-standard tool for network reconnaissance and security
    auditing. It can discover hosts, services, versions, OS details, and potential
    security issues.

    Args:
        args: Additional arguments to pass to the nmap command
              Common flags:
              - -sV: Service version detection
              - -sC: Default scripts
              - -p-: All ports
              - -A: Aggressive scan (OS, version, scripts, traceroute)
              - -T4: Timing template (faster)
              - -Pn: Skip ping (treat as online)
        target: The target host or IP address to scan

    Returns:
        str: Port scan results including open ports, services, versions

    Examples:
        # Quick port scan
        nmap(args="-F", target="192.168.1.1")

        # Service version detection
        nmap(args="-sV", target="example.com")

        # Comprehensive scan
        nmap(args="-sC -sV -A", target="192.168.1.0/24")

        # All ports with fast timing
        nmap(args="-p- -T4", target="10.10.10.5")
    """
    command = f"nmap {args} {target}"
    return run_command(command, ctf=ctf)
