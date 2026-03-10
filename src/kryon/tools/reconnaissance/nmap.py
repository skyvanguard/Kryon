"""
Nmap - Network Mapper
======================

Nmap is the industry-standard network scanner for port discovery,
service detection, OS fingerprinting, and security auditing.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
port scans and improve response times by 10-30x for repeated scans.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command  # pylint: disable=E0401


@function_tool
@cache_scan_result(scan_type="port_scan", ttl=14400)  # Cache for 4 hours
def nmap(
    target: str = "",
    args: str = "",
    flags: str = "",
    arguments: str = "",
    ports: str = "",
    services: bool = False,
    os_detection: bool = False,
    ctf=None,
) -> str:
    """
    Network scanner for port discovery, service detection, and OS fingerprinting.

    CACHED: Results cached for 4 hours to avoid redundant port scans.

    Args:
        target: The target host or IP address to scan (REQUIRED).
        args: Nmap flags as a single string (e.g. "-sV -sC").
              Common flags: -sV (version), -sC (scripts), -p- (all ports),
              -A (aggressive), -T4 (fast), -Pn (skip ping), -F (fast/top 100).
        flags: Alias for args — nmap flags as a single string.
        arguments: Alternative to args+target — full nmap arguments as a single string
                   (e.g. "-sV -sC 10.10.10.5"). The target is extracted automatically.
        ports: Comma-separated ports to scan (e.g. "80,443,8080"). Optional.
        services: If True, adds -sV for service version detection.
        os_detection: If True, adds -O for OS fingerprinting.

    Returns:
        Port scan results including open ports, services, versions.

    Examples:
        nmap(target="192.168.1.1", args="-F")
        nmap(target="example.com", flags="-sV -sC")
        nmap(arguments="-sV -sC 10.10.10.5")
        nmap(target="10.10.10.5", ports="80,443,8080", services=True, os_detection=True)
    """
    # Merge aliases: flags → args
    if flags and not args:
        args = flags
    if not args:
        args = "-sV -sC"

    # Handle the 'arguments' alias: model often sends everything in one string
    if arguments and not target:
        # Extract target (last token that looks like a host/IP) from arguments
        import re
        parts = arguments.strip().split()
        # Find the target: last part that looks like an IP or hostname
        extracted_target = ""
        flag_parts = []
        i = 0
        while i < len(parts):
            part = parts[i]
            # Skip flag values (e.g. -p 80, --script vuln)
            if part.startswith("-"):
                flag_parts.append(part)
                # Check if this flag expects a value
                if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                    # Flags like -p, -oN, --script take a value
                    if re.match(r"^-[poPsSdDegiIkm]$|^--", part):
                        i += 1
                        flag_parts.append(parts[i])
            else:
                # Non-flag token — likely the target
                extracted_target = part
            i += 1
        if extracted_target:
            target = extracted_target
            args = " ".join(flag_parts) if flag_parts else "-sV -sC"
        else:
            # Fallback: use arguments as-is appended to nmap
            command = f"nmap {arguments}"
            return run_command(command, ctf=ctf)

    if not target:
        return "Error: target is required. Provide a host or IP address to scan."

    flags = args
    if ports:
        flags += f" -p {ports}"
    if services and "-sV" not in flags:
        flags += " -sV"
    if os_detection and "-O" not in flags:
        flags += " -O"
    command = f"nmap {flags} {target}"
    return run_command(command, ctf=ctf)
