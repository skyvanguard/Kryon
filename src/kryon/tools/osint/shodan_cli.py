"""
Shodan CLI - Internet-Wide Device Search
=========================================

Shodan is a search engine for Internet-connected devices. Find exposed services,
vulnerabilities, and misconfigurations across the internet.

PERFORMANCE: Shodan results are cached for 12 hours as internet-wide data
changes gradually.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="internet_intel", ttl=43200)
def shodan_search(query: str, limit: int = 100, output_format: str = "simple", fields: str = "", ctf=None) -> str:
    """
    Search Shodan for internet-connected devices.

    Args:
        query: Shodan search query
        limit: Maximum results
        output_format: Output format (simple, json, xml)
        fields: Specific fields to return (ip_str, port, org, etc.)
        ctf: CTF context

    Returns:
        str: Search results

    Examples:
        # Find Apache servers
        shodan_search(query="apache")

        # Find webcams
        shodan_search(query="title:camera")

        # Find MongoDB instances
        shodan_search(query="product:MongoDB", limit=50)

        # Find devices in specific country
        shodan_search(query="country:US port:22")
    """
    cmd_parts = ["shodan", "search"]

    if output_format != "simple":
        cmd_parts.append(f"--format={output_format}")

    if fields:
        cmd_parts.extend(["--fields", fields])

    cmd_parts.extend(["--limit", str(limit)])
    cmd_parts.append(f'"{query}"')

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="internet_intel", ttl=43200)
def shodan_host(ip_address: str, history: bool = False, ctf=None) -> str:
    """
    Get detailed information about a specific host.

    Args:
        ip_address: Target IP address
        history: Include historical data
        ctf: CTF context

    Returns:
        str: Host information including open ports, services, vulnerabilities

    Examples:
        # Basic host info
        shodan_host(ip_address="8.8.8.8")

        # With history
        shodan_host(ip_address="1.2.3.4", history=True)
    """
    cmd_parts = ["shodan", "host"]

    if history:
        cmd_parts.append("--history")

    cmd_parts.append(ip_address)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
