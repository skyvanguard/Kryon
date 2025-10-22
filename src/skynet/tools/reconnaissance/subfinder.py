"""
Subfinder - Fast Passive Subdomain Discovery
============================================

Subfinder is a subdomain discovery tool that discovers valid subdomains
using passive online sources. It's designed to be fast and efficient.

PERFORMANCE: Results are cached with 12-hour TTL to avoid redundant subdomain
enumeration and improve response times by 10-30x for repeated scans.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool
from skynet.cache import cache_scan_result


@function_tool
@cache_scan_result(scan_type="subdomain_enum", ttl=43200)  # Cache for 12 hours
def subfinder_scan(
    domain: str,
    sources: str = "",
    exclude_sources: str = "",
    recursive: bool = False,
    all_sources: bool = True,
    timeout: int = 30,
    max_time: int = 10,
    threads: int = 10,
    api_config: str = "",
    output_format: str = "text",
    ctf=None
) -> str:
    """
    Fast passive subdomain enumeration using multiple online sources.

    CACHED: Results cached for 12 hours to avoid redundant enumeration.

    Subfinder queries dozens of passive sources including certificate
    transparency logs, search engines, and DNS databases to find subdomains.

    Args:
        domain: Target domain to enumerate
        sources: Comma-separated list of sources to use
        exclude_sources: Comma-separated list of sources to exclude
        recursive: Enable recursive subdomain enumeration
        all_sources: Use all available sources (default: True)
        timeout: Timeout for each source in seconds
        max_time: Maximum time for enumeration in minutes
        threads: Number of concurrent threads
        api_config: Path to API configuration file
        output_format: Output format: text, json
        ctf: CTF context for execution

    Returns:
        str: List of discovered subdomains

    Examples:
        # Basic subdomain enumeration
        subfinder_scan(domain="example.com")

        # Fast scan with specific sources
        subfinder_scan(
            domain="example.com",
            sources="crtsh,virustotal,threatcrowd",
            threads=20
        )

        # Recursive enumeration
        subfinder_scan(
            domain="example.com",
            recursive=True,
            max_time=15
        )

        # With API keys for enhanced results
        subfinder_scan(
            domain="example.com",
            all_sources=True,
            api_config="~/.config/subfinder/config.yaml"
        )

    Available Sources:
        - alienvault, anubis, bevigil, binaryedge
        - bufferover, censys, certspotter, crtsh
        - chaos, chinaz, dnsdb, fofa
        - fullhunt, github, hackertarget, intelx
        - passivetotal, rapiddns, robtex, securitytrails
        - shodan, threatbook, urlscan, virustotal
        - waybackarchive, whoisxmlapi, zoomeye
    """
    # Build subfinder command
    cmd_parts = ["subfinder", "-d", domain]

    if sources:
        cmd_parts.append(f"-sources {sources}")
    elif not all_sources:
        # Use default sources only
        cmd_parts.append("-no-color")

    if exclude_sources:
        cmd_parts.append(f"-exclude-sources {exclude_sources}")

    if recursive:
        cmd_parts.append("-recursive")

    if timeout > 0:
        cmd_parts.append(f"-timeout {timeout}")

    if max_time > 0:
        cmd_parts.append(f"-max-time {max_time}")

    if threads > 0:
        cmd_parts.append(f"-t {threads}")

    if api_config:
        cmd_parts.append(f"-config {api_config}")

    if output_format == "json":
        cmd_parts.append("-json")

    # Add silent mode for cleaner output
    cmd_parts.append("-silent")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
