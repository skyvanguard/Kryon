"""
Amass - Advanced Subdomain Discovery
=====================================

OWASP Amass is a comprehensive subdomain enumeration tool that uses
multiple techniques including DNS enumeration, web scraping, recursive
brute forcing, crawling, and API integration.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def amass_enum(
    domain: str,
    passive: bool = False,
    active: bool = False,
    brute: bool = False,
    wordlist: str = "",
    max_dns_queries: int = 0,
    timeout: int = 0,
    api_config: str = "",
    output_format: str = "text",
    ctf=None
) -> str:
    """
    Comprehensive subdomain enumeration and network mapping.

    Uses multiple intelligence sources, DNS enumeration, web scraping,
    and brute force techniques to discover subdomains.

    Args:
        domain: Target domain to enumerate
        passive: Use only passive reconnaissance techniques (no DNS queries)
        active: Enable active reconnaissance (zone transfers, crawling)
        brute: Enable brute force subdomain discovery
        wordlist: Path to wordlist for brute forcing
        max_dns_queries: Maximum number of DNS queries per minute (rate limit)
        timeout: Minutes to wait before stopping enumeration
        api_config: Path to API configuration file (for VirusTotal, etc.)
        output_format: Output format: text, json
        ctf: CTF context for execution

    Returns:
        str: Discovered subdomains and related information

    Examples:
        # Passive reconnaissance only (stealthy)
        amass_enum(domain="example.com", passive=True)

        # Active enumeration with DNS queries
        amass_enum(
            domain="example.com",
            active=True,
            max_dns_queries=1000
        )

        # Comprehensive scan with brute force
        amass_enum(
            domain="example.com",
            active=True,
            brute=True,
            wordlist="/usr/share/wordlists/amass/subdomains-top1mil.txt"
        )

        # With API keys for enhanced results
        amass_enum(
            domain="example.com",
            active=True,
            api_config="~/.config/amass/config.ini"
        )
    """
    # Build amass enum command
    cmd_parts = ["amass", "enum", "-d", domain]

    if passive:
        cmd_parts.append("-passive")

    if active:
        cmd_parts.append("-active")

    if brute:
        cmd_parts.append("-brute")
        if wordlist:
            cmd_parts.append(f"-w {wordlist}")

    if max_dns_queries > 0:
        cmd_parts.append(f"-max-dns-queries {max_dns_queries}")

    if timeout > 0:
        cmd_parts.append(f"-timeout {timeout}")

    if api_config:
        cmd_parts.append(f"-config {api_config}")

    if output_format == "json":
        cmd_parts.append("-json")

    # Add verbosity
    cmd_parts.append("-v")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def amass_intel(
    target: str,
    whois: bool = True,
    asn: bool = False,
    cidr: bool = False,
    active: bool = False,
    api_config: str = "",
    ctf=None
) -> str:
    """
    Intelligence gathering for network reconnaissance.

    Discovers root domains, ASN information, CIDR ranges, and related
    infrastructure for a given target organization or IP range.

    Args:
        target: Organization name, domain, or IP/CIDR to investigate
        whois: Perform reverse WHOIS lookups
        asn: Look up ASN information
        cidr: Discover CIDR ranges
        active: Enable active reconnaissance techniques
        api_config: Path to API configuration file
        ctf: CTF context for execution

    Returns:
        str: Intelligence data including domains, ASNs, and IP ranges

    Examples:
        # Discover all domains owned by organization
        amass_intel(
            target="example.com",
            whois=True,
            asn=True
        )

        # Find CIDR ranges for IP
        amass_intel(
            target="8.8.8.8",
            cidr=True,
            asn=True
        )

        # Comprehensive intelligence gathering
        amass_intel(
            target="Example Corp",
            whois=True,
            asn=True,
            cidr=True,
            active=True,
            api_config="~/.config/amass/config.ini"
        )
    """
    # Build amass intel command
    cmd_parts = ["amass", "intel"]

    # Determine target type
    if "." in target and not target.startswith("http"):
        # Domain
        cmd_parts.extend(["-d", target])
    elif any(c.isdigit() for c in target) and ("/" in target or "." in target):
        # IP or CIDR
        cmd_parts.extend(["-addr", target])
    else:
        # Organization name
        cmd_parts.extend(["-org", f'"{target}"'])

    if whois:
        cmd_parts.append("-whois")

    if asn:
        cmd_parts.append("-asn")

    if cidr:
        cmd_parts.append("-cidr")

    if active:
        cmd_parts.append("-active")

    if api_config:
        cmd_parts.append(f"-config {api_config}")

    # Add verbosity
    cmd_parts.append("-v")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
