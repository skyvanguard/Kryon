"""
SpiderFoot - Automated OSINT Collection
=======================================

SpiderFoot is an open source intelligence automation tool. It integrates
with over 200 data sources to gather intelligence on IP addresses,
domain names, e-mail addresses, names, and more.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def spiderfoot_scan(
    target: str,
    modules: str = "all",
    target_type: str = "auto",
    max_threads: int = 3,
    timeout: int = 60,
    output_format: str = "json",
    quiet: bool = False,
    ctf=None
) -> str:
    """
    Comprehensive automated OSINT collection and correlation.

    SpiderFoot automatically discovers and correlates data from 200+
    sources including WHOIS, DNS, search engines, social media, and
    security databases.

    Args:
        target: Target to investigate (domain, IP, email, name, etc.)
        modules: Modules to use (comma-separated or "all")
        target_type: Type of target (auto, IP, domain, email, name, etc.)
        max_threads: Maximum concurrent threads
        timeout: Scan timeout in seconds
        output_format: Output format (json, csv, tab)
        quiet: Suppress output messages
        ctf: CTF context for execution

    Returns:
        str: Comprehensive OSINT data

    Examples:
        # Automatic comprehensive scan
        spiderfoot_scan(target="example.com")

        # Scan IP address
        spiderfoot_scan(
            target="8.8.8.8",
            target_type="IP",
            modules="all"
        )

        # Email investigation
        spiderfoot_scan(
            target="john@example.com",
            target_type="email",
            modules="all"
        )

        # Specific modules only
        spiderfoot_scan(
            target="example.com",
            modules="sfp_dnsresolve,sfp_whois,sfp_socialnetworks"
        )

    Module Categories:
        - DNS & Network: DNS records, WHOIS, BGP, ASN
        - Web: Web tech detection, SSL/TLS, HTTP headers
        - Social Media: Twitter, LinkedIn, GitHub, Instagram
        - Breach Data: HaveIBeenPwned, Dehashed
        - Threat Intel: AbuseIPDB, ThreatCrowd, AlienVault
        - Cloud: AWS, Azure, GCP infrastructure
        - Leaked Credentials: Password dumps, breach databases
        - Dark Web: Tor, dark web mentions
        - Company Data: Employee info, company structure
        - Email: Email addresses, email servers

    Note:
        SpiderFoot CLI mode is used here. For full functionality,
        consider running SpiderFoot web UI and using the API.
    """
    # Build spiderfoot command
    cmd_parts = [
        "spiderfoot",
        "-s", target,
        f"-t {target_type}",
        f"-m {modules}",
        f"-T {max_threads}",
        f"-q {timeout}"
    ]

    # Output format
    if output_format == "json":
        cmd_parts.append("-j")
    elif output_format == "csv":
        cmd_parts.append("-c")

    # Quiet mode
    if quiet:
        cmd_parts.append("-q")

    command = " ".join(cmd_parts)

    # Note: SpiderFoot is primarily a web application
    # This is a simplified CLI wrapper
    return run_command(command, ctf=ctf)
