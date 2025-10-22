"""
DNSEnum - DNS Enumeration Tool
==============================

DNSEnum is a multithreaded Perl script to enumerate DNS information
about a domain and discover non-contiguous IP blocks.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def dnsenum_scan(
    domain: str,
    wordlist: str = "",
    threads: int = 5,
    delay: int = 0,
    zone_transfer: bool = True,
    reverse_lookup: bool = True,
    google_scraping: bool = True,
    whois: bool = True,
    subfile: str = "",
    ctf=None
) -> str:
    """
    Comprehensive DNS enumeration and information gathering.

    Performs zone transfers, brute force subdomain enumeration, reverse
    lookups, Google scraping, and WHOIS queries.

    Args:
        domain: Target domain to enumerate
        wordlist: Path to wordlist for subdomain brute forcing
        threads: Number of concurrent threads (default: 5)
        delay: Delay between requests in seconds
        zone_transfer: Attempt DNS zone transfer
        reverse_lookup: Perform reverse DNS lookups
        google_scraping: Scrape Google for subdomains
        whois: Perform WHOIS queries
        subfile: File containing list of subdomains to check
        ctf: CTF context for execution

    Returns:
        str: DNS enumeration results

    Examples:
        # Basic DNS enumeration
        dnsenum_scan(domain="example.com")

        # Comprehensive scan with brute force
        dnsenum_scan(
            domain="example.com",
            wordlist="/usr/share/wordlists/dnsmap.txt",
            threads=10
        )

        # Stealthy scan with delays
        dnsenum_scan(
            domain="example.com",
            delay=3,
            threads=2,
            google_scraping=True
        )

        # Zone transfer attempt only
        dnsenum_scan(
            domain="example.com",
            zone_transfer=True,
            reverse_lookup=False,
            google_scraping=False
        )
    """
    # Build dnsenum command
    cmd_parts = ["dnsenum"]

    # Add wordlist for brute forcing
    if wordlist:
        cmd_parts.append(f"-f {wordlist}")

    # Threading
    cmd_parts.append(f"--threads {threads}")

    # Delay between requests
    if delay > 0:
        cmd_parts.append(f"--delay {delay}")

    # Disable options if needed
    if not zone_transfer:
        cmd_parts.append("--noreverse")

    if not google_scraping:
        cmd_parts.append("--nogoogle")

    if not whois:
        cmd_parts.append("--nowhois")

    # Subdomain file
    if subfile:
        cmd_parts.append(f"-s {subfile}")

    # Add domain
    cmd_parts.append(domain)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
