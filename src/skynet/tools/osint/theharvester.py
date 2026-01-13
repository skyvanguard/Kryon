"""
theHarvester - OSINT Information Gathering
===========================================

theHarvester is a tool for gathering emails, subdomains, hosts, employee names,
open ports and banners from different public sources.

PERFORMANCE: OSINT data is cached for 24 hours as public information changes
relatively slowly.
"""

from skynet.cache import cache_scan_result
from skynet.sdk.agents import function_tool
from skynet.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="osint_data", ttl=86400)
def theharvester_search(
    domain: str,
    sources: str = "all",
    limit: int = 500,
    start: int = 0,
    search_type: str = "all",
    output_file: str = "",
    ctf=None,
) -> str:
    """
    Gather OSINT data from multiple sources.

    theHarvester searches public sources for emails, subdomains, hosts,
    and other information related to a target domain.

    Args:
        domain: Target domain (e.g., example.com)
        sources: Data sources (all, google, bing, linkedin, twitter, etc.)
        limit: Maximum results per source
        start: Starting result number
        search_type: What to search (all, emails, hosts, subdomains)
        output_file: Save results to file (JSON/XML/HTML)
        ctf: CTF context for execution

    Returns:
        str: Discovered emails, subdomains, hosts, and other data

    Examples:
        # Basic domain search
        theharvester_search(domain="target.com")

        # Specific sources
        theharvester_search(
            domain="example.com",
            sources="google,bing,linkedin",
            limit=100
        )

        # Email harvesting
        theharvester_search(
            domain="company.com",
            search_type="emails",
            sources="google,linkedin"
        )

        # Subdomain enumeration
        theharvester_search(
            domain="target.com",
            search_type="subdomains",
            sources="all",
            output_file="/tmp/subdomains.json"
        )

    Data Sources:

    Search Engines:
        - google: Google search
        - bing: Bing search
        - yahoo: Yahoo search
        - baidu: Baidu (Chinese)
        - duckduckgo: DuckDuckGo

    Social Media:
        - linkedin: Employee names
        - twitter: Twitter mentions
        - instagram: Instagram profiles

    DNS/Certificates:
        - dnsdumpster: DNS records
        - crtsh: Certificate transparency logs
        - certspotter: Certificate monitoring

    Threat Intelligence:
        - virustotal: VirusTotal data
        - threatcrowd: ThreatCrowd
        - otx: AlienVault OTX

    Other:
        - shodan: Shodan results
        - hunter: Hunter.io emails
        - securitytrails: SecurityTrails

    Discovered Data:

    Emails:
        - Employee email addresses
        - Contact emails
        - Pattern identification

    Subdomains:
        - Active subdomains
        - Historical subdomains
        - Development/staging sites

    Hosts:
        - IP addresses
        - Server locations
        - Infrastructure mapping

    Employee Names:
        - LinkedIn profiles
        - Social media accounts
        - Organizational structure

    Use Cases:

    Reconnaissance:
        - Initial target profiling
        - Attack surface mapping
        - Infrastructure discovery

    Social Engineering:
        - Email list compilation
        - Employee targeting
        - Phishing campaigns (authorized)

    Vulnerability Assessment:
        - Forgotten subdomains
        - Development servers
        - Exposed services

    Security Note:
        theHarvester uses public sources only. Legal in most jurisdictions
        but check local laws. Rate limiting may apply to some sources.
    """
    cmd_parts = ["theHarvester", "-d", domain]

    # Sources
    if sources != "all":
        cmd_parts.extend(["-b", sources])
    else:
        cmd_parts.extend(["-b", "all"])

    # Limit and start
    cmd_parts.extend(["-l", str(limit)])
    if start > 0:
        cmd_parts.extend(["-s", str(start)])

    # Output file
    if output_file:
        cmd_parts.extend(["-f", output_file])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
