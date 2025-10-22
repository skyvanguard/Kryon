"""
TheHarvester - OSINT and Information Gathering
==============================================

TheHarvester is a tool for gathering emails, subdomains, hosts, employee
names, open ports and banners from different public sources.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool


@function_tool
def theharvester_scan(
    domain: str,
    sources: str = "all",
    limit: int = 500,
    start: int = 0,
    dns_lookup: bool = True,
    dns_brute: bool = False,
    dns_tld: bool = False,
    take_over: bool = False,
    screenshot: bool = False,
    virtual_host: bool = False,
    shodan: bool = False,
    api_keys_file: str = "",
    ctf=None
) -> str:
    """
    Comprehensive OSINT gathering from multiple public sources.

    Collects emails, subdomains, IPs, URLs, and other intelligence
    about a target domain from search engines and databases.

    Args:
        domain: Target domain to investigate
        sources: Data sources to use (default: all)
        limit: Limit results per source (default: 500)
        start: Start result number (pagination)
        dns_lookup: Perform DNS lookups on discovered hosts
        dns_brute: Enable DNS brute forcing
        dns_tld: Perform TLD expansion discovery
        take_over: Check for subdomain takeover possibilities
        screenshot: Take screenshots of discovered websites
        virtual_host: Verify discovered hosts with virtual host checks
        shodan: Use Shodan to query discovered hosts
        api_keys_file: Path to API keys configuration file
        ctf: CTF context for execution

    Returns:
        str: OSINT data including emails, hosts, IPs, and URLs

    Examples:
        # Basic OSINT gathering
        theharvester_scan(domain="example.com")

        # Specific sources only
        theharvester_scan(
            domain="example.com",
            sources="google,bing,linkedin,twitter"
        )

        # Comprehensive scan with DNS brute force
        theharvester_scan(
            domain="example.com",
            sources="all",
            dns_lookup=True,
            dns_brute=True,
            dns_tld=True
        )

        # Security-focused scan
        theharvester_scan(
            domain="example.com",
            sources="all",
            take_over=True,
            shodan=True,
            virtual_host=True
        )

        # Email harvesting
        theharvester_scan(
            domain="example.com",
            sources="google,bing,yahoo,linkedin",
            limit=1000
        )

    Available Sources:
        - anubis: Anubis-DB
        - baidu: Baidu search engine
        - bevigil: BeVigil mobile app security
        - binaryedge: BinaryEdge Internet scanning
        - bing: Bing search engine
        - bingapi: Bing API (requires key)
        - bufferoverun: BufferOver DNS data
        - censys: Censys Internet scanning
        - certspotter: Certificate Transparency logs
        - crtsh: Certificate Transparency (crt.sh)
        - dnsdumpster: DNS reconnaissance
        - duckduckgo: DuckDuckGo search
        - fullhunt: FullHunt attack surface
        - github-code: GitHub code search
        - google: Google search
        - hackertarget: HackerTarget online tools
        - hunter: Hunter.io email finder
        - intelx: Intelligence X
        - linkedin: LinkedIn (requires auth)
        - netlas: Netlas Internet scanning
        - omnisint: Omnisint OSINT
        - otx: AlienVault OTX
        - pentesttools: Pentest-Tools
        - projectdiscovery: ProjectDiscovery Chaos
        - qwant: Qwant search
        - rapiddns: RapidDNS
        - rocketreach: RocketReach
        - securityTrails: SecurityTrails
        - shodan: Shodan (requires key)
        - sitedossier: SiteDossier
        - subdomaincenter: Subdomain Center
        - subdomainfinderc99: C99 subdomain finder
        - threatcrowd: ThreatCrowd
        - threatminer: ThreatMiner
        - urlscan: URLScan.io
        - virustotal: VirusTotal (requires key)
        - yahoo: Yahoo search
        - zoomeye: ZoomEye (requires key)
    """
    # Build theHarvester command
    cmd_parts = [
        "theHarvester",
        f"-d {domain}",
        f"-b {sources}",
        f"-l {limit}"
    ]

    # Pagination
    if start > 0:
        cmd_parts.append(f"-s {start}")

    # DNS operations
    if dns_lookup:
        cmd_parts.append("-n")

    if dns_brute:
        cmd_parts.append("-c")

    if dns_tld:
        cmd_parts.append("-t")

    # Security checks
    if take_over:
        cmd_parts.append("-k")

    if screenshot:
        cmd_parts.append("-S")

    if virtual_host:
        cmd_parts.append("-v")

    if shodan:
        cmd_parts.append("-s")

    # API keys
    if api_keys_file:
        cmd_parts.append(f"-e {api_keys_file}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
