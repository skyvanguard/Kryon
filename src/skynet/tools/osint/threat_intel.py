"""
Threat Intelligence Tools
==========================

Collection of threat intelligence and OSINT tools for security research.

PERFORMANCE: Threat intelligence data is cached based on volatility.
"""

from skynet.tools.common import run_command, cache_scan_result
from skynet.sdk.agents import function_tool


@function_tool
@cache_scan_result(scan_type="osint_data", ttl=86400)
def recon_ng_search(
    domain: str,
    module: str = "recon/domains-hosts/bing_domain_web",
    workspace: str = "default",
    ctf=None
) -> str:
    """
    Web reconnaissance with Recon-ng framework.

    Args:
        domain: Target domain
        module: Recon-ng module to use
        workspace: Workspace name
        ctf: CTF context

    Returns:
        str: Reconnaissance results

    Examples:
        # Domain reconnaissance
        recon_ng_search(domain="example.com")

        # Contact harvesting
        recon_ng_search(
            domain="target.com",
            module="recon/domains-contacts/whois_pocs"
        )
    """
    command = f'recon-ng -w {workspace} -m {module} -o SOURCE={domain} -x'
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="threat_intel", ttl=43200)
def virustotal_search(
    query: str,
    query_type: str = "domain",
    api_key: str = "",
    ctf=None
) -> str:
    """
    Query VirusTotal for threat intelligence.

    Args:
        query: Search query (domain, IP, file hash)
        query_type: Type of query (domain, ip, file, url)
        api_key: VirusTotal API key
        ctf: CTF context

    Returns:
        str: Threat intelligence from VirusTotal

    Examples:
        # Domain reputation
        virustotal_search(
            query="malicious-site.com",
            query_type="domain",
            api_key="YOUR_KEY"
        )

        # File hash lookup
        virustotal_search(
            query="44d88612fea8a8f36de82e1278abb02f",
            query_type="file"
        )
    """
    if api_key:
        command = f'vt {query_type} {query} --apikey {api_key}'
    else:
        command = f'vt {query_type} {query}'

    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="osint_data", ttl=86400)
def spiderfoot_scan(
    target: str,
    scan_type: str = "all",
    output_file: str = "",
    ctf=None
) -> str:
    """
    Automated OSINT reconnaissance with SpiderFoot.

    Args:
        target: Target domain, IP, or name
        scan_type: Type of scan (all, passive, footprint)
        output_file: Output file path
        ctf: CTF context

    Returns:
        str: Comprehensive OSINT data

    Examples:
        # Full OSINT scan
        spiderfoot_scan(target="example.com", scan_type="all")

        # Passive only
        spiderfoot_scan(target="target.com", scan_type="passive")
    """
    cmd_parts = ["spiderfoot", "-s", target]

    if scan_type != "all":
        cmd_parts.extend(["-t", scan_type])

    if output_file:
        cmd_parts.extend(["-o", output_file])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
@cache_scan_result(scan_type="internet_intel", ttl=43200)
def censys_search(
    query: str,
    search_type: str = "hosts",
    max_results: int = 100,
    ctf=None
) -> str:
    """
    Search Censys for internet intelligence.

    Args:
        query: Search query
        search_type: Type of search (hosts, certificates)
        max_results: Maximum results
        ctf: CTF context

    Returns:
        str: Censys search results

    Examples:
        # Find hosts
        censys_search(query="services.service_name: HTTP")

        # Certificate search
        censys_search(
            query="parsed.subject.common_name: example.com",
            search_type="certificates"
        )
    """
    command = f'censys search {search_type} "{query}" --max-results {max_results}'
    return run_command(command, ctf=ctf)
