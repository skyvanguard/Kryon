"""FOFA — Direct API client for FOFA cyberspace search engine."""

import base64
import os

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def fofa_search(
    query: str,
    fields: str = "host,ip,port,title,server",
    size: int = 100,
    ctf=None,
) -> str:
    """
    Search FOFA cyberspace search engine for internet-facing assets.

    FOFA indexes billions of internet assets. Use FOFA query syntax
    for advanced searches (e.g. domain="example.com", port="443").

    Args:
        query: FOFA search query (e.g. 'domain="example.com"', 'app="Apache"')
        fields: Comma-separated fields to return (host, ip, port, title, server, etc.)
        size: Number of results (max 10000)
        ctf: CTF context

    Returns:
        str: FOFA search results
    """
    api_email = os.getenv("FOFA_EMAIL", "")
    api_key = os.getenv("FOFA_KEY", "")

    if not api_email or not api_key:
        return "Error: FOFA_EMAIL and FOFA_KEY environment variables required."

    # Base64 encode the query as required by FOFA API
    encoded_query = base64.b64encode(query.encode()).decode()

    cmd = (
        f"curl -s 'https://fofa.info/api/v1/search/all"
        f"?email={api_email}&key={api_key}"
        f"&qbase64={encoded_query}"
        f"&fields={fields}"
        f"&size={size}'"
    )

    return run_command(cmd, ctf=ctf)


@function_tool
def fofa_host_detail(
    host: str,
    ctf=None,
) -> str:
    """
    Get detailed information about a specific host from FOFA.

    Args:
        host: Hostname or IP to query
        ctf: CTF context

    Returns:
        str: Detailed host information from FOFA
    """
    api_email = os.getenv("FOFA_EMAIL", "")
    api_key = os.getenv("FOFA_KEY", "")

    if not api_email or not api_key:
        return "Error: FOFA_EMAIL and FOFA_KEY environment variables required."

    cmd = (
        f"curl -s 'https://fofa.info/api/v1/host/{host}"
        f"?email={api_email}&key={api_key}&detail=true'"
    )

    return run_command(cmd, ctf=ctf)
