"""
DuckDuckGo Search - Free Web Search (No API Key Required)
==========================================================

Provides web search capability using DuckDuckGo via the duckduckgo-search
package. No API keys needed — works out of the box.
"""

import logging

from kryon.agents.guardrails import sanitize_external_content
from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)


@function_tool
def duckduckgo_search(
    query: str,
    num_results: int = 10,
    region: str = "wt-wt",
    timelimit: str = "",
) -> str:
    """
    Search the web using DuckDuckGo (free, no API key required).

    Use this to research CVEs, exploits, advisories, target technologies,
    or any OSINT gathering during reconnaissance.

    Args:
        query: Search query (e.g., "CVE-2024-1234 exploit", "Apache 2.4.49 vulnerability")
        num_results: Maximum number of results to return (default: 10, max: 20)
        region: Region for results. Default "wt-wt" (worldwide). Examples: "us-en", "uk-en", "es-es"
        timelimit: Time filter. "" for any time, "d" for past day, "w" for past week, "m" for past month, "y" for past year

    Returns:
        Formatted search results with titles, URLs, and snippets.
    """
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        return "ERROR: duckduckgo-search package not installed. Run: pip install duckduckgo-search"

    num_results = min(max(num_results, 1), 20)

    try:
        with DDGS() as ddgs:
            kwargs = {
                "keywords": query,
                "max_results": num_results,
                "region": region,
            }
            if timelimit:
                kwargs["timelimit"] = timelimit

            results = list(ddgs.text(**kwargs))

        if not results:
            return f"No results found for: {query}"

        formatted = f"DuckDuckGo Search Results for: {query}\n{'=' * 60}\n\n"
        for i, r in enumerate(results, 1):
            title = sanitize_external_content(r.get("title", "No title"))
            url = r.get("href", "No URL")
            snippet = sanitize_external_content(r.get("body", "No snippet"))
            formatted += f"[{i}] {title}\n    URL: {url}\n    {snippet}\n\n"

        return formatted

    except Exception as e:
        logger.warning("DuckDuckGo search failed: %s", e)
        return f"Search failed: {e}"
