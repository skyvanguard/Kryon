"""
KRYON Framework - Web Security Tools Module
============================================

Advanced web application security testing and vulnerability scanning tools.

Tool Categories:
- Vulnerability Scanning: Nuclei
- SQL Injection: SQLMap
- Header Analysis: Custom headers tool
- Web Search: Google/Perplexity integration

Note: Additional tools (Nikto, Arjun, ParamSpider, WPScan, Dalfox, Katana)
are planned but not yet implemented.
"""

# Vulnerability Scanning
from .nuclei import nuclei_scan, nuclei_template_scan

# SQL Injection
from .sqlmap import sqlmap_crawl, sqlmap_request, sqlmap_scan

# Web Search (requires API keys)
try:
    from .search_web import make_web_search_with_explanation as make_web_search_with_explanation

    _SEARCH_AVAILABLE = True
except ImportError:
    _SEARCH_AVAILABLE = False

try:
    from .google_search import google_search as google_search

    _GOOGLE_SEARCH_AVAILABLE = True
except ImportError:
    _GOOGLE_SEARCH_AVAILABLE = False

# DuckDuckGo Search (free, no API key)
try:
    from .duckduckgo_search import duckduckgo_search as duckduckgo_search

    _DUCKDUCKGO_AVAILABLE = True
except ImportError:
    _DUCKDUCKGO_AVAILABLE = False

__all__ = [
    # Vulnerability Scanning
    "nuclei_scan",
    "nuclei_template_scan",
    # SQL Injection
    "sqlmap_scan",
    "sqlmap_crawl",
    "sqlmap_request",
]

# Conditionally export search tools
if _SEARCH_AVAILABLE:
    __all__.append("make_web_search_with_explanation")

if _GOOGLE_SEARCH_AVAILABLE:
    __all__.append("google_search")

if _DUCKDUCKGO_AVAILABLE:
    __all__.append("duckduckgo_search")
