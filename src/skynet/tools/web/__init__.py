"""
SKYNET Framework - Web Security Tools Module
============================================

Advanced web application security testing and vulnerability scanning tools.

Tool Categories:
- Vulnerability Scanning: Nuclei, Nikto
- SQL Injection: SQLMap, NoSQLMap
- Parameter Fuzzing: Arjun, ParamSpider
- CMS Scanning: WPScan, Joomscan
- API Testing: FFUF API mode, Postman
- XSS Detection: Dalfox, XSStrike
- Authentication: Patator, Hydra web modules
"""

# Vulnerability Scanning
from .nuclei import nuclei_scan, nuclei_template_scan
from .nikto import nikto_scan

# SQL Injection
from .sqlmap import sqlmap_scan, sqlmap_crawl, sqlmap_request

# Parameter Discovery
from .arjun import arjun_scan
from .paramspider import paramspider_discover

# CMS Scanning
from .wpscan import wpscan_enumerate, wpscan_vuln_scan

# XSS Detection
from .dalfox import dalfox_scan, dalfox_pipe

# Web Crawling
from .katana import katana_crawl

__all__ = [
    # Vulnerability Scanning
    "nuclei_scan",
    "nuclei_template_scan",
    "nikto_scan",

    # SQL Injection
    "sqlmap_scan",
    "sqlmap_crawl",
    "sqlmap_request",

    # Parameter Discovery
    "arjun_scan",
    "paramspider_discover",

    # CMS Scanning
    "wpscan_enumerate",
    "wpscan_vuln_scan",

    # XSS Detection
    "dalfox_scan",
    "dalfox_pipe",

    # Web Crawling
    "katana_crawl",
]
