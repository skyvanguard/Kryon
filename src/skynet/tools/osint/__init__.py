"""
OSINT & Threat Intelligence Tools
==================================

This module provides tools for Open Source Intelligence (OSINT) gathering,
threat intelligence, and malware identification.

Tool Categories:
- OSINT: Email/subdomain harvesting, employee enumeration
- Internet Intelligence: Shodan, Censys, internet-wide device discovery
- Threat Intelligence: VirusTotal, malware analysis
- Reconnaissance: Automated OSINT frameworks
- Malware Detection: Yara pattern matching

KRYON Integration: Phase 12
"""

from skynet.tools.osint.shodan_cli import shodan_host, shodan_search
from skynet.tools.osint.theharvester import theharvester_search
from skynet.tools.osint.threat_intel import (
    censys_search,
    recon_ng_search,
    spiderfoot_scan,
    virustotal_search,
)
from skynet.tools.osint.yara_scan import yara_scan_directory, yara_scan_file

__all__ = [
    # theHarvester - OSINT (1 function)
    "theharvester_search",
    # Shodan - Internet intelligence (2 functions)
    "shodan_search",
    "shodan_host",
    # Yara - Malware detection (2 functions)
    "yara_scan_file",
    "yara_scan_directory",
    # Threat Intelligence (4 functions)
    "recon_ng_search",
    "virustotal_search",
    "spiderfoot_scan",
    "censys_search",
]
