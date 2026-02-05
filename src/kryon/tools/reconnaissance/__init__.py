"""
KRYON Framework - Reconnaissance Tools Module
==============================================

Comprehensive reconnaissance and information gathering tools for
autonomous cybersecurity operations.

Tool Categories:
- Network Scanning: Nmap, Rustscan, Masscan
- DNS Enumeration: Amass, Subfinder, DNSEnum
- Web Discovery: FFuf, Gobuster, Feroxbuster
- OSINT: TheHarvester, Shodan, SpiderFoot
- Service Detection: Whatweb, Wappalyzer
"""

# Network Scanning
# DNS & Subdomain Enumeration
from .amass import amass_enum, amass_intel
from .dnsenum import dnsenum_scan
from .feroxbuster import feroxbuster_scan

# Web Discovery
from .ffuf import ffuf_scan, ffuf_vhost
from .gobuster import gobuster_dir, gobuster_dns, gobuster_vhost
from .masscan import masscan_scan
from .nmap import nmap
from .rustscan import rustscan
from .shodan import shodan_host_info, shodan_search
from .spiderfoot import spiderfoot_scan
from .subfinder import subfinder_scan

# OSINT & Information Gathering
from .theharvester import theharvester_scan
from .wappalyzer import wappalyzer_detect

# Service & Technology Detection
from .whatweb import whatweb_scan

__all__ = [
    # Network Scanning
    "nmap",
    "rustscan",
    "masscan_scan",
    # DNS & Subdomain
    "amass_enum",
    "amass_intel",
    "subfinder_scan",
    "dnsenum_scan",
    # Web Discovery
    "ffuf_scan",
    "ffuf_vhost",
    "gobuster_dir",
    "gobuster_dns",
    "gobuster_vhost",
    "feroxbuster_scan",
    # OSINT
    "theharvester_scan",
    "shodan_search",
    "shodan_host_info",
    "spiderfoot_scan",
    # Technology Detection
    "whatweb_scan",
    "wappalyzer_detect",
]
