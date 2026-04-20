"""
KRYON Knowledge Scrapers
=========================

Multi-source knowledge scraping for RAG system.

Available Scrapers:
- ExploitDBScraper: Exploit-DB database
- NVDScraper: National Vulnerability Database
- GitHubScraper: GitHub PoC repositories
- WriteupScraper: CTF writeups (HTB, THM)
- IntelligenceScraper: MITRE ATT&CK + CISA KEV
- OWASPScraper: OWASP Cheat Sheet Series
- CWEScraper: MITRE Common Weakness Enumeration
- VendorAdvisoryScraper: CISA KEV + GitHub Security Advisories
- StaticSeedScraper: Static seed data from JSON files
"""

from .base_scraper import BaseScraper
from .cwe_scraper import CWEScraper
from .exploit_db_scraper import ExploitDBScraper
from .github_scraper import GitHubScraper
from .intelligence_scraper import IntelligenceScraper
from .nvd_scraper import NVDScraper
from .owasp_scraper import OWASPScraper
from .research_writeup_scraper import ResearchWriteupScraper
from .static_seed_scraper import StaticSeedScraper
from .vendor_advisory_scraper import VendorAdvisoryScraper
from .writeup_scraper import WriteupScraper

__all__ = [
    "BaseScraper",
    "CWEScraper",
    "ExploitDBScraper",
    "GitHubScraper",
    "IntelligenceScraper",
    "NVDScraper",
    "OWASPScraper",
    "ResearchWriteupScraper",
    "StaticSeedScraper",
    "VendorAdvisoryScraper",
    "WriteupScraper",
    "SCRAPER_REGISTRY",
]

# Centralized registry — maps source name to scraper class.
# Used by auto_updater and the /knowledge/scrape API endpoint.
SCRAPER_REGISTRY: dict[str, type[BaseScraper]] = {
    "intelligence": IntelligenceScraper,
    "nvd": NVDScraper,
    "github": GitHubScraper,
    "exploit-db": ExploitDBScraper,
    "writeups": WriteupScraper,
    "research-writeups": ResearchWriteupScraper,
    "owasp": OWASPScraper,
    "cwe": CWEScraper,
    "vendor-advisories": VendorAdvisoryScraper,
    "static-seed": StaticSeedScraper,
}
