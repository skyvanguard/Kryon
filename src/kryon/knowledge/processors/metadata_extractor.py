"""
Metadata Extractor
==================

Extract metadata from documents for better indexing.
"""

import re
from typing import Any, Optional


class MetadataExtractor:
    """
    Extract metadata from text content.

    Extracts:
    - CVE references
    - Tools mentioned
    - Techniques (MITRE ATT&CK)
    - Difficulty level
    - Platforms (Linux, Windows, etc.)
    """

    def __init__(self):
        """Initialize metadata extractor."""
        pass

    def extract(self, content: str) -> dict[str, Any]:
        """
        Extract metadata from content.

        Args:
            content: Text content

        Returns:
            Metadata dictionary
        """
        metadata = {}

        # Extract CVEs
        cves = self._extract_cves(content)
        if cves:
            metadata["cves"] = cves

        # Extract tools
        tools = self._extract_tools(content)
        if tools:
            metadata["tools"] = tools

        # Extract platforms
        platforms = self._extract_platforms(content)
        if platforms:
            metadata["platforms"] = platforms

        # Extract difficulty
        difficulty = self._extract_difficulty(content)
        if difficulty:
            metadata["difficulty"] = difficulty

        # Extract attack types
        attack_types = self._extract_attack_types(content)
        if attack_types:
            metadata["attack_types"] = attack_types

        return metadata

    def _extract_cves(self, content: str) -> list[str]:
        """Extract CVE references."""
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cves = re.findall(cve_pattern, content, re.IGNORECASE)
        return list(set(cves))  # Unique

    def _extract_tools(self, content: str) -> list[str]:
        """Extract mentioned tools."""
        tools = [
            "nmap",
            "metasploit",
            "burp suite",
            "sqlmap",
            "nikto",
            "gobuster",
            "dirbuster",
            "hydra",
            "john",
            "hashcat",
            "netcat",
            "nc",
            "socat",
            "wireshark",
            "tcpdump",
            "nessus",
            "openvas",
            "bloodhound",
            "mimikatz",
            "powersploit",
            "empire",
            "covenant",
            "cobalt strike",
            "linpeas",
            "winpeas",
            "exploit-db",
            "searchsploit",
        ]

        found_tools = []
        content_lower = content.lower()

        for tool in tools:
            if tool in content_lower:
                found_tools.append(tool)

        return found_tools

    def _extract_platforms(self, content: str) -> list[str]:
        """Extract platforms mentioned."""
        platforms = {
            "linux": ["linux", "ubuntu", "debian", "centos", "kali"],
            "windows": ["windows", "win10", "win11", "active directory", "ad"],
            "macos": ["macos", "osx", "mac os"],
            "web": ["web", "http", "https", "webapp"],
            "mobile": ["android", "ios", "mobile"],
        }

        found_platforms = []
        content_lower = content.lower()

        for platform, keywords in platforms.items():
            if any(keyword in content_lower for keyword in keywords):
                found_platforms.append(platform)

        return found_platforms

    def _extract_difficulty(self, content: str) -> Optional[str]:
        """Extract difficulty level."""
        content_lower = content.lower()

        if "easy" in content_lower or "beginner" in content_lower:
            return "easy"
        elif "medium" in content_lower or "intermediate" in content_lower:
            return "medium"
        elif "hard" in content_lower or "advanced" in content_lower or "insane" in content_lower:
            return "hard"

        return None

    def _extract_attack_types(self, content: str) -> list[str]:
        """Extract attack types mentioned."""
        attack_types = {
            "sqli": ["sql injection", "sqli"],
            "xss": ["cross-site scripting", "xss"],
            "rce": ["remote code execution", "rce"],
            "lfi": ["local file inclusion", "lfi"],
            "rfi": ["remote file inclusion", "rfi"],
            "ssrf": ["server-side request forgery", "ssrf"],
            "xxe": ["xml external entity", "xxe"],
            "csrf": ["cross-site request forgery", "csrf"],
            "idor": ["insecure direct object reference", "idor"],
            "privesc": ["privilege escalation", "privesc"],
            "buffer_overflow": ["buffer overflow", "bof"],
            "brute_force": ["brute force", "bruteforce"],
            "phishing": ["phishing"],
        }

        found_attacks = []
        content_lower = content.lower()

        for attack_type, keywords in attack_types.items():
            if any(keyword in content_lower for keyword in keywords):
                found_attacks.append(attack_type)

        return found_attacks


# Convenience function
def extract_metadata(content: str) -> dict[str, Any]:
    """Extract metadata from content."""
    extractor = MetadataExtractor()
    return extractor.extract(content)
