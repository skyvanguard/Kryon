"""IoC extraction and correlation from scan results."""

from __future__ import annotations

import logging
import re

from kryon.intelligence.models import IoC

logger = logging.getLogger(__name__)

# Regex patterns for IoC extraction
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|info|biz|me|tv|cc|xyz|dev|app|cloud|security|hack|onion)\b"
)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# Private/reserved IPs to exclude
_PRIVATE_IP_RE = re.compile(r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|255\.)")


class IoCExtractor:
    """Extract and correlate Indicators of Compromise from scan results."""

    def __init__(self, include_private_ips: bool = False) -> None:
        self.include_private_ips = include_private_ips

    def extract_from_text(self, text: str, source: str = "") -> list[IoC]:
        """Regex-based extraction of IPs, domains, hashes, URLs, emails."""
        iocs: list[IoC] = []
        seen: set[str] = set()

        # IPs
        for match in _IPV4_RE.finditer(text):
            ip = match.group()
            if ip in seen:
                continue
            if not self.include_private_ips and _PRIVATE_IP_RE.match(ip):
                continue
            seen.add(ip)
            iocs.append(IoC(type="ip", value=ip, source=source))

        # Domains
        for match in _DOMAIN_RE.finditer(text):
            domain = match.group().lower()
            if domain in seen:
                continue
            seen.add(domain)
            iocs.append(IoC(type="domain", value=domain, source=source))

        # URLs
        for match in _URL_RE.finditer(text):
            url = match.group().rstrip(".,;:")
            if url in seen:
                continue
            seen.add(url)
            iocs.append(IoC(type="url", value=url, source=source))

        # Emails
        for match in _EMAIL_RE.finditer(text):
            email = match.group().lower()
            if email in seen:
                continue
            seen.add(email)
            iocs.append(IoC(type="email", value=email, source=source))

        # Hashes (SHA-256 first to avoid partial matches)
        for match in _SHA256_RE.finditer(text):
            h = match.group().lower()
            if h in seen:
                continue
            seen.add(h)
            iocs.append(IoC(type="hash_sha256", value=h, source=source))

        for match in _SHA1_RE.finditer(text):
            h = match.group().lower()
            if h in seen:
                continue
            seen.add(h)
            iocs.append(IoC(type="hash_sha1", value=h, source=source))

        for match in _MD5_RE.finditer(text):
            h = match.group().lower()
            if h in seen:
                continue
            seen.add(h)
            iocs.append(IoC(type="hash_md5", value=h, source=source))

        return iocs

    async def correlate(self, iocs: list[IoC]) -> list[IoC]:
        """Enrich IoCs via threat feeds (adds threat_score, tags)."""
        from kryon.intelligence.threat_feeds import ThreatFeedAggregator

        feeds = ThreatFeedAggregator()
        enriched: list[IoC] = []

        for ioc in iocs:
            try:
                if ioc.type == "ip":
                    result = await feeds.check_ip(ioc.value)
                    if result.get("available"):
                        score = result.get("abuse_score", 0) / 100.0
                        ioc = ioc.model_copy(
                            update={
                                "threat_score": min(score, 1.0),
                                "tags": (["tor_exit"] if result.get("is_tor") else []),
                            }
                        )
                elif ioc.type == "domain":
                    result = await feeds.check_domain(ioc.value)
                    if result.get("blacklisted"):
                        ioc = ioc.model_copy(
                            update={
                                "threat_score": 0.8,
                                "tags": ["blacklisted"],
                            }
                        )
                elif ioc.type.startswith("hash"):
                    result = await feeds.check_hash(ioc.value)
                    if result.get("available"):
                        total = result.get("total_engines", 1) or 1
                        mal = result.get("malicious", 0)
                        ioc = ioc.model_copy(
                            update={
                                "threat_score": min(mal / total, 1.0),
                                "tags": result.get("detection_names", []),
                            }
                        )
            except Exception:  # noqa: BLE001 — feed enrichment is best-effort; keep the IOC un-enriched
                # Logged (not silently swallowed) so a real bug in the scoring/model_copy
                # path is traceable instead of hidden behind the expected network failure.
                logger.debug("IOC enrichment failed for %s", getattr(ioc, "value", "?"), exc_info=True)
            enriched.append(ioc)

        return enriched
