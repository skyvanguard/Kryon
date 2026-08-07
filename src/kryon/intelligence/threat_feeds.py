"""Threat feed aggregation — AbuseIPDB, VirusTotal, DNS blacklists."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


class ThreatFeedAggregator:
    """Aggregate threat intelligence from multiple free feeds."""

    def __init__(self) -> None:
        self._abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
        self._virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY")

    async def check_ip(self, ip: str) -> dict:
        """Check IP against AbuseIPDB (free tier: 1000 checks/day)."""
        if not self._abuseipdb_key:
            return {"source": "abuseipdb", "available": False, "reason": "no_api_key"}

        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": self._abuseipdb_key,
                        "Accept": "application/json",
                    },
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "available": True,
                    "ip": ip,
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "is_tor": data.get("isTor", False),
                }
        except Exception:
            logger.debug("AbuseIPDB check failed for %s", ip, exc_info=True)
            return {"source": "abuseipdb", "available": False, "reason": "error"}

    async def check_domain(self, domain: str) -> dict:
        """Check domain reputation via DNS blacklists."""
        import asyncio
        import socket

        blacklists = [
            "zen.spamhaus.org",
            "dnsbl.sorbs.net",
            "bl.spamcop.net",
        ]
        hits: list[str] = []

        for bl in blacklists:
            query = f"{domain}.{bl}"
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, socket.gethostbyname, query)
                hits.append(bl)
            except socket.gaierror:
                pass
            except Exception:
                pass

        return {
            "source": "dnsbl",
            "available": True,
            "domain": domain,
            "blacklisted": len(hits) > 0,
            "blacklists_hit": hits,
            "total_checked": len(blacklists),
        }

    async def check_hash(self, file_hash: str) -> dict:
        """Check file hash against VirusTotal (free: 4 req/min)."""
        if not self._virustotal_key:
            return {"source": "virustotal", "available": False, "reason": "no_api_key"}

        try:
            import httpx

            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": self._virustotal_key},
                )
                resp.raise_for_status()
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "available": True,
                    "hash": file_hash,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "detection_names": list(
                        attrs.get("popular_threat_classification", {}).get("suggested_threat_label", [])
                    )[:5],
                }
        except Exception:
            logger.debug("VirusTotal check failed for %s", file_hash, exc_info=True)
            return {"source": "virustotal", "available": False, "reason": "error"}

    async def get_cisa_kev_list(self) -> list[dict]:
        """Download and return CISA KEV catalog."""
        from kryon.intelligence.cve_enrichment import CVEEnricher

        enricher = CVEEnricher()
        await enricher._load_kev()
        return enricher._kev_data or []
