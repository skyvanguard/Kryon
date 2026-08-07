"""CVE enrichment — EPSS scores, CISA KEV, exploit availability."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from kryon.intelligence.models import CVEDetail

logger = logging.getLogger(__name__)

_CACHE_DIR = Path.home() / ".kryon" / "cache"
_KEV_CACHE = _CACHE_DIR / "cisa_kev.json"
_KEV_MAX_AGE = 86400  # 24h


class CVEEnricher:
    """Enrich CVE data with EPSS, exploit availability, CISA KEV."""

    def __init__(self) -> None:
        self._kev_data: list[dict] | None = None
        self._kev_set: set[str] | None = None

    async def enrich(self, cve_id: str) -> CVEDetail:
        """Full enrichment pipeline for a single CVE."""
        detail = CVEDetail(cve_id=cve_id)

        nvd = await self.get_nvd_detail(cve_id)
        detail.description = nvd.get("description", "")
        detail.cvss_score = nvd.get("cvss_score")
        detail.cvss_vector = nvd.get("cvss_vector")
        detail.cpe_affected = nvd.get("cpe_affected", [])
        detail.references = nvd.get("references", [])

        epss_score, epss_pct = await self.get_epss(cve_id)
        detail.epss_score = epss_score
        detail.epss_percentile = epss_pct

        detail.cisa_kev = await self.check_cisa_kev(cve_id)
        detail.exploit_refs = await self.check_exploit_db(cve_id)
        detail.exploit_available = len(detail.exploit_refs) > 0

        return detail

    async def get_nvd_detail(self, cve_id: str) -> dict:
        """Query NVD API 2.0 for description, CVSS, CPE, references.

        Live fetch (no static corpus). Honors ``NVD_API_KEY`` env (raises the
        rate limit 5→50 req/30s). Best-effort: returns {} on any failure.
        """
        out: dict = {}
        try:
            import httpx

            headers = {}
            key = os.environ.get("NVD_API_KEY", "").strip()
            if key:
                headers["apiKey"] = key
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id},
                    headers=headers,
                )
                resp.raise_for_status()
                vulns = resp.json().get("vulnerabilities", [])
                if not vulns:
                    return out
                cve = vulns[0].get("cve", {})
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        out["description"] = d.get("value", "")
                        break
                metrics = cve.get("metrics", {})
                for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(mkey):
                        cd = metrics[mkey][0].get("cvssData", {})
                        out["cvss_score"] = cd.get("baseScore")
                        out["cvss_vector"] = cd.get("vectorString")
                        break
                cpes: list[str] = []
                for conf in cve.get("configurations", []):
                    for node in conf.get("nodes", []):
                        for m in node.get("cpeMatch", []):
                            if m.get("criteria"):
                                cpes.append(m["criteria"])
                out["cpe_affected"] = cpes[:20]
                out["references"] = [r.get("url", "") for r in cve.get("references", []) if r.get("url")][:10]
        except Exception:
            logger.debug("NVD lookup failed for %s", cve_id, exc_info=True)
        return out

    async def enrich_batch(self, cve_ids: list[str]) -> list[CVEDetail]:
        """Batch enrichment with rate limiting."""
        results: list[CVEDetail] = []
        for cve_id in cve_ids:
            try:
                detail = await self.enrich(cve_id)
                results.append(detail)
            except Exception:
                logger.warning("Failed to enrich %s", cve_id, exc_info=True)
                results.append(CVEDetail(cve_id=cve_id))
        return results

    async def get_epss(self, cve_id: str) -> tuple[float | None, float | None]:
        """Query FIRST EPSS API for exploit prediction score."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.first.org/data/v1/epss",
                    params={"cve": cve_id},
                )
                resp.raise_for_status()
                data = resp.json().get("data", [])
                if data:
                    entry = data[0]
                    return float(entry.get("epss", 0)), float(entry.get("percentile", 0))
        except Exception:
            logger.debug("EPSS lookup failed for %s", cve_id, exc_info=True)
        return None, None

    async def check_cisa_kev(self, cve_id: str) -> bool:
        """Check against local CISA KEV cache."""
        kev_set = await self._load_kev()
        return cve_id.upper() in kev_set

    async def _load_kev(self) -> set[str]:
        """Load CISA KEV catalog (download if stale/missing)."""
        if self._kev_set is not None:
            return self._kev_set

        _CACHE_DIR.mkdir(parents=True, exist_ok=True)

        needs_download = True
        if _KEV_CACHE.exists():
            age = time.time() - _KEV_CACHE.stat().st_mtime
            if age < _KEV_MAX_AGE:
                needs_download = False

        if needs_download:
            try:
                import httpx

                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get(
                        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                    )
                    resp.raise_for_status()
                    _KEV_CACHE.write_bytes(resp.content)
            except Exception:
                logger.debug("CISA KEV download failed", exc_info=True)

        if _KEV_CACHE.exists():
            with open(_KEV_CACHE, encoding="utf-8") as f:
                data = json.load(f)
            self._kev_data = data.get("vulnerabilities", [])
            self._kev_set = {v["cveID"] for v in self._kev_data}
        else:
            self._kev_set = set()

        return self._kev_set

    async def check_exploit_db(self, cve_id: str) -> list[str]:
        """Cross-reference with ExploitDB (via existing scraper if available)."""
        refs: list[str] = []
        try:
            from kryon.knowledge.exploitdb_scraper import search_exploitdb

            results = search_exploitdb(cve_id)
            if results:
                refs = [r.get("url", "") for r in results if r.get("url")]
        except ImportError:
            pass
        except Exception:
            logger.debug("ExploitDB lookup failed for %s", cve_id, exc_info=True)
        return refs
