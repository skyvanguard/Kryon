"""F2 — cve_intel: live CVE intelligence tool (no static RAG corpus).

Queries NVD / CISA-KEV / EPSS / ExploitDB **live** and returns an
offensive-oriented triage verdict ("is this CVE worth pursuing right now?").
Replaces the static ChromaDB CVE corpus that was 94% duplicated and never
queried usefully (see the offensive pivot). Reuses ``CVEEnricher``.

Free APIs used (no key required; NVD_API_KEY env raises NVD rate limits):
- NVD API 2.0 (description, CVSS, CPE, references)
- CISA KEV (actively-exploited catalog, cached 24h)
- FIRST EPSS (exploit-probability score)
- ExploitDB (public exploit references)
"""

from __future__ import annotations

import os
import re
from typing import Any

from kryon.sdk.agents import function_tool

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Offensive-triage thresholds (named, not magic numbers).
_EPSS_HIGH = 0.5
_CVSS_CRITICAL = 9.0
_CVSS_HIGH = 7.0
_PURSUE_SCORE = 50
_CONSIDER_SCORE = 20


def _verdict(detail: Any) -> dict[str, Any]:
    """Offensive triage: should the operator pursue this CVE now?

    Weighted by *real-world exploitability* signals (KEV/exploit/EPSS) over
    raw CVSS — a critical CVSS with no exploit is less actionable than a
    medium one in CISA KEV.
    """
    score = 0
    reasons: list[str] = []
    if detail.cisa_kev:
        score += 50
        reasons.append("CISA KEV — actively exploited in the wild")
    if detail.exploit_available:
        score += 25
        reasons.append(f"public exploit ({len(detail.exploit_refs)} ref)")
    if detail.epss_score is not None and detail.epss_score >= _EPSS_HIGH:
        score += 15
        reasons.append(f"EPSS {detail.epss_score:.2f} — high exploit probability")
    if detail.cvss_score is not None and detail.cvss_score >= _CVSS_CRITICAL:
        score += 10
        reasons.append(f"CVSS {detail.cvss_score} (critical)")
    elif detail.cvss_score is not None and detail.cvss_score >= _CVSS_HIGH:
        score += 5
        reasons.append(f"CVSS {detail.cvss_score} (high)")

    if score >= _PURSUE_SCORE:
        priority = "PURSUE"
    elif score >= _CONSIDER_SCORE:
        priority = "CONSIDER"
    else:
        priority = "LOW"
    return {"priority": priority, "pursue_score": score, "reasons": reasons}


async def _nvd_keyword_search(query: str, max_results: int) -> list[dict[str, Any]]:
    """Search NVD by keyword. Best-effort; returns [] on failure."""
    out: list[dict[str, Any]] = []
    try:
        import httpx

        headers = {}
        key = os.environ.get("NVD_API_KEY", "").strip()
        if key:
            headers["apiKey"] = key
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": query, "resultsPerPage": min(max_results, 20)},
                headers=headers,
            )
            resp.raise_for_status()
            for v in resp.json().get("vulnerabilities", [])[:max_results]:
                cve = v.get("cve", {})
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:200]
                        break
                cvss = None
                metrics = cve.get("metrics", {})
                for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(mk):
                        cvss = metrics[mk][0].get("cvssData", {}).get("baseScore")
                        break
                out.append({"cve_id": cve.get("id", ""), "cvss_score": cvss, "summary": desc})
    except Exception:
        pass
    out.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)
    return out


@function_tool
async def cve_intel(query: str, max_results: int = 5) -> dict[str, Any]:
    """Live CVE / vulnerability intelligence with an offensive triage verdict.

    Pass a CVE id (e.g. ``CVE-2024-3094``) for full live enrichment
    (NVD description + CVSS + EPSS + CISA-KEV + public exploits) plus a
    PURSUE/CONSIDER/LOW verdict. Pass a keyword/product (e.g.
    ``apache struts rce``) to search NVD ranked by CVSS. Data is fetched
    live from free APIs — there is no stale local corpus.
    """
    from kryon.intelligence.cve_enrichment import CVEEnricher

    m = _CVE_RE.search(query or "")
    if m:
        cve_id = m.group(0).upper()
        detail = await CVEEnricher().enrich(cve_id)
        return {
            "mode": "cve_detail",
            "cve_id": cve_id,
            "description": detail.description,
            "cvss_score": detail.cvss_score,
            "cvss_vector": detail.cvss_vector,
            "epss_score": detail.epss_score,
            "cisa_kev": detail.cisa_kev,
            "exploit_available": detail.exploit_available,
            "exploit_refs": detail.exploit_refs[:5],
            "cpe_affected": detail.cpe_affected[:10],
            "references": detail.references[:5],
            "verdict": _verdict(detail),
        }
    results = await _nvd_keyword_search(query, max_results)
    return {
        "mode": "keyword_search",
        "query": query,
        "count": len(results),
        "results": results,
    }
