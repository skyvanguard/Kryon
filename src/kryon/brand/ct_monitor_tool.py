"""F90.2 — agent-facing tool wrapper for the CT monitor."""

from __future__ import annotations

import json
from typing import Any

from kryon.brand.ct_monitor import (
    DEFAULT_MAX_CERTS,
    CTQueryResult,
    classify_cert,
    query_crtsh,
)
from kryon.sdk.agents import function_tool

__all__ = ["ct_monitor"]


def _result_to_summary(
    result: CTQueryResult,
    brand_keyword: str,
    legitimate_csv: str,
    recency_days: int,
) -> dict[str, Any]:
    legitimate = tuple(d.strip() for d in legitimate_csv.split(",") if d.strip())
    if result.verdict != "ok":
        return {
            "keyword": result.keyword,
            "verdict": result.verdict,
            "error": result.error,
            "notes": result.notes,
            "certificate_count": 0,
            "by_risk": {},
            "high_risk": [],
            "medium_risk": [],
        }

    classifications = [
        classify_cert(
            c,
            brand_keyword=brand_keyword,
            legitimate_domains=legitimate,
            recency_days=recency_days,
        )
        for c in result.certificates
    ]
    by_risk: dict[str, int] = {}
    for r in classifications:
        by_risk[r.risk] = by_risk.get(r.risk, 0) + 1

    def _to_dict(a) -> dict[str, Any]:
        return {
            "cert_id": a.cert.cert_id,
            "common_name": a.cert.common_name,
            "san_names": list(a.cert.san_names)[:20],  # cap for context
            "issuer_name": a.cert.issuer_name,
            "not_before": a.cert.not_before,
            "not_after": a.cert.not_after,
            "entry_timestamp": a.cert.entry_timestamp,
            "risk": a.risk,
            "reason": a.reason,
            "matched_brand": a.matched_brand,
            "matched_legitimate": a.matched_legitimate,
            "matched_suspicious_tld": a.matched_suspicious_tld,
            "matched_recent": a.matched_recent,
        }

    return {
        "keyword": result.keyword,
        "verdict": "ok",
        "certificate_count": len(classifications),
        "by_risk": by_risk,
        "high_risk": [_to_dict(a) for a in classifications if a.risk == "high"],
        "medium_risk": [_to_dict(a) for a in classifications if a.risk == "medium"],
    }


@function_tool
def ct_monitor(
    brand_keyword: str,
    legitimate_domains_csv: str = "",
    fire: bool = False,
    max_certs: int = DEFAULT_MAX_CERTS,
    recency_days: int = 30,
    exclude_expired: bool = True,
) -> str:
    """Query crt.sh for certificates matching a brand keyword and
    classify each by risk tier (low / medium / high).

    Args:
        brand_keyword: substring to search for (e.g. "bcp",
            "bancard"). crt.sh wraps it with % so partial matches
            are returned.
        legitimate_domains_csv: comma-separated whitelist of the
            bank's legitimate domains (e.g. "bcp.com.py,bancard.com.py").
            Certs whose identifiers are all covered by the whitelist
            classify as "low" risk regardless of recency.
        fire: required (with KRYON_BRAND_FIRE=true env) for the live
            crt.sh query. Default False = dry-run.
        max_certs: cap on certificates parsed/classified.
        recency_days: window for the "matched_recent" classifier
            input. Default 30.
        exclude_expired: drop expired certs from the crt.sh response
            (default True — expired certs aren't actionable phishing
            infrastructure).

    Returns:
        JSON string with the classification summary. Only high_risk
        + medium_risk entries are surfaced inline; low risk certs
        are counted in `by_risk` but not enumerated to keep the
        agent's context window clean.
    """
    if not brand_keyword.strip():
        return json.dumps({"error": "empty brand_keyword"})

    result = query_crtsh(
        brand_keyword,
        fire=fire,
        max_certs=max_certs,
        exclude_expired=exclude_expired,
    )
    payload = _result_to_summary(
        result,
        brand_keyword=brand_keyword,
        legitimate_csv=legitimate_domains_csv,
        recency_days=recency_days,
    )
    return json.dumps(payload, ensure_ascii=False)
