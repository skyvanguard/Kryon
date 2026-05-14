"""F90.3 — agent-facing wrapper for the reputation aggregator.

The agent typically calls this AFTER typosquat_scan and ct_monitor
have run; it accepts their JSON outputs (or fresh dicts) and
produces the unified risk report.
"""

from __future__ import annotations

import json
from typing import Any

from kryon.brand.ct_monitor import (
    CTCertificate,
    CTRiskAssessment,
    classify_cert,
)
from kryon.brand.reputation import (
    DomainRisk,
    ReputationReport,
    aggregate_reputation,
    lookup_whois_age,
)
from kryon.brand.typosquat import (
    TyposquatCandidate,
    TyposquatScanResult,
)
from kryon.sdk.agents import function_tool

__all__ = ["reputation_aggregate"]


def _typosquat_from_dict(payload: list[dict[str, Any]]) -> list[TyposquatScanResult]:
    """Convert the F90.1 tool's JSON output back into typed results
    for the aggregator. Defensive — unknown keys silently dropped."""
    out: list[TyposquatScanResult] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        candidate = TyposquatCandidate(
            original_domain=str(entry.get("original_domain") or ""),
            variant=str(entry.get("variant") or ""),
            display_variant=str(entry.get("display") or entry.get("variant") or ""),
            strategy=str(entry.get("strategy") or "unknown"),
        )
        out.append(
            TyposquatScanResult(
                candidate=candidate,
                verdict=str(entry.get("verdict") or "dry_run"),
                ip_addresses=tuple(str(ip) for ip in entry.get("ips") or ()),
                error=entry.get("error"),
            )
        )
    return out


def _ct_from_dict(
    payload: list[dict[str, Any]],
    brand_keyword: str,
    legitimate_domains: tuple[str, ...],
) -> list[CTRiskAssessment]:
    """Convert the F90.2 tool's JSON output back into typed
    assessments. Re-classifies via classify_cert so the freshness
    + suspicious-TLD + legitimate logic is consistent — no risk
    of the agent re-pasting a stale tier label."""
    out: list[CTRiskAssessment] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        cert = CTCertificate(
            cert_id=str(entry.get("cert_id") or ""),
            common_name=str(entry.get("common_name") or "").lower(),
            san_names=tuple(str(s).lower() for s in entry.get("san_names") or ()),
            issuer_name=str(entry.get("issuer_name") or ""),
            not_before=str(entry.get("not_before") or ""),
            not_after=str(entry.get("not_after") or ""),
            entry_timestamp=str(entry.get("entry_timestamp") or ""),
            serial_number=str(entry.get("serial_number") or ""),
        )
        out.append(
            classify_cert(
                cert,
                brand_keyword=brand_keyword,
                legitimate_domains=legitimate_domains,
            )
        )
    return out


def _risk_to_dict(risk: DomainRisk) -> dict[str, Any]:
    return {
        "domain": risk.domain,
        "score": risk.score,
        "tier": risk.tier,
        "signals": [{"name": s.name, "delta": s.delta, "detail": s.detail} for s in risk.signals],
        "strategies_observed": list(risk.strategies_observed),
        "ip_addresses": list(risk.ip_addresses),
        "matching_cert_count": risk.matching_cert_count,
    }


def _report_to_dict(report: ReputationReport) -> dict[str, Any]:
    return {
        "brand_keyword": report.brand_keyword,
        "total_domains": report.total_domains,
        "by_tier": dict(report.by_tier),
        "high_risk_count": len(report.high_risk),
        "medium_risk_count": len(report.medium_risk),
        "high_risk": [_risk_to_dict(r) for r in report.high_risk],
        "medium_risk": [_risk_to_dict(r) for r in report.medium_risk],
    }


@function_tool
def reputation_aggregate(
    brand_keyword: str,
    typosquat_results_json: str = "[]",
    ct_results_json: str = "[]",
    legitimate_domains_csv: str = "",
    fetch_whois: bool = False,
    fire: bool = False,
) -> str:
    """Aggregate F90.1 typosquat + F90.2 CT signals into a per-domain
    risk report.

    Args:
        brand_keyword: the brand under protection.
        typosquat_results_json: JSON array of typosquat scan results
            (the `results` field of the F90.1 tool output).
        ct_results_json: JSON array of CT cert entries (the
            `high_risk` + `medium_risk` lists from the F90.2 tool
            concatenated, OR a fresh CT query payload).
        legitimate_domains_csv: bank's whitelist.
        fetch_whois: when True (and KRYON_BRAND_FIRE=true env set),
            issues `whois` lookups for each candidate domain. Slow
            (1-3s per domain) but adds the WHOIS-age signal.
        fire: required for live `whois` lookups when fetch_whois=True.

    Returns:
        JSON string with the ReputationReport summary. High + medium
        domains enumerated; low / info counted only in by_tier.
    """
    if not brand_keyword.strip():
        return json.dumps({"error": "empty brand_keyword"})

    try:
        ts_payload = json.loads(typosquat_results_json)
        ct_payload = json.loads(ct_results_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})

    if not isinstance(ts_payload, list):
        ts_payload = []
    if not isinstance(ct_payload, list):
        ct_payload = []

    legitimate = tuple(d.strip() for d in legitimate_domains_csv.split(",") if d.strip())

    typosquat_results = _typosquat_from_dict(ts_payload)
    ct_assessments = _ct_from_dict(ct_payload, brand_keyword, legitimate)

    whois_ages: dict[str, int | None] | None = None
    if fetch_whois:
        whois_ages = {}
        # Collect candidate domains from both signal sources.
        candidates: set[str] = set()
        for r in typosquat_results:
            if r.verdict == "registered":
                candidates.add(r.candidate.variant.lower())
        for a in ct_assessments:
            if a.matched_brand and not a.matched_legitimate:
                if a.cert.common_name:
                    candidates.add(a.cert.common_name.lower())
                candidates.update(s.lower() for s in a.cert.san_names if not s.startswith("*."))
        for domain in sorted(candidates):
            whois_ages[domain] = lookup_whois_age(domain, fire=fire)

    report = aggregate_reputation(
        brand_keyword=brand_keyword,
        typosquat_results=typosquat_results,
        ct_assessments=ct_assessments,
        whois_ages=whois_ages,
        legitimate_domains=legitimate,
    )
    return json.dumps(_report_to_dict(report), ensure_ascii=False)
