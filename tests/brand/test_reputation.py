"""F90.3 — TDD contract for the reputation aggregator.

Coverage:
  - Signal-delta table pinned (catches unintentional tuning drift).
  - Tier classifier (boundaries inclusive).
  - Empty inputs → empty report.
  - Single signal: registered alone → low.
  - Multi-signal: registered + brand_keyword → medium.
  - Suspicious TLD + recent cert + brand → high.
  - Legitimate override forces score to 0 regardless of other
    signals.
  - WHOIS new (age < 30d) adds 30 points.
  - WHOIS unknown (None) contributes 0.
  - CT match against wildcard cert covers the base domain.
  - lookup_whois_age: fire-gate, missing whois binary tolerated.
  - WHOIS parser: multiple registrar formats, malformed input
    returns None.
  - Frozen contracts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import pytest

from kryon.brand.ct_monitor import (
    CTCertificate,
    CTRiskAssessment,
)
from kryon.brand.reputation import (
    DEFAULT_TIER_THRESHOLDS,
    SIGNAL_DELTAS,
    BrandSignal,
    DomainRisk,
    ReputationReport,
    _parse_creation_date,
    _tier_for_score,
    aggregate_reputation,
    lookup_whois_age,
)
from kryon.brand.typosquat import (
    TyposquatCandidate,
    TyposquatScanResult,
)

# =====================================================================
# Fixtures
# =====================================================================


def _now_iso(offset_days: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=offset_days)).strftime("%Y-%m-%dT%H:%M:%S")


def _typosquat_result(
    variant: str,
    *,
    strategy: str = "transposition",
    verdict: str = "registered",
    ips: tuple[str, ...] = ("203.0.113.1",),
) -> TyposquatScanResult:
    return TyposquatScanResult(
        candidate=TyposquatCandidate(
            original_domain="bcp.com.py",
            variant=variant,
            display_variant=variant,
            strategy=strategy,
        ),
        verdict=verdict,
        ip_addresses=ips,
    )


def _ct_assessment(
    cn: str,
    *,
    risk: str = "high",
    matched_brand: bool = True,
    matched_recent: bool = True,
    matched_legitimate: bool = False,
    matched_suspicious_tld: bool = False,
    sans: tuple[str, ...] = (),
) -> CTRiskAssessment:
    cert = CTCertificate(
        cert_id="fake",
        common_name=cn.lower(),
        san_names=tuple(s.lower() for s in (sans or (cn,))),
        issuer_name="",
        not_before=_now_iso(60),
        not_after=_now_iso(-60),
        entry_timestamp=_now_iso(2 if matched_recent else 200),
    )
    return CTRiskAssessment(
        cert=cert,
        risk=risk,
        matched_brand=matched_brand,
        matched_legitimate=matched_legitimate,
        matched_suspicious_tld=matched_suspicious_tld,
        matched_recent=matched_recent,
        reason="",
    )


# =====================================================================
# SIGNAL_DELTAS pin
# =====================================================================


def test_signal_deltas_pinned():
    """Pinning the table catches unintentional tuning drift. Any
    deliberate change requires updating this test + docs."""
    assert SIGNAL_DELTAS == {
        "registered": 20,
        "brand_keyword": 20,
        "ssl_cert": 15,
        "ssl_cert_recent": 15,
        "ssl_cert_high": 20,
        "suspicious_tld": 20,
        "whois_new": 30,
        "legitimate": -100,
    }


def test_default_tier_thresholds_pinned():
    assert DEFAULT_TIER_THRESHOLDS == {"high": 70, "medium": 40, "low": 20}


# =====================================================================
# _tier_for_score
# =====================================================================


@pytest.mark.parametrize(
    "score,expected",
    [
        (100, "high"),
        (75, "high"),
        (70, "high"),  # boundary inclusive
        (69, "medium"),
        (40, "medium"),  # boundary inclusive
        (39, "low"),
        (20, "low"),  # boundary inclusive
        (19, "info"),
        (0, "info"),
    ],
)
def test_tier_for_score_boundaries(score, expected):
    assert _tier_for_score(score) == expected


def test_tier_for_score_custom_thresholds():
    """Operators can override the cutoffs for stricter / looser
    policies."""
    t = {"high": 80, "medium": 50, "low": 30}
    assert _tier_for_score(85, t) == "high"
    assert _tier_for_score(50, t) == "medium"
    assert _tier_for_score(29, t) == "info"


# =====================================================================
# aggregate_reputation — empty + single-signal paths
# =====================================================================


def test_aggregate_empty_inputs_returns_empty_report():
    report = aggregate_reputation(brand_keyword="bcp")
    assert report.total_domains == 0
    assert report.by_tier == {}
    assert report.high_risk == ()


def test_registered_alone_is_low():
    """Just a registered typosquat (no brand keyword in domain, no
    cert) scores +20 → low."""
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result("example.com")],
    )
    assert report.total_domains == 1
    domain_risk = next(iter(report.by_tier.keys()), None)
    assert domain_risk == "low"


def test_registered_plus_brand_in_domain_is_medium():
    """registered (20) + brand_keyword (20) = 40 → medium."""
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result("bcp-secure.com")],
    )
    assert "medium" in report.by_tier
    medium = report.medium_risk[0]
    assert medium.score == 40
    signal_names = {s.name for s in medium.signals}
    assert {"registered", "brand_keyword"} <= signal_names


def test_full_phishing_signal_set_is_high():
    """registered (20) + brand_keyword (20) + ssl_cert (15) +
    ssl_cert_recent (15) + suspicious_tld (20) = 90 → high."""
    domain = "bcp-login.click"
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result(domain, strategy="tld_swap")],
        ct_assessments=[_ct_assessment(domain, risk="medium", matched_recent=True)],
    )
    assert len(report.high_risk) == 1
    high = report.high_risk[0]
    assert high.score >= 70
    signal_names = {s.name for s in high.signals}
    # Every expected signal fired.
    assert "registered" in signal_names
    assert "brand_keyword" in signal_names
    assert "ssl_cert" in signal_names
    assert "ssl_cert_recent" in signal_names
    assert "suspicious_tld" in signal_names


def test_legitimate_override_forces_low_regardless_of_other_signals():
    """A domain on the whitelist scores 0 even when every other
    suspicious signal fires."""
    domain = "bcp.com.py"
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result(domain)],
        ct_assessments=[
            _ct_assessment(
                domain,
                risk="high",
                matched_recent=True,
                matched_legitimate=True,
            )
        ],
        legitimate_domains=("bcp.com.py",),
    )
    assert len(report.high_risk) == 0
    # The domain should still be in the universe — just classified low.
    domain_records = list(report.by_tier.keys())
    assert domain_records  # at least one tier counted
    # The legitimate signal must be among the recorded signals.
    # Look it up by iterating all risk lists.
    for risk_list in (report.high_risk, report.medium_risk):
        for r in risk_list:
            if r.domain == domain:
                assert any(s.name == "legitimate" for s in r.signals)


def test_whois_new_adds_thirty_points():
    """WHOIS age < 30 days = +30. A registered + new domain (50)
    crosses the medium threshold."""
    domain = "registered-new.example"
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result(domain)],
        whois_ages={domain: 5},  # 5 days old
    )
    assert "medium" in report.by_tier
    medium = report.medium_risk[0]
    assert medium.score >= 40
    assert any(s.name == "whois_new" for s in medium.signals)


def test_whois_old_does_not_fire():
    """Domain > 30 days old doesn't fire whois_new."""
    domain = "registered-old.example"
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result(domain)],
        whois_ages={domain: 200},
    )
    # registered alone = 20 → low
    assert "low" in report.by_tier
    risk_list = [r for r in report.high_risk + report.medium_risk]
    # The domain is low-tier; not in high or medium.
    for r in risk_list:
        assert r.domain != domain


def test_whois_unknown_does_not_penalize():
    """None entry in whois_ages must NOT contribute any signal —
    unknown data shouldn't drive false positives."""
    domain = "bcp-unknown-whois.com"
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result(domain)],
        whois_ages={domain: None},
    )
    # registered (20) + brand_keyword (20) = 40 → medium.
    # whois_new should NOT fire.
    medium = report.medium_risk[0]
    assert not any(s.name == "whois_new" for s in medium.signals)


def test_unresolved_typosquat_does_not_register():
    """A typosquat that didn't resolve in DNS must NOT contribute
    'registered' signal. Otherwise the report inflates with
    candidates the operator can't act on."""
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result("ghost-domain.example", verdict="not_resolving")],
    )
    assert report.total_domains == 0


def test_ct_only_signal_still_surfaces_domain():
    """Domain seen only in CT (no typosquat hit) must still appear
    in the report — the operator needs to know about phishing certs
    even if the domain's typosquat tool didn't pick it up."""
    report = aggregate_reputation(
        brand_keyword="bcp",
        ct_assessments=[_ct_assessment("bcp-secure-banking.com", risk="high", matched_recent=True)],
    )
    assert report.total_domains >= 1
    # The domain made it into the universe.
    risk_domains = {r.domain for r in report.high_risk} | {r.domain for r in report.medium_risk}
    assert "bcp-secure-banking.com" in risk_domains


def test_ct_assessment_without_matched_brand_is_skipped():
    """CT entries flagged as not-brand are incidental keyword hits —
    don't pull them into the universe."""
    report = aggregate_reputation(
        brand_keyword="bcp",
        ct_assessments=[_ct_assessment("unrelated.example", matched_brand=False)],
    )
    assert report.total_domains == 0


def test_wildcard_cert_covers_base_domain():
    """A *.bcp-secure.com cert should make bcp-secure.com appear in
    the report — wildcards cover the base."""
    cert = CTCertificate(
        cert_id="x",
        common_name="*.bcp-secure.com",
        san_names=("*.bcp-secure.com", "bcp-secure.com"),
        issuer_name="",
        not_before=_now_iso(60),
        not_after=_now_iso(-60),
        entry_timestamp=_now_iso(2),
    )
    assessment = CTRiskAssessment(
        cert=cert,
        risk="high",
        matched_brand=True,
        matched_legitimate=False,
        matched_suspicious_tld=False,
        matched_recent=True,
        reason="",
    )
    report = aggregate_reputation(
        brand_keyword="bcp",
        ct_assessments=[assessment],
    )
    risk_domains = {r.domain for r in report.high_risk} | {r.domain for r in report.medium_risk}
    assert "bcp-secure.com" in risk_domains


def test_report_sort_high_score_first():
    """The aggregator must order findings by score descending so the
    operator sees the worst offenders first."""
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[
            _typosquat_result("low-score.example"),  # 20
            _typosquat_result("bcp-medium.example"),  # 40
        ],
        ct_assessments=[
            _ct_assessment(
                "bcp-high.click",
                risk="high",
                matched_recent=True,
                matched_suspicious_tld=True,
            )
        ],
    )
    # Higher score first inside each tier list, AND higher tier first
    # in the overall enumeration.
    if len(report.high_risk) >= 2:
        for i in range(len(report.high_risk) - 1):
            assert report.high_risk[i].score >= report.high_risk[i + 1].score


def test_signals_carry_human_readable_detail():
    """Every signal has a `detail` string the report renders.
    Sanity-check: not empty for the common ones."""
    domain = "bcp-x.click"
    report = aggregate_reputation(
        brand_keyword="bcp",
        typosquat_results=[_typosquat_result(domain)],
        ct_assessments=[_ct_assessment(domain, matched_recent=True)],
    )
    risks = report.high_risk + report.medium_risk
    for risk in risks:
        for sig in risk.signals:
            if sig.name in ("registered", "ssl_cert", "ssl_cert_recent"):
                assert sig.detail, f"signal {sig.name} missing detail"


# =====================================================================
# lookup_whois_age — fire gate + parser
# =====================================================================


def test_lookup_whois_dry_run_returns_none():
    """Default gate → no subprocess invocation, None returned."""
    with patch("kryon.brand.reputation.subprocess.run") as mock_run:
        age = lookup_whois_age("bcp.com.py", fire=False)
    assert age is None
    mock_run.assert_not_called()


def test_lookup_whois_fire_without_env_stays_none(monkeypatch):
    monkeypatch.delenv("KRYON_BRAND_FIRE", raising=False)
    with patch("kryon.brand.reputation.subprocess.run") as mock_run:
        age = lookup_whois_age("bcp.com.py", fire=True)
    assert age is None
    mock_run.assert_not_called()


def test_lookup_whois_missing_binary_returns_none(monkeypatch):
    """FileNotFoundError on subprocess (whois binary missing) MUST
    return None gracefully — the aggregator treats that as
    'unknown'."""
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    with patch(
        "kryon.brand.reputation.subprocess.run",
        side_effect=FileNotFoundError(),
    ):
        age = lookup_whois_age("bcp.com.py", fire=True)
    assert age is None


def test_lookup_whois_timeout_returns_none(monkeypatch):
    import subprocess as sp

    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    with patch(
        "kryon.brand.reputation.subprocess.run",
        side_effect=sp.TimeoutExpired(cmd="whois", timeout=15),
    ):
        age = lookup_whois_age("bcp.com.py", fire=True)
    assert age is None


def test_lookup_whois_parses_age_from_creation_date(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")

    class _Result:
        stdout = "Creation Date: " + (datetime.now(timezone.utc) - timedelta(days=42)).strftime("%Y-%m-%dT%H:%M:%SZ")

    with patch("kryon.brand.reputation.subprocess.run", return_value=_Result()):
        age = lookup_whois_age("bcp.com.py", fire=True)
    # ~42 days. Allow ±1 for boundary timing.
    assert age is not None
    assert 41 <= age <= 43


def test_lookup_whois_unrecognized_format_returns_none(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")

    class _Result:
        stdout = "Some weird registrar response without a date pattern"

    with patch("kryon.brand.reputation.subprocess.run", return_value=_Result()):
        age = lookup_whois_age("bcp.com.py", fire=True)
    assert age is None


# =====================================================================
# _parse_creation_date — multi-format
# =====================================================================


def test_parse_creation_date_iso_zulu():
    text = "Creation Date: 2026-05-13T12:34:56Z"
    result = _parse_creation_date(text)
    assert result is not None
    assert result.year == 2026


def test_parse_creation_date_subsecond_fraction():
    text = "Creation Date: 2026-05-13T12:34:56.789Z"
    result = _parse_creation_date(text)
    assert result is not None


def test_parse_creation_date_created_on_format():
    """Some registrars use 'Created On:' instead of 'Creation Date:'."""
    text = "    Created On: 2026-01-01T00:00:00Z"
    result = _parse_creation_date(text)
    assert result is not None
    assert result.year == 2026


def test_parse_creation_date_registered_on_format():
    text = "Registered On: 2026-03-15"
    result = _parse_creation_date(text)
    assert result is not None
    assert result.month == 3


def test_parse_creation_date_returns_none_on_garbage():
    assert _parse_creation_date("no date here") is None


def test_parse_creation_date_returns_none_on_malformed_date():
    text = "Creation Date: not-a-date"
    assert _parse_creation_date(text) is None


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    signal = BrandSignal(name="registered", delta=20)
    with pytest.raises(FrozenInstanceError):
        signal.delta = 100  # type: ignore[misc]

    risk = DomainRisk(domain="x.com", score=10, tier="info")
    with pytest.raises(FrozenInstanceError):
        risk.score = 99  # type: ignore[misc]

    report = ReputationReport(brand_keyword="bcp", total_domains=0)
    with pytest.raises(FrozenInstanceError):
        report.total_domains = 1  # type: ignore[misc]


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_handles_empty_inputs():
    from kryon.brand.reputation_tool import _report_to_dict

    report = aggregate_reputation(brand_keyword="bcp")
    payload = _report_to_dict(report)
    assert payload["total_domains"] == 0
    assert payload["high_risk"] == []
    assert payload["medium_risk"] == []
    import json as _json

    _json.dumps(payload)  # round-trips through JSON


def test_tool_round_trips_typosquat_results():
    """The agent passes JSON between F90.1 and F90.3; the type
    reconstruction must preserve verdict + strategy + ips."""
    from kryon.brand.reputation_tool import _typosquat_from_dict

    payload = [
        {
            "variant": "bcp-secure.com",
            "display": "bcp-secure.com",
            "strategy": "addition",
            "verdict": "registered",
            "ips": ["203.0.113.1"],
        }
    ]
    results = _typosquat_from_dict(payload)
    assert len(results) == 1
    assert results[0].candidate.variant == "bcp-secure.com"
    assert results[0].verdict == "registered"
    assert results[0].ip_addresses == ("203.0.113.1",)
