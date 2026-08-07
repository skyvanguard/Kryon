"""Finding aggregation / dedup — strong-key merge + cross-engine corroboration."""

from __future__ import annotations

from kryon.cli.engage import make_finding
from kryon.services.finding_dedup import (
    aggregate,
    aggregate_sources,
    dedup_key,
    dedupe_findings,
    source_of,
)


def _f(rule_id, host, sev, *, conf=1.0, nv=False, msg="", cwe="X", source=""):
    return make_finding(
        cwe=cwe,
        severity=sev,
        host=host,
        rule_id=rule_id,
        message=msg or rule_id,
        confidence=conf,
        needs_verification=nv,
        source=source,
    )


# --- source attribution ---


def test_source_of_prefixes():
    assert source_of(_f("LYNIS-SSH-7408", "h", "LOW")) == "lynis"
    assert source_of(_f("CINC-sshd-01", "h", "LOW")) == "cinc"
    assert source_of(_f("OPENVAS-1.2.3", "h", "LOW")) == "openvas"
    assert source_of(_f("LNX-1.1", "h", "LOW")) == "kryon-native"
    assert source_of(_f("CVE-2021-3711", "h", "LOW")) == "cve-scan"
    assert source_of(_f("Missing-CSP", "h", "LOW")) == "kryon"


def test_source_of_prefers_explicit_source():
    # A carried source overrides prefix inference (disambiguates CVE findings).
    assert source_of(_f("CVE-2021-3711", "h", "LOW", source="openvas")) == "openvas"


# --- dedup key ---


def test_dedup_key_cve_from_rule_id():
    assert dedup_key(_f("CVE-2021-3711", "10.0.0.5", "HIGH")) == ("cve", "10.0.0.5", "CVE-2021-3711")


def test_dedup_key_cve_from_message():
    f = _f("OPENVAS-1.2.3", "10.0.0.5", "HIGH", msg="OpenSSL flaw CVE-2020-1234 detected")
    assert dedup_key(f) == ("cve", "10.0.0.5", "CVE-2020-1234")


def test_dedup_key_rule_fallback():
    assert dedup_key(_f("LYNIS-SSH-7408", "h", "LOW")) == ("rule", "h", "LYNIS-SSH-7408")


# --- aggregation / corroboration ---


def test_same_cve_distinct_sources_merges_and_boosts():
    ov = _f("CVE-2021-3711", "10.0.0.5", "HIGH", conf=0.8, nv=True, source="openvas")
    own = _f("CVE-2021-3711", "10.0.0.5", "CRITICAL", conf=1.0, nv=False, source="kryon-native")
    aggs = aggregate([ov, own])
    assert len(aggs) == 1
    a = aggs[0]
    assert a.corroboration == 2
    assert a.sources == ("kryon-native", "openvas")  # accurate via carried source
    assert a.finding.severity == "CRITICAL"  # highest-severity representative
    assert a.finding.confidence == 1.0  # boosted (distinct sources)
    assert a.finding.needs_verification is False  # corroborated → trusted
    assert "corroborado por 2 fuentes" in a.finding.message


def test_same_cve_same_source_no_false_corroboration():
    # One engine emitting the same CVE twice must NOT fake corroboration.
    a = _f("CVE-2021-3711", "h", "HIGH", conf=0.8, nv=True, source="openvas")
    b = _f("CVE-2021-3711", "h", "HIGH", conf=0.8, nv=True, source="openvas")
    aggs = aggregate([a, b])
    assert len(aggs) == 1
    assert aggs[0].corroboration == 2  # 2 raw hits...
    assert aggs[0].sources == ("openvas",)  # ...but one source
    assert aggs[0].finding.confidence == 0.8  # NOT boosted
    assert aggs[0].finding.needs_verification is True  # not corroborated
    assert "corroborado" not in aggs[0].finding.message


def test_same_cve_different_host_not_merged():
    aggs = aggregate([_f("CVE-2021-3711", "10.0.0.5", "HIGH"), _f("CVE-2021-3711", "10.0.0.6", "HIGH")])
    assert len(aggs) == 2


def test_cross_engine_same_topic_not_fuzzy_merged():
    # Lynis + Cinc both about SSH but distinct rule_ids → preserved, not merged.
    aggs = aggregate([_f("LYNIS-SSH-7408", "h", "MEDIUM"), _f("CINC-sshd-01", "h", "HIGH")])
    assert len(aggs) == 2


def test_single_finding_no_suffix_no_boost():
    aggs = aggregate([_f("CVE-2021-3711", "h", "HIGH", conf=0.8, nv=True)])
    assert aggs[0].corroboration == 1
    assert "corroborado" not in aggs[0].finding.message
    assert aggs[0].finding.confidence == 0.8
    assert aggs[0].finding.needs_verification is True  # unchanged when uncorroborated


def test_dedupe_findings_returns_plain_findings():
    out = dedupe_findings([_f("CVE-2021-3711", "h", "HIGH"), _f("CVE-2021-3711", "h", "HIGH")])
    assert len(out) == 1
    assert out[0].rule_id == "CVE-2021-3711"
    assert hasattr(out[0], "severity_rank")  # a real Finding


def test_aggregate_sources_accurate_provenance():
    ov = _f("CVE-2021-3711", "h", "HIGH", conf=0.8, nv=True)
    own = _f("CVE-2021-3711", "h", "CRITICAL", conf=1.0)
    aggs = aggregate_sources([("openvas", [ov]), ("kryon-native", [own])])
    assert len(aggs) == 1
    assert aggs[0].sources == ("kryon-native", "openvas")
    assert aggs[0].corroboration == 2


def test_sorted_by_severity():
    aggs = aggregate([_f("LNX-1.1", "h", "LOW"), _f("PG-2.2", "h", "CRITICAL"), _f("NGX-1.1", "h", "MEDIUM")])
    sevs = [a.finding.severity for a in aggs]
    assert sevs == ["CRITICAL", "MEDIUM", "LOW"]


def test_dedup_key_includes_url_for_web_findings():
    # T3-A13: probe ids are static per class, so distinct urls must yield distinct keys.
    from kryon.cli.engage import Finding
    from kryon.services.finding_dedup import dedup_key

    f1 = Finding(
        cwe="CWE-79",
        severity="HIGH",
        host="t",
        rule_id="probe_xss_reflected",
        message="XSS",
        severity_rank=1,
        url="/a?q=",
    )
    f2 = Finding(
        cwe="CWE-79",
        severity="HIGH",
        host="t",
        rule_id="probe_xss_reflected",
        message="XSS",
        severity_rank=1,
        url="/b?q=",
    )
    assert dedup_key(f1) != dedup_key(f2)


def test_dedup_key_without_url_stays_backward_compatible():
    from kryon.cli.engage import Finding
    from kryon.services.finding_dedup import dedup_key

    f = Finding(cwe="CWE-200", severity="LOW", host="t", rule_id="http-server-token", message="x", severity_rank=3)
    assert dedup_key(f) == ("rule", "t", "http-server-token")


def test_dedupe_preserves_distinct_url_instances():
    from kryon.cli.engage import Finding
    from kryon.services.finding_dedup import dedupe_findings

    fs = [
        Finding(
            cwe="CWE-79",
            severity="HIGH",
            host="t",
            rule_id="probe_xss_reflected",
            message="XSS",
            severity_rank=1,
            url=f"/form{i}?q=",
        )
        for i in range(3)
    ]
    out = dedupe_findings(fs)
    assert len(out) == 3  # 3 XSS in 3 different forms must NOT collapse into 1


# --- F210: verification_level preservation across merge ---


def _fl(rule_id, host, sev, level, *, conf=None, source=""):
    from kryon.scoring.confidence import _VERIFICATION_BANDS

    return make_finding(
        cwe="X",
        severity=sev,
        host=host,
        rule_id=rule_id,
        message=rule_id,
        confidence=_VERIFICATION_BANDS[level] if conf is None else conf,
        needs_verification=(level != "confirmed"),
        verification_level=level,
        source=source,
    )


def test_merge_preserves_inferred_level():
    # The bug: dedup rebuilt findings via make_finding and dropped the level,
    # flattening every inferred finding to "confirmed" (defeating F210).
    aggs = aggregate([_fl("CVE-2021-41773", "h", "CRITICAL", "inferred")])
    merged = aggs[0].finding
    assert merged.verification_level == "inferred"
    assert merged.needs_verification is True
    assert merged.confidence <= 0.4


def test_merge_confirmed_stays_confirmed():
    aggs = aggregate([_fl("http-plaintext", "h", "HIGH", "confirmed")])
    assert aggs[0].finding.verification_level == "confirmed"


def test_merge_mixed_group_picks_most_confident_level():
    # A real probe (confirmed) corroborating a banner (inferred) → confirmed.
    aggs = aggregate(
        [
            _fl("CVE-2021-41773", "h", "CRITICAL", "inferred", source="cve-scan"),
            _fl("CVE-2021-41773", "h", "CRITICAL", "confirmed", source="nuclei"),
        ]
    )
    assert len(aggs) == 1
    assert aggs[0].finding.verification_level == "confirmed"


def test_corroboration_does_not_promote_inferred_cap():
    # Two banner-only (inferred) detections from distinct engines corroborate
    # numerically, but the cap must NOT promote them to confirmed.
    aggs = aggregate(
        [
            _fl("CVE-2021-41773", "h", "CRITICAL", "inferred", source="cve-scan"),
            _fl("CVE-2021-41773", "h", "CRITICAL", "inferred", source="openvas"),
        ]
    )
    assert len(aggs) == 1
    merged = aggs[0].finding
    assert merged.verification_level == "inferred"
    assert merged.needs_verification is True
    assert merged.confidence <= 0.4  # corroboration bonus capped to the band
