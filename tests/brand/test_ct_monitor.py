"""F90.2 — TDD contract for the CT monitor.

Coverage:
  - Fire gate (env + arg) for query_crtsh
  - JSON parsing (full payload + degraded shapes)
  - HTTP 429 distinct verdict (rate_limited)
  - Network failure → error verdict
  - Cap honored (max_certs)
  - classify_cert decision tree: not_brand / legitimate / suspicious
    TLD / recent / older
  - Wildcard cert covered by whitelist
  - Multi-SAN cert with one non-whitelisted entry NOT covered
  - Recency parser handles crt.sh timestamp shape + degraded inputs
  - filter_recent helper
  - Tool wrapper summary shape (high + medium surfaced, low counted
    only)
  - Frozen contracts
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import pytest

from kryon.brand.ct_monitor import (
    DEFAULT_MAX_CERTS,
    SUSPICIOUS_TLDS,
    CTCertificate,
    CTQueryResult,
    CTRiskAssessment,
    _matches_brand,
    _matches_legitimate,
    _matches_recent,
    _matches_suspicious_tld,
    _parse_certificates,
    classify_cert,
    filter_recent,
    query_crtsh,
)

# =====================================================================
# Fixtures
# =====================================================================


def _now_iso(offset_days: int = 0) -> str:
    """Build a crt.sh-shaped ISO timestamp `offset_days` ago."""
    t = datetime.now(timezone.utc) - timedelta(days=offset_days)
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def _cert(
    *,
    cn: str = "login.bcp-secure.com",
    sans: tuple[str, ...] = ("login.bcp-secure.com",),
    issuer: str = "C=US, O=Let's Encrypt, CN=R3",
    age_days: int = 1,
    cert_id: str = "12345",
) -> CTCertificate:
    return CTCertificate(
        cert_id=cert_id,
        common_name=cn.lower(),
        san_names=tuple(s.lower() for s in sans),
        issuer_name=issuer,
        not_before=_now_iso(age_days + 30),
        not_after=_now_iso(-60),  # expires in future
        entry_timestamp=_now_iso(age_days),
    )


# =====================================================================
# query_crtsh — fire gate
# =====================================================================


def test_query_dry_run_default_returns_dry_run():
    with patch("kryon.brand.ct_monitor.urlopen") as mock_open:
        result = query_crtsh("bcp", fire=False)
    assert result.verdict == "dry_run"
    assert result.certificates == ()
    mock_open.assert_not_called()


def test_query_fire_without_env_stays_dry_run(monkeypatch):
    monkeypatch.delenv("KRYON_BRAND_FIRE", raising=False)
    with patch("kryon.brand.ct_monitor.urlopen") as mock_open:
        result = query_crtsh("bcp", fire=True)
    assert result.verdict == "dry_run"
    mock_open.assert_not_called()


def test_query_empty_keyword_returns_error():
    """Defensive: empty keyword would crt.sh-search for '%%' and
    return everything. Refuse early."""
    result = query_crtsh("", fire=False)
    assert result.verdict == "error"
    assert result.error and "empty" in result.error


# =====================================================================
# query_crtsh — live fire (mocked)
# =====================================================================


class _FakeResp:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, cap):
        return self._body[:cap]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _crtsh_payload() -> bytes:
    """Realistic crt.sh JSON shape."""
    return json.dumps(
        [
            {
                "id": "1234567890",
                "common_name": "login.bcp-secure.com",
                "name_value": "login.bcp-secure.com\nwww.bcp-secure.com",
                "issuer_name": "C=US, O=Let's Encrypt",
                "not_before": _now_iso(31),
                "not_after": _now_iso(-60),
                "entry_timestamp": _now_iso(1),
                "serial_number": "0123abcd",
            },
            {
                "id": "987654321",
                "common_name": "bcp.com.py",
                "name_value": "bcp.com.py\n*.bcp.com.py",
                "issuer_name": "C=US, O=DigiCert",
                "not_before": _now_iso(60),
                "not_after": _now_iso(-300),
                "entry_timestamp": _now_iso(45),
                "serial_number": "0123abce",
            },
        ]
    ).encode("utf-8")


def test_query_parses_crtsh_payload(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    # Reset rate limiter so the test doesn't sleep.
    monkeypatch.setattr("kryon.brand.ct_monitor._last_query_at", 0.0)
    monkeypatch.setattr("kryon.brand.ct_monitor.time.sleep", lambda _: None)
    resp = _FakeResp(200, _crtsh_payload())
    with patch("kryon.brand.ct_monitor.urlopen", return_value=resp):
        result = query_crtsh("bcp", fire=True)
    assert result.verdict == "ok"
    assert len(result.certificates) == 2
    cns = {c.common_name for c in result.certificates}
    assert "login.bcp-secure.com" in cns
    assert "bcp.com.py" in cns


def test_query_sorts_by_entry_timestamp_desc(monkeypatch):
    """Most recent first so the operator sees fresh phishing infra at
    the top of the report."""
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    monkeypatch.setattr("kryon.brand.ct_monitor._last_query_at", 0.0)
    monkeypatch.setattr("kryon.brand.ct_monitor.time.sleep", lambda _: None)
    resp = _FakeResp(200, _crtsh_payload())
    with patch("kryon.brand.ct_monitor.urlopen", return_value=resp):
        result = query_crtsh("bcp", fire=True)
    # Fixture has 1-day-old cert first vs 45-day-old cert second; the
    # newer one (1 day) should appear first after sort.
    assert result.certificates[0].cert_id == "1234567890"


def test_query_honors_max_certs_cap(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    monkeypatch.setattr("kryon.brand.ct_monitor._last_query_at", 0.0)
    monkeypatch.setattr("kryon.brand.ct_monitor.time.sleep", lambda _: None)
    # Build a 10-cert payload.
    rows = [
        {
            "id": str(i),
            "common_name": f"cert{i}.bcp.example",
            "name_value": f"cert{i}.bcp.example",
            "issuer_name": "x",
            "not_before": "",
            "not_after": "",
            "entry_timestamp": _now_iso(i),
            "serial_number": "",
        }
        for i in range(10)
    ]
    resp = _FakeResp(200, json.dumps(rows).encode())
    with patch("kryon.brand.ct_monitor.urlopen", return_value=resp):
        result = query_crtsh("bcp", fire=True, max_certs=3)
    assert len(result.certificates) == 3


def test_query_http_429_returns_rate_limited(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    monkeypatch.setattr("kryon.brand.ct_monitor._last_query_at", 0.0)
    monkeypatch.setattr("kryon.brand.ct_monitor.time.sleep", lambda _: None)
    from urllib.error import HTTPError

    err = HTTPError("http://crt.sh", 429, "Too Many Requests", {}, None)
    with patch("kryon.brand.ct_monitor.urlopen", side_effect=err):
        result = query_crtsh("bcp", fire=True)
    assert result.verdict == "rate_limited"


def test_query_http_500_returns_error(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    monkeypatch.setattr("kryon.brand.ct_monitor._last_query_at", 0.0)
    monkeypatch.setattr("kryon.brand.ct_monitor.time.sleep", lambda _: None)
    from urllib.error import HTTPError

    err = HTTPError("http://crt.sh", 500, "Internal Error", {}, None)
    with patch("kryon.brand.ct_monitor.urlopen", side_effect=err):
        result = query_crtsh("bcp", fire=True)
    assert result.verdict == "error"
    assert "500" in (result.error or "")


def test_query_network_error_returns_error(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    monkeypatch.setattr("kryon.brand.ct_monitor._last_query_at", 0.0)
    monkeypatch.setattr("kryon.brand.ct_monitor.time.sleep", lambda _: None)
    from urllib.error import URLError

    with patch("kryon.brand.ct_monitor.urlopen", side_effect=URLError("dns")):
        result = query_crtsh("bcp", fire=True)
    assert result.verdict == "error"
    assert "URLError" in (result.error or "")


def test_query_invalid_json_returns_error(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    monkeypatch.setattr("kryon.brand.ct_monitor._last_query_at", 0.0)
    monkeypatch.setattr("kryon.brand.ct_monitor.time.sleep", lambda _: None)
    resp = _FakeResp(200, b"not json")
    with patch("kryon.brand.ct_monitor.urlopen", return_value=resp):
        result = query_crtsh("bcp", fire=True)
    assert result.verdict == "error"
    assert "invalid JSON" in (result.error or "")


# =====================================================================
# Parser — _parse_certificates
# =====================================================================


def test_parser_handles_non_list_payload():
    assert _parse_certificates({"not": "a list"}) == ()


def test_parser_handles_missing_fields():
    """A row with only an id must still produce a valid cert (with
    empty strings everywhere else)."""
    certs = _parse_certificates([{"id": "x"}])
    assert len(certs) == 1
    assert certs[0].cert_id == "x"
    assert certs[0].common_name == ""
    assert certs[0].san_names == ()


def test_parser_splits_newline_separated_sans():
    certs = _parse_certificates(
        [
            {
                "id": "1",
                "common_name": "Foo.Example.com",
                "name_value": "foo.example.com\nbar.example.com\nfoo.example.com",  # duped
            }
        ]
    )
    sans = certs[0].san_names
    # Dedup applied, sorted.
    assert sans == ("bar.example.com", "foo.example.com")


def test_parser_lowercases_common_name_and_sans():
    """Normalization at parse time makes downstream comparisons
    cheap — every domain comparator can assume lower-case."""
    certs = _parse_certificates([{"id": "1", "common_name": "LOGIN.BCP.COM.PY", "name_value": "LOGIN.BCP.COM.PY"}])
    assert certs[0].common_name == "login.bcp.com.py"
    assert certs[0].san_names == ("login.bcp.com.py",)


# =====================================================================
# _matches_brand
# =====================================================================


def test_matches_brand_on_common_name():
    cert = _cert(cn="login.bcp-secure.com")
    assert _matches_brand(cert, "bcp") is True


def test_matches_brand_on_san():
    cert = _cert(cn="example.com", sans=("example.com", "login.bcp-secure.com"))
    assert _matches_brand(cert, "bcp") is True


def test_matches_brand_negative():
    cert = _cert(cn="example.com", sans=("example.com",))
    assert _matches_brand(cert, "bcp") is False


def test_matches_brand_case_insensitive():
    cert = _cert(cn="LOGIN.BCP-SECURE.COM")
    assert _matches_brand(cert, "BCP") is True


# =====================================================================
# _matches_legitimate
# =====================================================================


def test_legitimate_when_all_identifiers_covered():
    cert = _cert(cn="bcp.com.py", sans=("bcp.com.py", "www.bcp.com.py"))
    assert _matches_legitimate(cert, ("bcp.com.py",)) is True


def test_legitimate_wildcard_treated_as_subdomain_coverage():
    """A *.bcp.com.py wildcard is legitimate if bcp.com.py is in the
    whitelist."""
    cert = _cert(cn="*.bcp.com.py", sans=("*.bcp.com.py", "bcp.com.py"))
    assert _matches_legitimate(cert, ("bcp.com.py",)) is True


def test_legitimate_partial_coverage_is_NOT_legitimate():
    """Cert covering both a legitimate AND an unknown domain is NOT
    legitimate — that's how attackers smuggle phishing surface."""
    cert = _cert(
        cn="bcp.com.py",
        sans=("bcp.com.py", "login-bcp-secure.com"),
    )
    assert _matches_legitimate(cert, ("bcp.com.py",)) is False


def test_legitimate_empty_whitelist_returns_false():
    """No whitelist → can't assess → not legitimate. Caller falls
    back to the brand+recency path."""
    cert = _cert(cn="bcp.com.py")
    assert _matches_legitimate(cert, ()) is False


def test_legitimate_subdomain_coverage():
    """app.bcp.com.py is covered when bcp.com.py is whitelisted."""
    cert = _cert(cn="app.bcp.com.py", sans=("app.bcp.com.py",))
    assert _matches_legitimate(cert, ("bcp.com.py",)) is True


# =====================================================================
# _matches_suspicious_tld
# =====================================================================


def test_suspicious_tld_lit_when_cn_uses_one():
    cert = _cert(cn="bcp-login.click")
    assert _matches_suspicious_tld(cert) is True


def test_suspicious_tld_lit_when_any_san_uses_one():
    cert = _cert(
        cn="example.com",
        sans=("example.com", "bcp-secure.top"),
    )
    assert _matches_suspicious_tld(cert) is True


def test_normal_tld_not_suspicious():
    cert = _cert(cn="bcp.com.py", sans=("bcp.com.py",))
    assert _matches_suspicious_tld(cert) is False


def test_suspicious_tlds_includes_known_abuse_tlds():
    """Pin the set — if someone removes .tk / .ml / .xyz the catch
    rate drops without a corresponding test red."""
    for tld in ("tk", "ml", "ga", "xyz", "top", "click"):
        assert tld in SUSPICIOUS_TLDS, f"{tld} missing from SUSPICIOUS_TLDS"


# =====================================================================
# _matches_recent
# =====================================================================


def test_recent_matches_within_window():
    cert = _cert(age_days=5)
    assert _matches_recent(cert, max_age_days=30) is True


def test_recent_excludes_older_than_window():
    cert = _cert(age_days=45)
    assert _matches_recent(cert, max_age_days=30) is False


def test_recent_handles_malformed_timestamp():
    cert = CTCertificate(
        cert_id="x",
        common_name="x",
        san_names=(),
        issuer_name="",
        not_before="",
        not_after="",
        entry_timestamp="not-a-date",
    )
    # Malformed → False (under-flag rather than over-flag).
    assert _matches_recent(cert, max_age_days=30) is False


def test_recent_handles_subsecond_fraction():
    """crt.sh sometimes returns '2026-05-10T12:00:00.123' — the
    parser must strip the sub-second fraction or Python's fromisoformat
    fails on older Pythons. Our parser strips it explicitly."""
    iso_with_fraction = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.456")
    cert = CTCertificate(
        cert_id="x",
        common_name="x",
        san_names=(),
        issuer_name="",
        not_before="",
        not_after="",
        entry_timestamp=iso_with_fraction,
    )
    assert _matches_recent(cert, max_age_days=7) is True


# =====================================================================
# classify_cert — decision tree
# =====================================================================


def test_classify_not_brand_is_low():
    cert = _cert(cn="example.com", sans=("example.com",))
    assessment = classify_cert(cert, brand_keyword="bcp")
    assert assessment.risk == "low"
    assert not assessment.matched_brand


def test_classify_legitimate_is_low():
    cert = _cert(cn="bcp.com.py", sans=("bcp.com.py",))
    assessment = classify_cert(cert, brand_keyword="bcp", legitimate_domains=("bcp.com.py",))
    assert assessment.risk == "low"
    assert assessment.matched_legitimate is True


def test_classify_brand_plus_suspicious_tld_is_high():
    cert = _cert(cn="bcp-login.click", age_days=200)  # age irrelevant
    assessment = classify_cert(cert, brand_keyword="bcp")
    assert assessment.risk == "high"
    assert assessment.matched_suspicious_tld is True


def test_classify_brand_plus_recent_is_high():
    cert = _cert(cn="bcp-secure-banking.com", age_days=1)
    assessment = classify_cert(cert, brand_keyword="bcp", legitimate_domains=("bcp.com.py",), recency_days=30)
    assert assessment.risk == "high"
    assert assessment.matched_recent is True


def test_classify_brand_older_is_medium():
    cert = _cert(cn="bcp-something.com", age_days=200)
    assessment = classify_cert(cert, brand_keyword="bcp", legitimate_domains=("bcp.com.py",), recency_days=30)
    assert assessment.risk == "medium"


def test_classify_legitimate_overrides_suspicious_recency_check():
    """A cert that IS legitimate (covered by whitelist) classifies
    low even if it's also recent — banks issue new certs all the
    time."""
    cert = _cert(cn="bcp.com.py", sans=("bcp.com.py",), age_days=1)
    assessment = classify_cert(cert, brand_keyword="bcp", legitimate_domains=("bcp.com.py",))
    assert assessment.risk == "low"


# =====================================================================
# filter_recent
# =====================================================================


def test_filter_recent_keeps_only_within_window():
    certs = [_cert(cert_id=str(i), age_days=i * 3) for i in range(5)]
    # ages: 0, 3, 6, 9, 12 days
    recent = filter_recent(certs, max_age_days=7)
    assert {c.cert_id for c in recent} == {"0", "1", "2"}  # ≤ 6 days


def test_filter_recent_empty_input():
    assert filter_recent([]) == ()


# =====================================================================
# Tool wrapper summary
# =====================================================================


def test_tool_summary_dry_run_returns_minimal_shape():
    from kryon.brand.ct_monitor_tool import _result_to_summary

    result = CTQueryResult(keyword="bcp", verdict="dry_run", notes="x")
    summary = _result_to_summary(result, "bcp", "", 30)
    assert summary["verdict"] == "dry_run"
    assert summary["certificate_count"] == 0
    assert summary["high_risk"] == []


def test_tool_summary_surfaces_only_high_and_medium():
    """Low-risk certs counted in by_risk but not enumerated — keeps
    the agent's context window clean."""
    from kryon.brand.ct_monitor_tool import _result_to_summary

    high = _cert(cn="bcp-login.click", sans=("bcp-login.click",), age_days=2)
    medium = _cert(cn="bcp-old-redirect.com", sans=("bcp-old-redirect.com",), age_days=200)
    low = _cert(cn="bcp.com.py", sans=("bcp.com.py",), age_days=1)
    result = CTQueryResult(
        keyword="bcp",
        verdict="ok",
        certificates=(high, medium, low),
    )
    summary = _result_to_summary(result, "bcp", "bcp.com.py", 30)
    assert summary["by_risk"].get("high", 0) >= 1
    assert summary["by_risk"].get("medium", 0) >= 1
    assert summary["by_risk"].get("low", 0) >= 1
    # Only high + medium enumerated.
    enumerated_cns = {x["common_name"] for x in summary["high_risk"]} | {
        x["common_name"] for x in summary["medium_risk"]
    }
    assert "bcp.com.py" not in enumerated_cns


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    cert = _cert()
    with pytest.raises(FrozenInstanceError):
        cert.common_name = "x"  # type: ignore[misc]

    result = CTQueryResult(keyword="bcp", verdict="dry_run")
    with pytest.raises(FrozenInstanceError):
        result.verdict = "ok"  # type: ignore[misc]

    assessment = CTRiskAssessment(
        cert=cert,
        risk="high",
        matched_brand=True,
        matched_legitimate=False,
        matched_suspicious_tld=False,
        matched_recent=True,
        reason="",
    )
    with pytest.raises(FrozenInstanceError):
        assessment.risk = "low"  # type: ignore[misc]
