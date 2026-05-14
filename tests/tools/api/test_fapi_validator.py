"""F87.4 — TDD contract for the FAPI 1.0 Advanced validator.

Fixtures:
  _compliant_discovery() — a hand-built doc that passes every check.
                            Used as a baseline; per-check tests mutate
                            ONE field and assert exactly that check
                            flips to fail.
  _bcp_paraguay_discovery() — realistic LATAM bank shape (BCP
                              Paraguay-like) that fails several checks
                              — pins the report against the real
                              non-compliant pattern we see in the wild.

Coverage groups:
  - parse_discovery: defensive nulls, type coercion, raw preserved.
  - Each check in isolation (10 checks).
  - Aggregate report: compliance gate (CRITICAL+HIGH must pass).
  - Discovery fetcher: double-gate (dry-run default).
  - URL normalization (issuer with / without trailing slash,
    issuer already pointing at .well-known).
  - Tool wrapper from_url + from_json modes.
  - Frozen contracts.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from kryon.tools.api.fapi_validator import (
    ALL_FAPI_CHECKS,
    DISCOVERY_RESPONSE_CAP_BYTES,
    FAPICheckResult,
    FAPIComplianceReport,
    FAPIDiscovery,
    _well_known_url,
    fetch_discovery_document,
    parse_discovery,
    validate_fapi_advanced,
)

# =====================================================================
# Fixtures
# =====================================================================


def _compliant_discovery() -> dict[str, Any]:
    """Discovery doc that passes every FAPI Advanced check."""
    return {
        "issuer": "https://auth.bank.example",
        "authorization_endpoint": "https://auth.bank.example/oauth2/authorize",
        "token_endpoint": "https://auth.bank.example/oauth2/token",
        "pushed_authorization_request_endpoint": "https://auth.bank.example/oauth2/par",
        "jwks_uri": "https://auth.bank.example/jwks.json",
        "response_types_supported": ["code", "code id_token"],
        "response_modes_supported": ["query", "fragment", "form_post", "jwt", "query.jwt"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "request_object_signing_alg_values_supported": ["PS256", "ES256"],
        "id_token_signing_alg_values_supported": ["PS256", "ES256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "tls_client_auth"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "accounts", "payments"],
        "acr_values_supported": ["urn:openbanking:psd2:sca"],
        "amr_values_supported": ["hwk", "phr", "phrh"],
        "tls_client_certificate_bound_access_tokens": True,
        "dpop_signing_alg_values_supported": ["PS256"],
    }


def _bcp_paraguay_discovery() -> dict[str, Any]:
    """Realistic LATAM bank discovery — fails on PAR, JARM, and the
    PSD2 SCA AMR claim. Pins the report against a real non-compliant
    pattern."""
    return {
        "issuer": "https://auth.bcp.com.py",
        "authorization_endpoint": "https://auth.bcp.com.py/oauth2/authorize",
        "token_endpoint": "https://auth.bcp.com.py/oauth2/token",
        # NO par_endpoint declared
        "jwks_uri": "https://auth.bcp.com.py/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "form_post"],  # no JARM
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "request_object_signing_alg_values_supported": ["PS256"],
        "id_token_signing_alg_values_supported": ["PS256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "accounts", "payments"],
        # NO PSD2 SCA acr / amr
        "tls_client_certificate_bound_access_tokens": True,
    }


# =====================================================================
# parse_discovery — defensive parsing
# =====================================================================


def test_parse_discovery_extracts_all_fields():
    d = parse_discovery(_compliant_discovery())
    assert d.issuer == "https://auth.bank.example"
    assert d.par_endpoint == "https://auth.bank.example/oauth2/par"
    assert "PS256" in d.request_object_signing_alg_values
    assert "tls_client_auth" in d.token_endpoint_auth_methods
    assert d.tls_client_certificate_bound_access_tokens is True


def test_parse_discovery_handles_missing_keys():
    d = parse_discovery({"issuer": "x"})
    assert d.issuer == "x"
    assert d.par_endpoint is None
    assert d.response_types_supported == ()
    assert d.tls_client_certificate_bound_access_tokens is False


def test_parse_discovery_coerces_non_list_fields():
    """If a server returns a string where the spec says list, we drop
    the field. Better than crashing or producing garbage tuples."""
    d = parse_discovery({"issuer": "x", "response_types_supported": "not a list"})
    assert d.response_types_supported == ()


def test_parse_discovery_dedupes_preserving_order():
    d = parse_discovery(
        {
            "issuer": "x",
            "response_types_supported": ["code", "code", "code id_token", "code"],
        }
    )
    assert d.response_types_supported == ("code", "code id_token")


def test_parse_discovery_preserves_raw_dict():
    """Curators access weird/exotic fields via .raw — must not be
    stripped."""
    doc = _compliant_discovery()
    doc["custom_bank_field"] = "bcp_marker"
    d = parse_discovery(doc)
    assert d.raw["custom_bank_field"] == "bcp_marker"


def test_parse_discovery_non_dict_returns_empty():
    d = parse_discovery("not a dict")  # type: ignore[arg-type]
    assert d.issuer == ""


# =====================================================================
# Individual checks against a compliant baseline
# =====================================================================


def test_all_checks_pass_on_compliant_doc():
    d = parse_discovery(_compliant_discovery())
    report = validate_fapi_advanced(d)
    assert report.compliant is True
    # Every check is pass except maybe MEDIUM/INFO (which can be warning).
    for r in report.results:
        if r.severity in ("CRITICAL", "HIGH"):
            assert r.status == "pass", f"{r.check_id} unexpectedly failed: {r.actual}"


def test_par_check_fails_when_endpoint_missing():
    doc = _compliant_discovery()
    del doc["pushed_authorization_request_endpoint"]
    report = validate_fapi_advanced(parse_discovery(doc))
    par = next(r for r in report.results if r.check_id == "FAPI-1")
    assert par.status == "fail"
    assert par.severity == "CRITICAL"


def test_request_object_signing_fails_with_rs256_only():
    doc = _compliant_discovery()
    doc["request_object_signing_alg_values_supported"] = ["RS256"]
    report = validate_fapi_advanced(parse_discovery(doc))
    r = next(r for r in report.results if r.check_id == "FAPI-2")
    assert r.status == "fail"
    assert "RS256" in r.actual


def test_id_token_signing_fails_with_hs256():
    doc = _compliant_discovery()
    doc["id_token_signing_alg_values_supported"] = ["HS256"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-3")
    assert r.status == "fail"


def test_client_auth_fails_with_secret_basic():
    doc = _compliant_discovery()
    doc["token_endpoint_auth_methods_supported"] = ["client_secret_basic", "client_secret_post"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-4")
    assert r.status == "fail"


def test_sender_constrained_passes_with_dpop_alone():
    """DPoP is an acceptable alternative to mTLS-bound tokens."""
    doc = _compliant_discovery()
    doc["tls_client_certificate_bound_access_tokens"] = False
    doc["dpop_signing_alg_values_supported"] = ["PS256"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-5")
    assert r.status == "pass"
    assert "DPoP" in r.actual


def test_sender_constrained_fails_with_neither():
    doc = _compliant_discovery()
    doc["tls_client_certificate_bound_access_tokens"] = False
    doc.pop("dpop_signing_alg_values_supported", None)
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-5")
    assert r.status == "fail"


def test_pkce_check_fails_with_plain_only():
    doc = _compliant_discovery()
    doc["code_challenge_methods_supported"] = ["plain"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-6")
    assert r.status == "fail"
    assert r.severity == "HIGH"


def test_implicit_flow_check_fails_when_id_token_alone():
    doc = _compliant_discovery()
    doc["response_types_supported"] = ["code", "id_token"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-7")
    assert r.status == "fail"
    assert "id_token" in r.actual


def test_implicit_flow_check_passes_with_hybrid():
    """`code id_token` is a hybrid flow that DOES include `code` — FAPI
    Advanced actually permits this (vs implicit-only which is banned)."""
    doc = _compliant_discovery()
    doc["response_types_supported"] = ["code", "code id_token"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-7")
    assert r.status == "pass"


def test_jarm_check_warns_when_no_jwt_response_mode():
    doc = _compliant_discovery()
    doc["response_modes_supported"] = ["query", "form_post"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-8")
    assert r.status == "warning"
    assert r.severity == "MEDIUM"


def test_acr_amr_check_fails_with_neither():
    doc = _compliant_discovery()
    doc["acr_values_supported"] = ["urn:mace:incommon:iap:silver"]
    doc["amr_values_supported"] = ["pwd"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-10")
    assert r.status == "fail"
    assert r.severity == "HIGH"


def test_acr_amr_check_passes_with_amr_alone():
    """Either ACR or AMR satisfies — don't require both."""
    doc = _compliant_discovery()
    doc.pop("acr_values_supported", None)
    doc["amr_values_supported"] = ["hwk"]
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-10")
    assert r.status == "pass"


def test_open_banking_scopes_info_check():
    """FAPI-9 is INFO — passes when OB-shaped scopes appear, warns
    otherwise. Never fails the report."""
    doc = _compliant_discovery()
    doc["scopes_supported"] = ["openid"]  # minimal
    r = next(c for c in validate_fapi_advanced(parse_discovery(doc)).results if c.check_id == "FAPI-9")
    assert r.status == "pass"  # openid is in the recognized set
    assert r.severity == "INFO"


# =====================================================================
# Aggregate compliance gate
# =====================================================================


def test_compliance_requires_all_critical_and_high_pass():
    """Removing one CRITICAL check from the compliant baseline must
    flip compliance to False."""
    doc = _compliant_discovery()
    del doc["pushed_authorization_request_endpoint"]
    report = validate_fapi_advanced(parse_discovery(doc))
    assert report.compliant is False


def test_compliance_not_blocked_by_medium_warnings():
    """A doc with all CRITICAL + HIGH passing but FAPI-8 (JARM,
    MEDIUM) warning should still be `compliant=True`."""
    doc = _compliant_discovery()
    doc["response_modes_supported"] = ["query"]  # no JARM
    report = validate_fapi_advanced(parse_discovery(doc))
    fapi8 = next(r for r in report.results if r.check_id == "FAPI-8")
    assert fapi8.status == "warning"
    # Everything CRITICAL+HIGH still passes.
    assert report.compliant is True


def test_report_summary_counts_statuses():
    report = validate_fapi_advanced(parse_discovery(_compliant_discovery()))
    assert report.summary.get("pass", 0) >= 8  # most checks pass
    # Total counts match results length.
    assert sum(report.summary.values()) == len(report.results)


def test_report_includes_all_ten_checks():
    report = validate_fapi_advanced(parse_discovery(_compliant_discovery()))
    check_ids = {r.check_id for r in report.results}
    assert check_ids == {f"FAPI-{i}" for i in range(1, 11)}


# =====================================================================
# Realistic LATAM fixture
# =====================================================================


def test_bcp_paraguay_fails_expected_checks():
    """The realistic LATAM bank fixture pins which checks fail in the
    wild — PAR, JARM, AMR. If the fixture or the validator drifts,
    this catches it."""
    report = validate_fapi_advanced(parse_discovery(_bcp_paraguay_discovery()))
    failures = {r.check_id for r in report.results if r.status == "fail"}
    warnings = {r.check_id for r in report.results if r.status == "warning"}
    assert "FAPI-1" in failures  # PAR missing
    assert "FAPI-10" in failures  # AMR/ACR missing
    assert "FAPI-8" in warnings  # JARM warning
    # Critical checks fail → not compliant.
    assert report.compliant is False


# =====================================================================
# Discovery fetcher — double gate
# =====================================================================


def test_fetch_discovery_dry_run_returns_none(monkeypatch):
    monkeypatch.delenv("KRYON_FAPI_FIRE", raising=False)
    with patch("kryon.tools.api.fapi_validator.urlopen") as mock_open:
        result = fetch_discovery_document("https://auth.bank.example", fire=False)
    assert result is None
    mock_open.assert_not_called()


def test_fetch_discovery_fire_without_env_stays_dry_run(monkeypatch):
    monkeypatch.delenv("KRYON_FAPI_FIRE", raising=False)
    with patch("kryon.tools.api.fapi_validator.urlopen") as mock_open:
        result = fetch_discovery_document("https://auth.bank.example", fire=True)
    assert result is None
    mock_open.assert_not_called()


def test_fetch_discovery_live_fire_returns_parsed_dict(monkeypatch):
    monkeypatch.setenv("KRYON_FAPI_FIRE", "true")

    class _FakeResp:
        def read(self, cap):
            return json.dumps(_compliant_discovery()).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("kryon.tools.api.fapi_validator.urlopen", return_value=_FakeResp()):
        result = fetch_discovery_document("https://auth.bank.example", fire=True)
    assert result is not None
    assert result["issuer"] == "https://auth.bank.example"


def test_fetch_discovery_http_error_returns_none(monkeypatch):
    monkeypatch.setenv("KRYON_FAPI_FIRE", "true")
    from urllib.error import HTTPError

    err = HTTPError("http://x", 404, "not found", {}, None)
    with patch("kryon.tools.api.fapi_validator.urlopen", side_effect=err):
        result = fetch_discovery_document("https://auth.bank.example", fire=True)
    assert result is None


def test_fetch_discovery_invalid_json_returns_none(monkeypatch):
    monkeypatch.setenv("KRYON_FAPI_FIRE", "true")

    class _BadResp:
        def read(self, cap):
            return b"not json"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("kryon.tools.api.fapi_validator.urlopen", return_value=_BadResp()):
        result = fetch_discovery_document("https://auth.bank.example", fire=True)
    assert result is None


# =====================================================================
# URL normalization
# =====================================================================


def test_well_known_url_appends_path():
    assert _well_known_url("https://auth.bank.example") == "https://auth.bank.example/.well-known/openid-configuration"


def test_well_known_url_strips_trailing_slash():
    assert _well_known_url("https://auth.bank.example/") == "https://auth.bank.example/.well-known/openid-configuration"


def test_well_known_url_preserves_existing_path():
    """If caller already passed a full discovery URL, don't double up."""
    url = "https://auth.bank.example/.well-known/openid-configuration"
    assert _well_known_url(url) == url


def test_well_known_url_accepts_oauth_metadata_path():
    """RFC 8414 OAuth metadata path is also acceptable — many banks
    publish discovery at this alternate location."""
    url = "https://auth.bank.example/.well-known/oauth-authorization-server"
    assert _well_known_url(url) == url


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_wrapper_from_json_mode():
    """No HTTP traffic. Inline doc → report dict."""
    from kryon.tools.api.fapi_tool import _report_to_dict

    doc = _compliant_discovery()
    report = validate_fapi_advanced(parse_discovery(doc))
    payload = _report_to_dict(report)
    # Round-trip through json to catch any non-serializable fields.
    blob = json.dumps(payload)
    parsed = json.loads(blob)
    assert parsed["compliant"] is True
    assert parsed["profile"] == "fapi_1_advanced"
    assert len(parsed["checks"]) == 10


def test_tool_wrapper_check_keys_present():
    from kryon.tools.api.fapi_tool import _report_to_dict

    report = validate_fapi_advanced(parse_discovery(_bcp_paraguay_discovery()))
    payload = _report_to_dict(report)
    first = payload["checks"][0]
    expected_keys = {"check_id", "title", "severity", "status", "expected", "actual", "remediation", "rationale"}
    assert set(first.keys()) >= expected_keys


# =====================================================================
# Banca-safety
# =====================================================================


def test_discovery_response_cap_is_1mb():
    assert DISCOVERY_RESPONSE_CAP_BYTES == 1 * 1024 * 1024


def test_all_fapi_checks_constant_lists_ten_entries():
    """If someone adds an 11th check they must update the test
    constant too — pins the report shape."""
    assert len(ALL_FAPI_CHECKS) == 10


# =====================================================================
# Frozen
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    d = parse_discovery(_compliant_discovery())
    with pytest.raises(FrozenInstanceError):
        d.issuer = "x"  # type: ignore[misc]
    r = FAPICheckResult(
        check_id="FAPI-1",
        title="x",
        severity="CRITICAL",
        status="pass",
        expected="",
        actual="",
        remediation="",
        rationale="",
    )
    with pytest.raises(FrozenInstanceError):
        r.status = "fail"  # type: ignore[misc]
