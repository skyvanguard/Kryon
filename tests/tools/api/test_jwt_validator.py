"""F87.5 — TDD contract for the JWT validator.

Coverage:
  - parse_jwt: valid 3-segment token; rejects 1/2/4 segments;
    rejects empty; rejects non-JSON header/payload; rejects
    non-dict header/payload; base64url with missing padding works.
  - Algorithm checks: alg=none / missing alg / unknown alg / HMAC
    with pubkey (key confusion) / explicit algorithm mismatch.
  - Temporal claims: missing exp / expired exp / future iat /
    future nbf / leeway tolerance.
  - Identity claims: missing aud / aud mismatch (string + list
    forms) / missing iss / iss mismatch / missing sub.
  - Header smell tests: kid traversal patterns (8 variants), jku
    without whitelist, jku outside whitelist, jku in whitelist OK,
    x5u same path, typ unusual.
  - Banca-safety: JWTAnalysis does NOT carry the raw token in its
    serialization surface (only finding metadata).
  - Frozen contracts.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from kryon.tools.api.jwt_validator import (
    KNOWN_SIGNATURE_ALGS,
    JWTAnalysis,
    JWTFinding,
    JWTParseError,
    JWTToken,
    _base64url_decode,
    analyze_jwt,
    parse_jwt,
)


# =====================================================================
# Helpers
# =====================================================================


def _b64url(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _build_token(
    header: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    *,
    signature: str = "fakesig",
) -> str:
    """Build a JWT-shaped string for testing. Signature isn't
    cryptographically meaningful — the validator doesn't verify."""
    h = _b64url(header or {"alg": "HS256", "typ": "JWT"})
    p = _b64url(payload or {"sub": "u"})
    return f"{h}.{p}.{signature}"


def _now_ts(offset_seconds: int = 0) -> int:
    return int(datetime.now(timezone.utc).timestamp() + offset_seconds)


# =====================================================================
# parse_jwt
# =====================================================================


def test_parse_valid_token():
    token = _build_token(
        header={"alg": "RS256", "typ": "JWT"},
        payload={"sub": "user-1", "iss": "https://auth.bank.com"},
    )
    parsed = parse_jwt(token)
    assert parsed.alg == "RS256"
    assert parsed.payload["sub"] == "user-1"


def test_parse_rejects_empty_input():
    with pytest.raises(JWTParseError):
        parse_jwt("")
    with pytest.raises(JWTParseError):
        parse_jwt("   ")


@pytest.mark.parametrize("segments", [1, 2, 4, 5])
def test_parse_rejects_wrong_segment_count(segments):
    bad = ".".join("x" * 4 for _ in range(segments))
    with pytest.raises(JWTParseError) as exc:
        parse_jwt(bad)
    assert "3 dot-separated" in str(exc.value) or "segments" in str(exc.value)


def test_parse_rejects_non_json_header():
    bad_header = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
    good_payload = _b64url({"sub": "x"})
    with pytest.raises(JWTParseError):
        parse_jwt(f"{bad_header}.{good_payload}.sig")


def test_parse_rejects_non_dict_payload():
    """JSON that decodes but isn't an object (a list, scalar) is
    not a valid JWT per RFC 7519."""
    bad_payload = base64.urlsafe_b64encode(b'["array"]').rstrip(b"=").decode()
    good_header = _b64url({"alg": "HS256"})
    with pytest.raises(JWTParseError):
        parse_jwt(f"{good_header}.{bad_payload}.sig")


def test_parse_handles_missing_padding():
    """base64url omits padding; the decoder must put it back."""
    # JSON `{"a":1}` → b'{"a":1}' → b64url 'eyJhIjoxfQ' (no padding)
    no_pad = "eyJhIjoxfQ"
    decoded = _base64url_decode(no_pad)
    assert decoded == b'{"a":1}'


def test_parse_token_object_alg_property():
    """The JWTToken.alg accessor returns empty string when missing."""
    token = _build_token(header={"typ": "JWT"})  # no alg
    parsed = parse_jwt(token)
    assert parsed.alg == ""


# =====================================================================
# Algorithm checks
# =====================================================================


def test_alg_none_is_critical():
    token = _build_token(header={"alg": "none"})
    analysis = analyze_jwt(token)
    ids = {f.finding_id for f in analysis.findings}
    assert "JWT-002" in ids
    none_findings = [f for f in analysis.findings if f.finding_id == "JWT-002"]
    assert none_findings[0].severity == "CRITICAL"


def test_alg_none_case_insensitive():
    """Accept 'None' / 'NONE' / 'NoNe' as the same attack."""
    for variant in ("None", "NONE", "NoNe"):
        token = _build_token(header={"alg": variant})
        analysis = analyze_jwt(token)
        assert any(f.finding_id == "JWT-002" for f in analysis.findings)


def test_missing_alg_is_critical():
    token = _build_token(header={"typ": "JWT"})
    analysis = analyze_jwt(token)
    ids = {f.finding_id for f in analysis.findings}
    assert "JWT-001" in ids


def test_unknown_alg_is_high():
    token = _build_token(header={"alg": "MyCustomCipher"})
    analysis = analyze_jwt(token)
    ids = {f.finding_id for f in analysis.findings}
    assert "JWT-003" in ids


def test_hmac_with_pubkey_is_critical():
    """When the verifier holds the issuer's public key, accepting an
    HS256 token is a key-confusion attack."""
    token = _build_token(header={"alg": "HS256"})
    analysis = analyze_jwt(token, allow_hmac_with_pubkey=True)
    ids = {f.finding_id for f in analysis.findings}
    assert "JWT-004" in ids


def test_hmac_alone_is_not_flagged_when_pubkey_flag_false():
    """The default (no pubkey-in-scope) means HMAC alone is fine —
    the verifier presumably has the shared secret."""
    token = _build_token(header={"alg": "HS256"})
    analysis = analyze_jwt(token)
    assert not any(f.finding_id == "JWT-004" for f in analysis.findings)


def test_explicit_alg_mismatch_fires_jwt_005():
    token = _build_token(header={"alg": "RS256"})
    analysis = analyze_jwt(token, expected_alg="ES256")
    ids = {f.finding_id for f in analysis.findings}
    assert "JWT-005" in ids


def test_known_signature_algs_set_is_comprehensive():
    """Pin the set — silent removal would weaken the unknown-alg
    detector."""
    for required in ("HS256", "RS256", "ES256", "PS256", "EdDSA"):
        assert required in KNOWN_SIGNATURE_ALGS


# =====================================================================
# Temporal claims
# =====================================================================


def test_missing_exp_is_high():
    token = _build_token(payload={"sub": "u", "iss": "x", "aud": "x"})
    analysis = analyze_jwt(token)
    assert any(f.finding_id == "JWT-010" for f in analysis.findings)


def test_expired_exp_is_medium():
    """A token already expired — verifiers should already reject;
    we surface as MEDIUM informational so the auditor sees it."""
    token = _build_token(payload={"sub": "u", "exp": _now_ts(-3600)})
    analysis = analyze_jwt(token)
    expired = [f for f in analysis.findings if f.finding_id == "JWT-011"]
    assert expired and expired[0].severity == "MEDIUM"


def test_future_iat_is_high():
    """Issued-at in the future signals forgery or major clock skew."""
    token = _build_token(payload={"sub": "u", "exp": _now_ts(3600), "iat": _now_ts(7200)})
    analysis = analyze_jwt(token)
    assert any(f.finding_id == "JWT-012" for f in analysis.findings)


def test_future_nbf_is_medium():
    token = _build_token(payload={"sub": "u", "exp": _now_ts(3600), "nbf": _now_ts(7200)})
    analysis = analyze_jwt(token)
    assert any(f.finding_id == "JWT-013" for f in analysis.findings)


def test_temporal_leeway_tolerated():
    """A token 30s old shouldn't trigger future-iat with default
    60s leeway."""
    token = _build_token(payload={"sub": "u", "exp": _now_ts(3600), "iat": _now_ts(30)})
    analysis = analyze_jwt(token, leeway_seconds=60)
    assert not any(f.finding_id == "JWT-012" for f in analysis.findings)


# =====================================================================
# Identity claims
# =====================================================================


def test_missing_aud_is_high():
    token = _build_token(payload={"sub": "u", "exp": _now_ts(3600), "iss": "x"})
    analysis = analyze_jwt(token)
    assert any(f.finding_id == "JWT-020" for f in analysis.findings)


def test_aud_string_mismatch_fires_jwt_021():
    token = _build_token(payload={"sub": "u", "exp": _now_ts(3600), "iss": "x", "aud": "other-svc"})
    analysis = analyze_jwt(token, expected_audience="my-svc")
    assert any(f.finding_id == "JWT-021" for f in analysis.findings)


def test_aud_list_form_accepted():
    """RFC 7519 §4.1.3: aud may be a string OR a list of strings."""
    token = _build_token(
        payload={"sub": "u", "exp": _now_ts(3600), "iss": "x", "aud": ["other", "my-svc"]}
    )
    analysis = analyze_jwt(token, expected_audience="my-svc")
    # aud list contains expected_audience → JWT-021 should NOT fire.
    assert not any(f.finding_id == "JWT-021" for f in analysis.findings)


def test_missing_iss_is_high():
    token = _build_token(payload={"sub": "u", "exp": _now_ts(3600)})
    analysis = analyze_jwt(token)
    assert any(f.finding_id == "JWT-022" for f in analysis.findings)


def test_iss_mismatch_fires_jwt_023():
    token = _build_token(payload={"sub": "u", "exp": _now_ts(3600), "iss": "rogue-idp"})
    analysis = analyze_jwt(token, expected_issuer="https://auth.bank.example")
    assert any(f.finding_id == "JWT-023" for f in analysis.findings)


def test_missing_sub_is_medium():
    token = _build_token(payload={"exp": _now_ts(3600), "iss": "x", "aud": "y"})
    analysis = analyze_jwt(token)
    sub_findings = [f for f in analysis.findings if f.finding_id == "JWT-024"]
    assert sub_findings and sub_findings[0].severity == "MEDIUM"


# =====================================================================
# kid traversal
# =====================================================================


@pytest.mark.parametrize(
    "kid",
    [
        "../keys/admin",
        "..\\windows\\config",
        "%2e%2e/keys",
        "/etc/passwd",
        "/etc/shadow",
        "C:\\Windows\\System32",
        "../../config/key",
        "key%2fpath",
    ],
)
def test_kid_traversal_pattern_fires_critical(kid):
    token = _build_token(header={"alg": "RS256", "kid": kid})
    analysis = analyze_jwt(token)
    traversal = [f for f in analysis.findings if f.finding_id == "JWT-030"]
    assert traversal, f"kid {kid!r} should fire JWT-030"
    assert traversal[0].severity == "CRITICAL"


def test_kid_normal_value_does_not_fire():
    token = _build_token(header={"alg": "RS256", "kid": "key-rotation-2026-q1"})
    analysis = analyze_jwt(token)
    assert not any(f.finding_id == "JWT-030" for f in analysis.findings)


def test_kid_missing_does_not_fire():
    token = _build_token(header={"alg": "RS256"})
    analysis = analyze_jwt(token)
    assert not any(f.finding_id == "JWT-030" for f in analysis.findings)


# =====================================================================
# jku / x5u
# =====================================================================


def test_jku_without_whitelist_is_high():
    token = _build_token(header={"alg": "RS256", "jku": "https://attacker.example/jwks.json"})
    analysis = analyze_jwt(token)
    assert any(f.finding_id == "JWT-040" for f in analysis.findings)


def test_jku_outside_whitelist_is_high():
    token = _build_token(header={"alg": "RS256", "jku": "https://attacker.example/jwks.json"})
    analysis = analyze_jwt(
        token, trusted_jku_hosts=("auth.bank.example",)
    )
    assert any(f.finding_id == "JWT-041" for f in analysis.findings)


def test_jku_in_whitelist_does_not_fire():
    token = _build_token(header={"alg": "RS256", "jku": "https://auth.bank.example/jwks.json"})
    analysis = analyze_jwt(
        token, trusted_jku_hosts=("auth.bank.example",)
    )
    assert not any(f.finding_id in ("JWT-040", "JWT-041") for f in analysis.findings)


def test_x5u_treated_same_as_jku():
    token = _build_token(header={"alg": "RS256", "x5u": "https://attacker.example/cert.pem"})
    analysis = analyze_jwt(token)
    assert any(f.finding_id == "JWT-040" for f in analysis.findings)


# =====================================================================
# typ
# =====================================================================


def test_typ_jwt_does_not_fire():
    token = _build_token(header={"alg": "HS256", "typ": "JWT"})
    analysis = analyze_jwt(token)
    assert not any(f.finding_id == "JWT-050" for f in analysis.findings)


def test_typ_at_jwt_does_not_fire():
    """RFC 9068 'AT+JWT' (access token) is a legitimate variant."""
    token = _build_token(header={"alg": "HS256", "typ": "AT+JWT"})
    analysis = analyze_jwt(token)
    assert not any(f.finding_id == "JWT-050" for f in analysis.findings)


def test_typ_unusual_value_fires_medium():
    token = _build_token(header={"alg": "HS256", "typ": "MyCustomType"})
    analysis = analyze_jwt(token)
    typ_findings = [f for f in analysis.findings if f.finding_id == "JWT-050"]
    assert typ_findings
    assert typ_findings[0].severity == "MEDIUM"


# =====================================================================
# Parse failure
# =====================================================================


def test_unparseable_token_returns_critical_jwt_000():
    analysis = analyze_jwt("not-a-jwt")
    assert analysis.parsed is False
    assert len(analysis.findings) == 1
    assert analysis.findings[0].finding_id == "JWT-000"
    assert analysis.findings[0].severity == "CRITICAL"


# =====================================================================
# Banca-safety: analysis doesn't leak raw claims
# =====================================================================


def test_analysis_does_not_carry_sub_claim_value():
    """Banca-privacy: the JWTAnalysis surfaces only finding metadata
    (id, severity, title, detail, remediation). The token's `sub`
    value (typically a user id / email / cedula) should NOT appear
    in the serializable output beyond claims_present (key list)."""
    sensitive_sub = "cedula-1234567-9"
    token = _build_token(
        payload={"sub": sensitive_sub, "exp": _now_ts(3600), "iss": "x", "aud": "y"}
    )
    analysis = analyze_jwt(token)
    # claims_present is the list of KEYS, not values.
    assert sensitive_sub not in analysis.claims_present
    # The sub VALUE shouldn't leak through any finding's detail
    # string either. Building all detail strings + searching is
    # cheap and definitive.
    rendered = " ".join(f.detail + " " + f.title for f in analysis.findings)
    assert sensitive_sub not in rendered


def test_claims_present_reports_keys_only():
    token = _build_token(
        payload={"sub": "x", "exp": _now_ts(3600), "iss": "y", "aud": "z", "email": "u@x"}
    )
    analysis = analyze_jwt(token)
    assert set(analysis.claims_present) == {"sub", "exp", "iss", "aud", "email"}


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_wrapper_dict_shape():
    from kryon.tools.api.jwt_tool import _analysis_to_dict

    token = _build_token(header={"alg": "none"})
    analysis = analyze_jwt(token)
    payload = _analysis_to_dict(analysis)
    assert payload["parsed"] is True
    assert payload["alg_observed"] == "none"
    assert "JWT-002" in {f["id"] for f in payload["findings"]}
    # by_severity bucket counts.
    assert payload["by_severity"]["CRITICAL"] >= 1
    # JSON-serializable.
    json.dumps(payload)


def test_tool_wrapper_handles_parse_failure():
    from kryon.tools.api.jwt_tool import _analysis_to_dict

    analysis = analyze_jwt("not.a.jwt")
    payload = _analysis_to_dict(analysis)
    assert payload["parsed"] is False
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["id"] == "JWT-000"


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    finding = JWTFinding(
        finding_id="JWT-001",
        severity="CRITICAL",
        title="x",
        detail="x",
        remediation="x",
    )
    with pytest.raises(FrozenInstanceError):
        finding.severity = "LOW"  # type: ignore[misc]

    analysis = JWTAnalysis(parsed=True)
    with pytest.raises(FrozenInstanceError):
        analysis.parsed = False  # type: ignore[misc]
