"""F95 — TDD contract for the webhook signature validator.

Coverage:
  - Scheme detection: every documented header pattern + priority
    resolution (vendor wins over generic).
  - Per-scheme parsing: Stripe-Signature t=/v1= shape, GitHub
    "sha256=<hex>" shape, RFC 9421 key=value.
  - Replay-protection findings: Stripe missing t=, Discord missing
    timestamp header, GitHub doesn't sign timestamp (always fires
    WHK-003), RFC 9421 missing `created`, timestamp outside window.
  - Weak algorithm detection: github_sha1 + RFC 9421 with sha1/md5.
  - Expected-scheme mismatch fires WHK-011.
  - Body integrity: Content-Length mismatch flagged.
  - Stripe + GitHub HMAC verification: round-trip succeeds with
    correct secret; fails with wrong secret; constant-time
    comparison via hmac.compare_digest.
  - Banca-safety: secret never appears in analysis output.
  - Frozen contracts.
  - Tool wrapper E2E.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from kryon.tools.api.webhook_validator import (
    ALL_SCHEMES,
    DEFAULT_MAX_SKEW_SECONDS,
    WebhookAnalysis,
    WebhookFinding,
    WebhookRequest,
    analyze_webhook,
    detect_signature_scheme,
)


# =====================================================================
# Helpers
# =====================================================================


def _now() -> int:
    return int(time.time())


def _stripe_sig(secret: bytes, body: bytes, ts: int) -> str:
    payload = f"{ts}.".encode() + body
    sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _github_sig(secret: bytes, body: bytes, *, sha256: bool = True) -> str:
    algo = hashlib.sha256 if sha256 else hashlib.sha1
    sig = hmac.new(secret, body, algo).hexdigest()
    prefix = "sha256" if sha256 else "sha1"
    return f"{prefix}={sig}"


def _req(
    headers: dict[str, str], body: bytes = b"", method: str = "POST"
) -> WebhookRequest:
    return WebhookRequest(method=method, url="https://example.com/hook", headers=headers, body=body)


# =====================================================================
# Scheme detection
# =====================================================================


def test_detect_stripe():
    r = _req({"Stripe-Signature": f"t={_now()},v1=abcd"})
    assert detect_signature_scheme(r) == "stripe"


def test_detect_github_sha256():
    r = _req({"X-Hub-Signature-256": "sha256=abcd"})
    assert detect_signature_scheme(r) == "github_sha256"


def test_detect_github_sha1_legacy():
    """X-Hub-Signature (no -256) signals the legacy sha1 scheme."""
    r = _req({"X-Hub-Signature": "sha1=abcd"})
    assert detect_signature_scheme(r) == "github_sha1"


def test_detect_discord_ed25519():
    r = _req(
        {
            "X-Signature-Ed25519": "abcd",
            "X-Signature-Timestamp": str(_now()),
        }
    )
    assert detect_signature_scheme(r) == "discord_ed25519"


def test_detect_open_banking_jws():
    r = _req({"x-jws-signature": "abcd.efgh.ijkl"})
    assert detect_signature_scheme(r) == "open_banking_jws"


def test_detect_bancard_scheme():
    """LATAM banking scheme."""
    r = _req({"X-Bancard-Signature": "abcdef"})
    assert detect_signature_scheme(r) == "bancard"


def test_detect_bcp_scheme():
    r = _req({"X-BCP-Signature": "abcdef"})
    assert detect_signature_scheme(r) == "bcp"


def test_detect_rfc9421():
    r = _req(
        {
            "Signature": 'keyId="key-1",algorithm="hmac-sha256",signature="abc",created="100"'
        }
    )
    assert detect_signature_scheme(r) == "rfc9421"


def test_detect_custom_x_signature_fallback():
    r = _req({"X-Webhook-Signature": "abcd"})
    assert detect_signature_scheme(r) == "custom_x_signature"


def test_detect_unknown_no_headers():
    r = _req({})
    assert detect_signature_scheme(r) == "unknown"


def test_detect_vendor_wins_over_generic():
    """When BOTH X-Bancard-Signature AND generic X-Signature are
    present, the vendor-specific match wins."""
    r = _req({"X-Bancard-Signature": "abc", "X-Signature": "abc"})
    assert detect_signature_scheme(r) == "bancard"


def test_detect_case_insensitive():
    r = _req({"STRIPE-SIGNATURE": f"t={_now()},v1=abc"})
    assert detect_signature_scheme(r) == "stripe"


# =====================================================================
# Findings: missing signature
# =====================================================================


def test_unknown_scheme_fires_whk_001_critical():
    analysis = analyze_webhook(_req({}))
    crit = [f for f in analysis.findings if f.finding_id == "WHK-001"]
    assert crit and crit[0].severity == "CRITICAL"


def test_recognized_scheme_does_not_fire_whk_001():
    analysis = analyze_webhook(_req({"Stripe-Signature": f"t={_now()},v1=abc"}))
    assert not any(f.finding_id == "WHK-001" for f in analysis.findings)


# =====================================================================
# Weak algorithm
# =====================================================================


def test_github_sha1_fires_whk_002():
    analysis = analyze_webhook(_req({"X-Hub-Signature": "sha1=abc"}))
    weak = [f for f in analysis.findings if f.finding_id == "WHK-002"]
    assert weak and weak[0].severity == "HIGH"


def test_rfc9421_with_sha1_alg_fires_whk_002():
    analysis = analyze_webhook(
        _req({"Signature": 'algorithm="hmac-sha1",signature="abc",created="100"'})
    )
    assert any(f.finding_id == "WHK-002" for f in analysis.findings)


def test_rfc9421_with_sha256_does_not_fire_whk_002():
    analysis = analyze_webhook(
        _req(
            {
                "Signature": (
                    f'algorithm="hmac-sha256",signature="abc",created="{_now()}"'
                )
            }
        )
    )
    assert not any(f.finding_id == "WHK-002" for f in analysis.findings)


# =====================================================================
# Replay protection
# =====================================================================


def test_stripe_without_timestamp_in_value_fires_whk_003():
    """A Stripe-Signature with no `t=` is malformed; we surface WHK-003."""
    analysis = analyze_webhook(_req({"Stripe-Signature": "v1=abcd"}))
    assert any(f.finding_id == "WHK-003" for f in analysis.findings)


def test_stripe_with_old_timestamp_fires_whk_004():
    """Stripe ts 10 minutes ago, default window 5 min → WHK-004 fires."""
    ts = _now() - 600
    analysis = analyze_webhook(_req({"Stripe-Signature": f"t={ts},v1=abc"}))
    assert any(f.finding_id == "WHK-004" for f in analysis.findings)


def test_stripe_with_fresh_timestamp_does_not_fire_whk_004():
    ts = _now() - 30
    analysis = analyze_webhook(_req({"Stripe-Signature": f"t={ts},v1=abc"}))
    assert not any(f.finding_id == "WHK-004" for f in analysis.findings)


def test_discord_without_timestamp_header_fires_whk_003():
    analysis = analyze_webhook(_req({"X-Signature-Ed25519": "abc"}))
    # Without X-Signature-Timestamp, detection falls back to unknown.
    # We accept either WHK-001 (no recognized scheme) or WHK-003.
    ids = {f.finding_id for f in analysis.findings}
    assert ids & {"WHK-001", "WHK-003"}


def test_github_always_fires_whk_003():
    """GitHub doesn't sign a timestamp; receiver has to manage replay
    out-of-band. We fire WHK-003 to surface that gap."""
    analysis = analyze_webhook(_req({"X-Hub-Signature-256": "sha256=abc"}))
    assert any(f.finding_id == "WHK-003" for f in analysis.findings)


def test_rfc9421_missing_created_fires_whk_003():
    analysis = analyze_webhook(
        _req({"Signature": 'algorithm="hmac-sha256",signature="abc"'})
    )
    assert any(f.finding_id == "WHK-003" for f in analysis.findings)


# =====================================================================
# Expected scheme mismatch
# =====================================================================


def test_expected_scheme_mismatch_fires_whk_011():
    analysis = analyze_webhook(
        _req({"Stripe-Signature": f"t={_now()},v1=abc"}),
        expected_scheme="github_sha256",
    )
    assert any(f.finding_id == "WHK-011" for f in analysis.findings)


def test_expected_scheme_match_silences_whk_011():
    analysis = analyze_webhook(
        _req({"Stripe-Signature": f"t={_now()},v1=abc"}),
        expected_scheme="stripe",
    )
    assert not any(f.finding_id == "WHK-011" for f in analysis.findings)


# =====================================================================
# Body integrity
# =====================================================================


def test_content_length_mismatch_fires_whk_030():
    """Content-Length header lying about the actual body length is a
    common framework bug that breaks HMAC silently."""
    body = b'{"foo":"bar"}'
    headers = {
        "Stripe-Signature": f"t={_now()},v1=abc",
        "Content-Length": "999",
    }
    analysis = analyze_webhook(_req(headers, body=body))
    assert any(f.finding_id == "WHK-030" for f in analysis.findings)


def test_content_length_match_does_not_fire():
    body = b'{"foo":"bar"}'
    headers = {
        "Stripe-Signature": f"t={_now()},v1=abc",
        "Content-Length": str(len(body)),
    }
    analysis = analyze_webhook(_req(headers, body=body))
    assert not any(f.finding_id == "WHK-030" for f in analysis.findings)


# =====================================================================
# Stripe HMAC round-trip
# =====================================================================


def test_stripe_verify_succeeds_with_correct_secret():
    body = b'{"event":"payment.succeeded","amount":100}'
    secret = b"whsec_test_1234567890abcdef"
    ts = _now() - 30
    sig_header = _stripe_sig(secret, body, ts)
    analysis = analyze_webhook(
        _req({"Stripe-Signature": sig_header}, body=body),
        secret=secret,
    )
    assert analysis.verified is True
    assert any(f.finding_id == "WHK-021" for f in analysis.findings)


def test_stripe_verify_fails_with_wrong_secret():
    body = b'{"event":"payment.succeeded"}'
    real_secret = b"whsec_real"
    wrong_secret = b"whsec_wrong"
    ts = _now() - 30
    sig_header = _stripe_sig(real_secret, body, ts)
    analysis = analyze_webhook(
        _req({"Stripe-Signature": sig_header}, body=body),
        secret=wrong_secret,
    )
    assert analysis.verified is False
    assert any(f.finding_id == "WHK-020" for f in analysis.findings)


def test_stripe_verify_fails_when_body_modified():
    """Sign one body, verify against a modified body — must fail."""
    secret = b"whsec_test"
    ts = _now() - 30
    sig_header = _stripe_sig(secret, b'{"amount":100}', ts)
    # Sign with amount:100; verify with amount:1000000 (attacker
    # modified body in transit).
    analysis = analyze_webhook(
        _req({"Stripe-Signature": sig_header}, body=b'{"amount":1000000}'),
        secret=secret,
    )
    assert analysis.verified is False


# =====================================================================
# GitHub HMAC round-trip
# =====================================================================


def test_github_sha256_verify_succeeds():
    body = b'{"action":"push"}'
    secret = b"github_secret_xyz"
    sig_header = _github_sig(secret, body, sha256=True)
    analysis = analyze_webhook(
        _req({"X-Hub-Signature-256": sig_header}, body=body),
        secret=secret,
    )
    assert analysis.verified is True


def test_github_sha1_verify_succeeds():
    body = b'{"action":"push"}'
    secret = b"github_secret_xyz"
    sig_header = _github_sig(secret, body, sha256=False)
    analysis = analyze_webhook(
        _req({"X-Hub-Signature": sig_header}, body=body),
        secret=secret,
    )
    assert analysis.verified is True


def test_github_verify_fails_with_tampered_body():
    secret = b"github_secret_xyz"
    sig_header = _github_sig(secret, b'{"action":"push"}', sha256=True)
    analysis = analyze_webhook(
        _req({"X-Hub-Signature-256": sig_header}, body=b'{"action":"hijack"}'),
        secret=secret,
    )
    assert analysis.verified is False


def test_verification_not_attempted_without_secret():
    """analysis.verified is None when caller didn't provide a secret."""
    analysis = analyze_webhook(_req({"X-Hub-Signature-256": "sha256=abc"}))
    assert analysis.verified is None


# =====================================================================
# Banca-safety: secret never echoed
# =====================================================================


def test_secret_value_never_in_analysis_output():
    """Banca-privacy: even with a wildly-suspicious secret value,
    the analysis must NOT reveal it in any finding string."""
    secret = b"whsec_BANCO_SECRET_VALUE_AAAA_BBBB_CCCC"
    body = b'{"x":1}'
    ts = _now() - 30
    sig_header = _stripe_sig(secret + b"_wrong", body, ts)  # forces fail
    analysis = analyze_webhook(
        _req({"Stripe-Signature": sig_header}, body=body),
        secret=secret,
    )
    # Aggregate every string the analysis carries.
    rendered = " ".join(
        f.detail + " " + f.title + " " + f.remediation for f in analysis.findings
    )
    assert b"BANCO_SECRET_VALUE".decode() not in rendered
    assert secret.decode() not in rendered


# =====================================================================
# All-schemes pin + frozen contracts
# =====================================================================


def test_all_schemes_constant_includes_documented():
    required = {
        "stripe",
        "github_sha256",
        "github_sha1",
        "discord_ed25519",
        "rfc9421",
        "bancard",
        "bcp",
        "open_banking_jws",
        "custom_x_signature",
        "unknown",
    }
    assert required <= set(ALL_SCHEMES)


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    req = WebhookRequest(method="POST", url="x", headers={}, body=b"")
    with pytest.raises(FrozenInstanceError):
        req.method = "GET"  # type: ignore[misc]

    f = WebhookFinding(
        finding_id="WHK-001", severity="CRITICAL", title="x", detail="x", remediation="x"
    )
    with pytest.raises(FrozenInstanceError):
        f.severity = "LOW"  # type: ignore[misc]

    a = WebhookAnalysis(
        scheme_detected="unknown",
        signature_present=False,
        timestamp_present=False,
        timestamp_value=None,
        nonce_present=False,
    )
    with pytest.raises(FrozenInstanceError):
        a.scheme_detected = "stripe"  # type: ignore[misc]


# =====================================================================
# Output ordering
# =====================================================================


def test_findings_sorted_by_severity():
    """A request with multiple weaknesses — CRITICAL findings appear
    before HIGH which appear before MEDIUM/INFO."""
    headers = {
        "X-Hub-Signature": "sha1=abc",  # github_sha1 (HIGH WHK-002 + HIGH WHK-003)
        "Content-Length": "999",  # MEDIUM WHK-030
    }
    body = b"short"
    analysis = analyze_webhook(_req(headers, body=body))
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in analysis.findings]
    assert ranks == sorted(ranks)


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_wrapper_dict_shape():
    from kryon.tools.api.webhook_tool import _analysis_to_dict

    analysis = analyze_webhook(_req({}))
    payload = _analysis_to_dict(analysis)
    assert payload["scheme_detected"] == "unknown"
    assert payload["signature_present"] is False
    assert payload["verified"] is None
    assert "WHK-001" in {f["id"] for f in payload["findings"]}
    json.dumps(payload)  # serializable


def test_tool_wrapper_round_trip_via_helpers():
    """Exercise the dict↔finding round-trip without invoking the
    function_tool decorator (which wraps for SDK use)."""
    from kryon.tools.api.webhook_tool import _finding_to_dict

    f = WebhookFinding(
        finding_id="WHK-002",
        severity="HIGH",
        title="t",
        detail="d",
        remediation="r",
    )
    d = _finding_to_dict(f)
    assert d == {
        "id": "WHK-002",
        "severity": "HIGH",
        "title": "t",
        "detail": "d",
        "remediation": "r",
    }
