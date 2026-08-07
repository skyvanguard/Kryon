"""F116 — TDD contract for embedded secret detection + redaction."""

from __future__ import annotations

import pytest

from kryon.tools.content_classifier.secrets import (
    SECRET_PATTERNS,
    EmbeddedSecret,
    _redact,
    scan_for_secrets,
    shannon_entropy,
)

# =====================================================================
# Shannon entropy
# =====================================================================


def test_shannon_entropy_zero_for_uniform():
    assert shannon_entropy(b"AAAAA") == 0.0


def test_shannon_entropy_one_for_binary_uniform():
    assert shannon_entropy(b"AB" * 100) == pytest.approx(1.0, abs=0.01)


def test_shannon_entropy_high_for_random():
    import os

    e = shannon_entropy(os.urandom(2000))
    assert 7.5 <= e <= 8.0  # uniform random bytes ≈ 8.0


def test_shannon_entropy_caps_at_sample_size():
    # Should NOT scan the whole 1MB body, only sample_size bytes
    big = b"A" * 1_000_000
    assert shannon_entropy(big, sample_size=100) == 0.0


def test_shannon_entropy_empty():
    assert shannon_entropy(b"") == 0.0


# =====================================================================
# Redaction
# =====================================================================


def test_redact_long_value():
    r = _redact(b"AKIA12345678ABCDEFGH")
    assert r.startswith("AKIA")
    assert r.endswith("EFGH")
    assert "…" in r
    # The middle is NOT in the redaction
    assert "12345678" not in r


def test_redact_short_value():
    """< 8 chars → fully hidden as ***."""
    assert _redact(b"abc") == "***"
    assert _redact(b"a") == "***"
    assert _redact(b"abcdefg") == "***"  # 7 chars


def test_redact_medium_value():
    """8..12 chars → <first>***<last>."""
    r = _redact(b"abcdefgh")  # 8 chars
    assert r == "a***h"


def test_redact_long_keeps_first_last_four():
    r = _redact(b"abcdefghijklmnop")  # 16 chars
    assert r == "abcd…mnop"


# =====================================================================
# Pattern coverage
# =====================================================================


def test_detects_aws_access_key():
    body = b"some HTML content with AKIAIOSFODNN7EXAMPLE embedded"
    secrets = scan_for_secrets(body)
    assert any(s.kind == "aws-access-key" for s in secrets)
    aws = next(s for s in secrets if s.kind == "aws-access-key")
    assert aws.severity == "CRITICAL"
    assert "AKIA" in aws.redacted_preview


def test_detects_github_pat():
    body = b"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    secrets = scan_for_secrets(body)
    assert any(s.kind == "github-personal-access-token" for s in secrets)


def test_detects_stripe_live_secret():
    body = b"const stripeKey = 'sk_live_abcdefghij1234567890zyxw';"
    secrets = scan_for_secrets(body)
    assert any(s.kind == "stripe-secret-live" for s in secrets)


def test_detects_jwt():
    jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.AbCdEfGhIjKlMnOpQrStUv"
    body = b"Authorization: " + jwt
    secrets = scan_for_secrets(body)
    assert any(s.kind == "jwt-token" for s in secrets)


def test_detects_google_api_key():
    body = b"const apiKey = 'AIzaSyABC1234567890DEFghijklmnoprstuvwxy_';"
    secrets = scan_for_secrets(body)
    assert any(s.kind == "google-api-key" for s in secrets)


def test_detects_slack_token():
    body = b"slack_token='xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'"
    secrets = scan_for_secrets(body)
    assert any(s.kind == "slack-token" for s in secrets)


def test_detects_private_key_header():
    body = b"-----BEGIN OPENSSH PRIVATE KEY-----\nbase64...\n"
    secrets = scan_for_secrets(body)
    assert any(s.kind == "private-key-header" for s in secrets)


def test_detects_npm_token():
    body = b"//registry.npmjs.org/:_authToken=npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    secrets = scan_for_secrets(body)
    assert any(s.kind == "npm-token" for s in secrets)


def test_detects_bearer_in_body():
    body = (
        b'Sample HTML: <script>fetch("...", {headers: {Authorization: "Bearer eyJhbGc1234567890ABCDEFGHIJ"}})</script>'
    )
    secrets = scan_for_secrets(body)
    assert any(s.kind == "bearer-token-in-body" for s in secrets)


def test_detects_generic_api_key_context():
    body = b'config.json: {"api_key": "abc123def456ghi789jklmnop"}'
    secrets = scan_for_secrets(body)
    assert any(s.kind == "generic-api-key-context" for s in secrets)


def test_no_false_positive_on_clean_html():
    body = b"<html><body>Welcome to our site</body></html>"
    secrets = scan_for_secrets(body)
    assert secrets == ()


def test_empty_content_returns_empty():
    assert scan_for_secrets(b"") == ()


def test_dedupes_identical_secrets():
    """Same exact secret repeated → reported once."""
    body = b"AKIAIOSFODNN7EXAMPLE\n" * 5
    secrets = scan_for_secrets(body)
    aws_findings = [s for s in secrets if s.kind == "aws-access-key"]
    assert len(aws_findings) == 1


def test_distinct_aws_keys_both_reported():
    """Two DIFFERENT AWS keys → both reported."""
    # Each must be AKIA + 16 chars [0-9A-Z]
    body = b"AKIAIOSFODNN7EXAMPLE\nAKIA0000000000EXAMPLE"
    secrets = scan_for_secrets(body)
    aws_findings = [s for s in secrets if s.kind == "aws-access-key"]
    assert len(aws_findings) == 2


def test_redacted_preview_never_contains_full_value():
    """Banca-safety: the redacted_preview must NEVER contain the
    middle of the secret."""
    body = b"AKIAIOSFODNN7EXAMPLE"
    secrets = scan_for_secrets(body)
    aws = next(s for s in secrets if s.kind == "aws-access-key")
    # The full string IOSFODNN7 should NOT appear in the preview
    assert "IOSFODNN7" not in aws.redacted_preview


def test_max_secrets_cap_respected():
    """Generate way more secrets than max_secrets and ensure cap."""
    body = b"\n".join(f"AKIA{i:016d}".encode() for i in range(100))
    secrets = scan_for_secrets(body, max_secrets=10)
    assert len(secrets) <= 10


def test_pattern_set_has_critical_aws_github():
    """Sanity check on pattern coverage."""
    kinds_in_table = {kind for _p, kind, _sev in SECRET_PATTERNS}
    assert "aws-access-key" in kinds_in_table
    assert "github-personal-access-token" in kinds_in_table
    assert "private-key-header" in kinds_in_table
    assert "jwt-token" in kinds_in_table


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    s = EmbeddedSecret(
        kind="x",
        severity="LOW",
        redacted_preview="x",
        value_sha256="0" * 64,
        matched_at_offset=0,
        matched_length=0,
    )
    with pytest.raises(FrozenInstanceError):
        s.severity = "HIGH"  # type: ignore[misc]
