"""Deterministic secret extraction — pattern precision, FP-safety, redaction."""

from __future__ import annotations

from kryon.cli.secret_scanner import _redact, _shannon_entropy, scan_secrets, to_findings


def _kinds(text):
    return {m.rule_id for m in scan_secrets(text)}


def test_aws_access_key():
    rules = _kinds("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    assert "secret-aws-akid" in rules


def test_aws_secret_key():
    assert "secret-aws-secret" in _kinds('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')


def test_private_key_pem():
    assert "secret-private-key" in _kinds("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n")


def test_github_and_gitlab_tokens():
    assert "secret-github-pat" in _kinds("token: ghp_" + "a" * 36)
    assert "secret-gitlab-pat" in _kinds("GITLAB=glpat-" + "a" * 20)


def test_db_connection_uri():
    assert "secret-db-uri" in _kinds("DATABASE_URL=postgres://admin:s3cr3tpw@db.internal:5432/app")


def test_jwt():
    assert "secret-jwt" in _kinds("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36")


def test_generic_password_assignment():
    assert "secret-generic-password" in _kinds("DB_PASSWORD=SuperSecret123\nAPP_KEY=base64:abcd")


def test_high_entropy_fallback():
    # A secret-looking key with a high-entropy value not caught structurally.
    rules = _kinds('api_secret = "f8e7d6c5b4a39281f8e7d6c5b4a39281"')
    assert "secret-high-entropy" in rules or "secret-generic-password" in rules


def test_no_false_positive_on_prose():
    text = "<html><body>Welcome to our website. Contact us for an API to integrate.</body></html>"
    assert scan_secrets(text) == []


def test_no_false_positive_on_low_entropy_word():
    # "password = changeme" caught by generic rule (legit), but a normal sentence isn't.
    assert scan_secrets("The token of appreciation was given to all.") == []


def test_redaction_hides_value():
    matches = scan_secrets("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    assert matches
    for m in matches:
        assert "AKIAIOSFODNN7EXAMPLE" not in m.redacted
        assert "…" in m.redacted or "***" in m.redacted


def test_dedup_same_secret():
    text = "key=AKIAIOSFODNN7EXAMPLE\nagain=AKIAIOSFODNN7EXAMPLE"
    akids = [m for m in scan_secrets(text) if m.rule_id == "secret-aws-akid"]
    assert len(akids) == 1


def test_line_numbers():
    text = "line1\nline2\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    m = next(m for m in scan_secrets(text) if m.rule_id == "secret-aws-akid")
    assert m.line == 3


def test_to_findings_shape():
    matches = scan_secrets("DB_PASSWORD=hunter2hunter2")
    findings = to_findings(matches, "10.0.0.5", "/.env")
    assert findings and findings[0].cwe == "CWE-798" and findings[0].host == "10.0.0.5"
    assert "10.0.0.5" in findings[0].message and "/.env" in findings[0].evidence


def test_helpers():
    assert _shannon_entropy("aaaa") < 1.0
    assert _shannon_entropy("a1B2c3D4e5F6") > 3.0
    assert _redact("short") == "s***t"
    assert "…" in _redact("AKIAIOSFODNN7EXAMPLE")
