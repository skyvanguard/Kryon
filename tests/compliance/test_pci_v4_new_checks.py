"""PCI-DSS v4.0.1 checks: 6.4.3 (payment-script SRI+CSP) and 8.4.3 (SSH MFA).

These were named in the README/CLAUDE.md as implemented but did not exist —
now built as real deterministic checks. run_cmd is monkeypatched (no network).
"""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C643 = importlib.import_module("kryon.compliance.checks.section_6.c_6_4_3_payment_scripts")
C843 = importlib.import_module("kryon.compliance.checks.section_8.c_8_4_3_mfa")


def _ports_then(curl_response: str):
    """Fake run_cmd: `ss` reports one web port (443); `curl` returns the response."""

    def fake(_ctx, cmd, **_kw):
        if cmd[0] == "ss":
            return ("LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n", "", 0)
        if cmd[0] == "curl":
            return (curl_response, "", 0)
        return ("", "", 1)

    return fake


# --- 6.4.3: payment-page script management (SRI + CSP) ---


def test_643_na_when_no_web_ports(monkeypatch):
    monkeypatch.setattr(C643, "run_cmd", lambda _c, cmd, **_k: ("", "", 1))
    assert C643.CHECK.run(CheckContext(host="x")).verdict == "N/A"


def test_643_fail_external_script_without_sri(monkeypatch):
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><script src='https://cdn.evil.com/a.js'></script></html>"
    monkeypatch.setattr(C643, "run_cmd", _ports_then(resp))
    r = C643.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "FAIL"
    assert r.evidence_parsed["per_port"]["443"]["external_scripts_without_sri"]


def test_643_pass_with_sri_and_csp(monkeypatch):
    resp = (
        "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com\r\n\r\n"
        "<html><script src='https://cdn.example.com/a.js' integrity='sha384-abc' crossorigin='anonymous'></script></html>"
    )
    monkeypatch.setattr(C643, "run_cmd", _ports_then(resp))
    assert C643.CHECK.run(CheckContext(host="x")).verdict == "PASS"


def test_643_pass_inline_only_with_csp(monkeypatch):
    resp = "HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'self'\r\n\r\n<html><script>console.log(1)</script></html>"
    monkeypatch.setattr(C643, "run_cmd", _ports_then(resp))
    assert C643.CHECK.run(CheckContext(host="x")).verdict == "PASS"


# --- 8.4.3: MFA for remote SSH access ---


def _ssh_pam(sshd: str, pam: str, sshd_rc: int = 0, pam_rc: int = 0):
    def fake(_ctx, cmd, **_kw):
        if "sshd_config" in cmd[-1]:
            return (sshd, "", sshd_rc)
        if "pam.d/sshd" in cmd[-1]:
            return (pam, "", pam_rc)
        return ("", "", 1)

    return fake


def test_843_na_when_no_ssh(monkeypatch):
    monkeypatch.setattr(C843, "run_cmd", _ssh_pam("", "", sshd_rc=1, pam_rc=1))
    assert C843.CHECK.run(CheckContext(host="x")).verdict == "N/A"


def test_843_pass_authentication_methods(monkeypatch):
    monkeypatch.setattr(C843, "run_cmd", _ssh_pam("AuthenticationMethods publickey,keyboard-interactive\n", ""))
    r = C843.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "PASS"
    assert r.evidence_parsed["auth_methods_multifactor"] is True


def test_843_fail_single_factor(monkeypatch):
    monkeypatch.setattr(C843, "run_cmd", _ssh_pam("PasswordAuthentication yes\n", "auth required pam_unix.so\n"))
    assert C843.CHECK.run(CheckContext(host="x")).verdict == "FAIL"


def test_843_pass_phishing_resistant_fido2(monkeypatch):
    monkeypatch.setattr(C843, "run_cmd", _ssh_pam("PasswordAuthentication no\n", "auth required pam_u2f.so\n"))
    r = C843.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "PASS"
    assert r.evidence_parsed["phishing_resistant"] is True


def test_843_ignores_commented_pam_module(monkeypatch):
    monkeypatch.setattr(
        C843, "run_cmd", _ssh_pam("PasswordAuthentication yes\n", "# auth required pam_google_authenticator.so\n")
    )
    assert C843.CHECK.run(CheckContext(host="x")).verdict == "FAIL"


# --- registration: the new checks are discoverable ---


def test_new_checks_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert "6.4.3" in ids
    assert "8.4.3" in ids
