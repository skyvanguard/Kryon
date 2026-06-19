"""DNS / email-security probes — SPF/DMARC/DKIM posture + subdomain takeover.

Parsing logic is unit-tested with a mocked resolver (no live DNS); the IP/.local
skip and graceful behavior are checked directly."""

from __future__ import annotations

import kryon.cli.dns_probes as dp


def test_skips_ip_literals_and_local():
    assert dp.run_dns_probes("10.0.0.5") == []
    assert dp.run_dns_probes("192.168.1.1") == []
    assert dp.run_dns_probes("host.local") == []
    assert dp.run_dns_probes("nodot") == []


def test_spf_missing(monkeypatch):
    monkeypatch.setattr(dp, "_txt", lambda name: [])
    f = dp._check_spf("acme.com")
    assert f is not None and f.rule_id == "spf-missing"


def test_spf_permissive(monkeypatch):
    monkeypatch.setattr(dp, "_txt", lambda name: ["v=spf1 +all"])
    assert dp._check_spf("acme.com").rule_id == "spf-permissive"


def test_spf_ok(monkeypatch):
    monkeypatch.setattr(dp, "_txt", lambda name: ["v=spf1 include:_spf.google.com -all"])
    assert dp._check_spf("acme.com") is None


def test_dmarc_missing(monkeypatch):
    monkeypatch.setattr(dp, "_txt", lambda name: [])
    assert dp._check_dmarc("acme.com").rule_id == "dmarc-missing"


def test_dmarc_policy_none(monkeypatch):
    monkeypatch.setattr(dp, "_txt", lambda name: ["v=DMARC1; p=none; rua=mailto:x@acme.com"])
    assert dp._check_dmarc("acme.com").rule_id == "dmarc-policy-none"


def test_dmarc_reject_ok(monkeypatch):
    monkeypatch.setattr(dp, "_txt", lambda name: ["v=DMARC1; p=reject"])
    assert dp._check_dmarc("acme.com") is None


def test_dkim_found_ok(monkeypatch):
    monkeypatch.setattr(dp, "_txt", lambda name: ["v=DKIM1; k=rsa; p=MIGf..."] if name.startswith("default.") else [])
    assert dp._check_dkim("acme.com") is None
