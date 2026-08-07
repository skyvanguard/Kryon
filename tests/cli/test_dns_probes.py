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


# ---------------------------------------------------------------------------
# Batch J — CAA / MTA-STS / TLS-RPT
# ---------------------------------------------------------------------------


def test_caa_missing(monkeypatch):
    monkeypatch.setattr(dp, "_caa", lambda name: [])
    assert dp._check_caa("acme.com").rule_id == "caa-missing"


def test_caa_present_ok(monkeypatch):
    monkeypatch.setattr(dp, "_caa", lambda name: ['0 issue "letsencrypt.org"'])
    assert dp._check_caa("acme.com") is None


def test_mta_sts_missing_only_with_mx(monkeypatch):
    monkeypatch.setattr(dp, "_has_mx", lambda d: True)
    monkeypatch.setattr(dp, "_txt", lambda name: [])
    assert dp._check_mta_sts("acme.com").rule_id == "mta-sts-missing"
    # No MX → not applicable, no finding.
    monkeypatch.setattr(dp, "_has_mx", lambda d: False)
    assert dp._check_mta_sts("acme.com") is None


def test_mta_sts_present_ok(monkeypatch):
    monkeypatch.setattr(dp, "_has_mx", lambda d: True)
    monkeypatch.setattr(dp, "_txt", lambda name: ["v=STSv1; id=20240101"])
    assert dp._check_mta_sts("acme.com") is None


def test_tls_rpt_missing_only_with_mx(monkeypatch):
    monkeypatch.setattr(dp, "_has_mx", lambda d: True)
    monkeypatch.setattr(dp, "_txt", lambda name: [])
    assert dp._check_tls_rpt("acme.com").rule_id == "tls-rpt-missing"
    monkeypatch.setattr(dp, "_has_mx", lambda d: False)
    assert dp._check_tls_rpt("acme.com") is None


# ---------------------------------------------------------------------------
# Batch R — DNS zone transfer (AXFR)
# ---------------------------------------------------------------------------


def _patch_dns(monkeypatch, xfr):
    import types

    import dns.query
    import dns.resolver
    import dns.zone

    monkeypatch.setattr(dns.resolver, "resolve", lambda name, rtype, lifetime=5: (
        [types.SimpleNamespace(target="ns1.acme.com.")] if rtype == "NS" else ["10.0.0.1"]))
    monkeypatch.setattr(dns.query, "xfr", xfr)
    monkeypatch.setattr(dns.zone, "from_xfr",
                        lambda x: types.SimpleNamespace(nodes={"@": 1, "www": 1, "mail": 1}))


def test_axfr_open_detected(monkeypatch):
    _patch_dns(monkeypatch, lambda ip, domain, lifetime=8: iter([]))
    f = dp._check_axfr("acme.com")
    assert f is not None and f.rule_id == "dns-zone-transfer" and f.severity == "HIGH"


def test_axfr_refused_returns_none(monkeypatch):
    def _boom(ip, domain, lifetime=8):
        raise RuntimeError("transfer refused")

    _patch_dns(monkeypatch, _boom)
    assert dp._check_axfr("acme.com") is None


# ---------------------------------------------------------------------------
# Registrable-domain (apex) derivation — email posture must hit the org domain
# ---------------------------------------------------------------------------

import pytest  # noqa: E402


@pytest.mark.parametrize(
    "host,apex",
    [
        ("www.example.com", "example.com"),  # two-label suffix com.py
        ("odoo.example.com", "example.com"),
        ("example.com", "example.com"),  # already apex
        ("a.b.foo.co.uk", "foo.co.uk"),
        ("deep.sub.acme.com.ar", "acme.com.ar"),
        ("sub.example.com", "example.com"),  # plain gTLD → eTLD+1
        ("example.com", "example.com"),
    ],
)
def test_registrable_domain(host, apex):
    assert dp._registrable_domain(host) == apex


def test_run_dns_probes_email_checks_use_apex(monkeypatch):
    """SPF/DMARC/DKIM on a subdomain host must query the APEX, not the subdomain —
    the fix for the www.example.com false 'SPF/DMARC missing'."""
    seen: dict[str, str] = {}

    def _cap(key):
        def fn(d):
            seen[key] = d
            return None

        return fn

    monkeypatch.setattr(dp, "_check_spf", _cap("spf"))
    monkeypatch.setattr(dp, "_check_dmarc", _cap("dmarc"))
    monkeypatch.setattr(dp, "_check_dkim", _cap("dkim"))
    monkeypatch.setattr(dp, "_check_subdomain_takeover", _cap("takeover"))
    for name in ("_check_caa", "_check_mta_sts", "_check_tls_rpt", "_check_axfr"):
        monkeypatch.setattr(dp, name, lambda d: None)

    dp.run_dns_probes("www.example.com")

    assert seen["spf"] == "example.com"
    assert seen["dmarc"] == "example.com"
    assert seen["dkim"] == "example.com"
    # subdomain takeover stays host-specific
    assert seen["takeover"] == "www.example.com"
