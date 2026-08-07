"""Batch O — edge-VPN appliance fingerprinting (Fortinet/Citrix/GlobalProtect/
Pulse-Ivanti). HTTP responses mocked; signature precision + graceful behavior."""

from __future__ import annotations

import kryon.cli.vpn_probes as vp
from kryon.cli.engage import DiscoveredService
from kryon.cli.vpn_probes import _VPN_PROBES, run_vpn_probes

_DEAD = "127.0.0.1"


def _svc(port: int = 443) -> DiscoveredService:
    return DiscoveredService(host=_DEAD, port=port, state="open", service="https")


def test_run_vpn_probes_graceful_on_dead_port():
    assert isinstance(run_vpn_probes(_svc(443), "https"), list)


def test_dispatch_well_formed():
    assert len(_VPN_PROBES) == 9
    assert all(callable(p) for p in _VPN_PROBES)


def _mock(monkeypatch, responses):
    # responses: dict path -> (status, cookies_lower, body)
    monkeypatch.setattr(vp, "_vpn_get", lambda host, port, path, scheme: responses.get(path))


def test_fortinet_detected_by_body(monkeypatch):
    _mock(monkeypatch, {"/remote/login?lang=en": (200, "", "<html>var fgt_lang; logincheck</html>")})
    f = vp._check_fortinet(_svc(), "https")
    assert f is not None and f.rule_id == "fortinet-sslvpn-exposed" and f.severity == "HIGH"


def test_fortinet_detected_by_cookie(monkeypatch):
    _mock(monkeypatch, {"/remote/login?lang=en": (200, "svpncookie=abc; path=/", "<html>login</html>")})
    assert vp._check_fortinet(_svc(), "https").rule_id == "fortinet-sslvpn-exposed"


def test_fortinet_absent_returns_none(monkeypatch):
    _mock(monkeypatch, {"/remote/login?lang=en": (404, "", "<html>nginx</html>")})
    assert vp._check_fortinet(_svc(), "https") is None


def test_citrix_detected_by_cookie(monkeypatch):
    _mock(monkeypatch, {"/vpn/index.html": (200, "nsc_aaac=xyz; secure", "<html>gateway</html>")})
    f = vp._check_citrix(_svc(), "https")
    assert f is not None and f.rule_id == "citrix-netscaler-exposed"


def test_citrix_detected_by_body(monkeypatch):
    _mock(monkeypatch, {"/vpn/index.html": (200, "", "<title>Citrix Gateway</title>")})
    assert vp._check_citrix(_svc(), "https").rule_id == "citrix-netscaler-exposed"


def test_globalprotect_detected(monkeypatch):
    _mock(monkeypatch, {"/global-protect/login.esp": (200, "", "<title>GlobalProtect Portal</title>")})
    f = vp._check_globalprotect(_svc(), "https")
    assert f is not None and f.rule_id == "paloalto-globalprotect-exposed"


def test_pulse_ivanti_detected_by_cookie(monkeypatch):
    _mock(monkeypatch, {"/dana-na/auth/url_default/welcome.cgi": (200, "dsid=deadbeef; httponly", "<html>welcome</html>")})
    assert vp._check_pulse_ivanti(_svc(), "https").rule_id == "pulse-ivanti-exposed"


def test_cisco_iosxe_detected(monkeypatch):
    _mock(monkeypatch, {"/webui/": (200, "", "<html>Cisco IOS XE webui_internal login</html>")})
    f = vp._check_cisco_iosxe(_svc(), "https")
    assert f is not None and f.rule_id == "cisco-iosxe-webui-exposed" and f.severity == "HIGH"


def test_cisco_iosxe_absent_returns_none(monkeypatch):
    _mock(monkeypatch, {"/webui/": (404, "", "<html>nginx</html>")})
    assert vp._check_cisco_iosxe(_svc(), "https") is None


def test_checkpoint_detected(monkeypatch):
    _mock(monkeypatch, {"/": (200, "", "<html>Check Point Mobile Access Portal</html>")})
    f = vp._check_checkpoint(_svc(), "https")
    assert f is not None and f.rule_id == "checkpoint-gateway-exposed"


def test_checkpoint_no_fp_on_vercel_challenge(monkeypatch):
    """F210 regression — Vercel's anti-bot page titled 'Vercel Security
    Checkpoint' must NOT be fingerprinted as a Check Point gateway. The
    bare word 'checkpoint' (no space) used to match it → HIGH+CVE FP
    against example.com.py (a Vercel-hosted site)."""
    vercel_body = (
        "<!doctype html><html><head><title>Vercel Security Checkpoint</title></head>"
        "<body>please wait while we verify your request</body></html>"
    )
    _mock(monkeypatch, dict.fromkeys(("/", "/sslvpn/Login/Login", "/clients/"), (403, "", vercel_body)))
    assert vp._check_checkpoint(_svc(), "https") is None


def test_checkpoint_detected_by_cookie(monkeypatch):
    # A real Check Point gateway is still caught via the cvpnd VPN cookie.
    _mock(monkeypatch, {"/": (200, "cvpnd=abc; path=/", "<html>login</html>")})
    assert vp._check_checkpoint(_svc(), "https").rule_id == "checkpoint-gateway-exposed"


def test_no_false_positive_on_generic_https(monkeypatch):
    monkeypatch.setattr(vp, "_vpn_get", lambda *a: (200, "", "<html><body>welcome to nginx</body></html>"))
    assert run_vpn_probes(_svc(), "https") == []


def test_appliance_findings_are_heuristic_needs_review(monkeypatch):
    """F210 gap #2 — the appliance EXPOSURE is confirmed by fingerprint, but
    the named CVE ('verificar parche') is inferred → the finding must carry
    verification_level=heuristic + needs_verification so the report routes it
    to 'requiere verificación', not '✅ Verificado'."""
    _mock(monkeypatch, {"/remote/login?lang=en": (200, "svpncookie=abc; path=/", "<html>login</html>")})
    f = vp._check_fortinet(_svc(), "https")
    assert f is not None and f.rule_id == "fortinet-sslvpn-exposed"
    assert f.verification_level == "heuristic"
    assert f.needs_verification is True
    assert f.confidence < 0.7


def test_confirmed_probe_default_stays_ground_truth():
    """Regression — a plain _f() finding (no verification_level) is unchanged:
    confidence 1.0, not flagged."""
    from kryon.cli.probe_base import _f

    f = _f(_svc(), "CWE-200", "LOW", "info-leak", "banner leak", "evidence", "fix")
    assert f.verification_level == "confirmed"
    assert f.confidence == 1.0
    assert f.needs_verification is False
