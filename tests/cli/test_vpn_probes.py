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
    assert len(_VPN_PROBES) == 4
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


def test_no_false_positive_on_generic_https(monkeypatch):
    monkeypatch.setattr(vp, "_vpn_get", lambda *a: (200, "", "<html><body>welcome to nginx</body></html>"))
    assert run_vpn_probes(_svc(), "https") == []
