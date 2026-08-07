"""Tier-2 deterministic extensions — extra edge-VPN appliances (SonicWall/Cisco ASA/F5)
and CMS version-disclosure fingerprints (Drupal/Joomla/Zabbix). Responses are mocked;
read-only signature precision + graceful-on-unreachable are checked directly.
"""

from __future__ import annotations

import kryon.cli.vpn_probes as vp
import kryon.cli.web_probes as wp
from kryon.cli.engage import DiscoveredService


def _svc(port: int = 443, service: str = "https") -> DiscoveredService:
    return DiscoveredService(host="10.0.0.1", port=port, state="open", service=service)


# --- edge-VPN appliance fingerprints (read-only GET of the public portal) -----------------


def test_sonicwall_detected(monkeypatch):
    monkeypatch.setattr(vp, "_vpn_get", lambda *_a, **_k: (200, "", "<html>SonicWall SSL-VPN sslvpnclient</html>"))
    f = vp._check_sonicwall(_svc(), "https")
    assert f is not None and f.rule_id == "sonicwall-sslvpn-exposed" and f.severity == "HIGH"
    assert "CVE-2024-40766" in f.evidence or "CVE-2024-40766" in f.message


def test_cisco_asa_detected(monkeypatch):
    monkeypatch.setattr(vp, "_vpn_get", lambda *_a, **_k: (200, "", "<html>+CSCOE+/logon AnyConnect</html>"))
    f = vp._check_cisco_asa(_svc(), "https")
    assert f is not None and f.rule_id == "cisco-asa-webvpn-exposed"


def test_f5_bigip_detected_via_cookie(monkeypatch):
    monkeypatch.setattr(vp, "_vpn_get", lambda *_a, **_k: (200, "set-cookie: mrhsession=abc", "<html>login</html>"))
    f = vp._check_f5_bigip(_svc(), "https")
    assert f is not None and f.rule_id == "f5-bigip-exposed"


def test_vpn_appliances_none_when_no_markers(monkeypatch):
    monkeypatch.setattr(vp, "_vpn_get", lambda *_a, **_k: (200, "", "<html>generic page</html>"))
    assert vp._check_sonicwall(_svc(), "https") is None
    assert vp._check_cisco_asa(_svc(), "https") is None
    assert vp._check_f5_bigip(_svc(), "https") is None


def test_vpn_probes_table_has_seven():
    # Table grew from 7 to 9 (cisco_iosxe + checkpoint added); test_vpn_probes
    # asserts the same count of 9. Keeping the two in sync.
    assert len(vp._VPN_PROBES) == 9


# --- CMS version-disclosure fingerprints --------------------------------------------------


def test_drupal_version_disclosure(monkeypatch):
    def fake_get(host, port, path, scheme="http"):  # noqa: ANN001
        if path == "/CHANGELOG.txt":
            return (200, "\nDrupal 7.50, 2016-02-24\n-----------------\n")
        return None

    monkeypatch.setattr(wp, "_http_get", fake_get)
    out = wp._check_cms(_svc(80, "http"), "http")
    ids = {f.rule_id for f in out}
    assert "drupal-version-disclosure" in ids


def test_joomla_version_disclosure(monkeypatch):
    def fake_get(host, port, path, scheme="http"):  # noqa: ANN001
        if "joomla.xml" in path:
            return (200, "<extension><version>4.2.5</version></extension>")
        return None

    monkeypatch.setattr(wp, "_http_get", fake_get)
    out = wp._check_cms(_svc(80, "http"), "http")
    assert any(f.rule_id == "joomla-version-disclosure" and "4.2.5" in f.message for f in out)


def test_zabbix_frontend_detected(monkeypatch):
    def fake_get(host, port, path, scheme="http"):  # noqa: ANN001
        if path == "/zabbix/index.php":
            return (200, "<html><div class='z-logo'>Zabbix 6.0.1 by Zabbix SIA</div></html>")
        return None

    monkeypatch.setattr(wp, "_http_get", fake_get)
    out = wp._check_cms(_svc(80, "http"), "http")
    assert any(f.rule_id == "zabbix-frontend-exposed" for f in out)


def test_cms_none_on_plain_site(monkeypatch):
    monkeypatch.setattr(wp, "_http_get", lambda *_a, **_k: (404, ""))
    assert wp._check_cms(_svc(80, "http"), "http") == []


# --- WordPress under a subpath (Internal box: /blog) — found live, not just docroot --------


def test_wordpress_detected_under_subpath(monkeypatch):
    def fake_get(host, port, path, scheme="http"):  # noqa: ANN001
        if path == "/blog/":
            return (200, "<html><link href='/blog/wp-content/themes/x/style.css'></html>")
        if path == "/blog/xmlrpc.php":
            return (405, "XML-RPC server accepts POST requests only.")
        if path == "/blog/readme.html":
            return (200, "<h1>WordPress</h1> Version 5.1.6")
        if path == "/":  # docroot is a plain page → must not match
            return (200, "<html>It works</html>")
        return (404, "")

    monkeypatch.setattr(wp, "_http_get", fake_get)
    assert wp._find_wp_base(_svc(80, "http"), "http") == "/blog"
    ids = {f.rule_id for f in wp._check_wordpress(_svc(80, "http"), "http")}
    assert "wordpress-detected" in ids
    assert "wordpress-xmlrpc" in ids


def test_wordpress_abstains_on_non_wp_site(monkeypatch):
    monkeypatch.setattr(wp, "_http_get", lambda *_a, **_k: (200, "<html>nothing to see</html>"))
    assert wp._find_wp_base(_svc(80, "http"), "http") is None
    assert wp._check_wordpress(_svc(80, "http"), "http") == []
