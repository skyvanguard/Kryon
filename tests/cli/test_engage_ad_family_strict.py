"""F202.I — Restrict windows_ad family detection to AD-specific ports.

Surface ground truth POC Britimp 2026-05-18 against .101:
  Open ports: 135, 139, 445, 3389, 7070, 8080, 9999
  AD ports: NONE (88 Kerberos / 389 LDAP / 636 LDAPS / 3268 GC all closed)
  Pre-F202.I: windows_ad family activated by 135 + 445 -> 9 AD-* FPs
  Post-F202.I: only `windows` family; AD checks NOT applied.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _detect_device_families


def _svc(port: int, service: str = "", product: str = "", state: str = "open") -> DiscoveredService:
    return DiscoveredService(host="h", port=port, state=state, service=service, product=product)


# ---------------------------------------------------------------------------
# F202.I — Britimp .101 regression
# ---------------------------------------------------------------------------


class TestMemberServerNotAD:
    def test_britimp_h101_scenario(self):
        """The exact .101 case: Windows member server with SMB + RDP +
        IIS but NO AD-specific ports. Must NOT activate windows_ad."""
        services = [
            _svc(135, "msrpc", "Microsoft Windows RPC"),
            _svc(139, "netbios-ssn", "Microsoft Windows netbios-ssn"),
            _svc(445, "microsoft-ds"),
            _svc(3389, "ms-wbt-server"),
            _svc(7070, "realserver"),
            _svc(8080, "http", "Microsoft IIS httpd 10.0"),
            _svc(9999, "abyss"),
        ]
        families = _detect_device_families(services)
        assert "windows" in families, f"Expected windows family, got {families}"
        assert "windows_ad" not in families, f"Pre-F202.I bug: 135/445 alone activated AD family; got {families}"

    def test_basic_smb_only_no_ad(self):
        """Even barer Windows server (SMB-only) -> windows family only.
        Requires at least one banner mentioning Windows/Microsoft
        (matches what nmap returns for 135 msrpc / 445 microsoft-ds)."""
        services = [
            _svc(135, "msrpc", "Microsoft Windows RPC"),
            _svc(445, "microsoft-ds"),
            _svc(139, "netbios-ssn"),
        ]
        families = _detect_device_families(services)
        assert "windows" in families
        assert "windows_ad" not in families

    def test_rdp_only_no_ad(self):
        """Bare RDP jump host -> windows only (catch-all RDP branch).
        The 3389 fallback branch in _detect_device_families adds
        `windows` when windows_ad has NOT been triggered first."""
        services = [_svc(3389, "ms-wbt-server")]
        families = _detect_device_families(services)
        assert "windows" in families
        assert "windows_ad" not in families


# ---------------------------------------------------------------------------
# Real DC detection — must still work
# ---------------------------------------------------------------------------


class TestRealDcStillDetected:
    def test_full_dc_signature(self):
        """The .205 / .5 case: Kerberos + LDAP + SMB + RPC + RDP =
        full DC signature."""
        services = [
            _svc(53, "domain", "Simple DNS Plus"),
            _svc(88, "kerberos-sec", "Microsoft Windows Kerberos"),
            _svc(135, "msrpc", "Microsoft Windows RPC"),
            _svc(139, "netbios-ssn"),
            _svc(389, "ldap", "Microsoft Windows Active Directory LDAP"),
            _svc(445, "microsoft-ds"),
            _svc(3389, "ms-wbt-server"),
        ]
        families = _detect_device_families(services)
        assert "windows_ad" in families
        assert "windows" in families  # both — DC is also a Windows host

    def test_kerberos_alone_triggers_ad(self):
        services = [_svc(88, "kerberos-sec")]
        families = _detect_device_families(services)
        assert "windows_ad" in families

    def test_ldap_alone_triggers_ad(self):
        services = [_svc(389, "ldap")]
        families = _detect_device_families(services)
        assert "windows_ad" in families

    def test_ldaps_alone_triggers_ad(self):
        services = [_svc(636, "ldapssl")]
        families = _detect_device_families(services)
        assert "windows_ad" in families

    def test_global_catalog_triggers_ad(self):
        services = [_svc(3268, "msft-gc")]
        families = _detect_device_families(services)
        assert "windows_ad" in families

    def test_global_catalog_ssl_triggers_ad(self):
        services = [_svc(3269, "msft-gc-ssl")]
        families = _detect_device_families(services)
        assert "windows_ad" in families


# ---------------------------------------------------------------------------
# Non-AD-port-with-AD-banner — banner takes precedence
# ---------------------------------------------------------------------------


class TestAdBannerStillTriggers:
    """If a Windows host's banner explicitly says 'Active Directory'
    we still want AD checks. Banner is more reliable than port."""

    def test_smb_with_ad_banner_in_product(self):
        services = [_svc(389, "ldap", "Microsoft Windows Active Directory LDAP")]
        families = _detect_device_families(services)
        assert "windows_ad" in families
