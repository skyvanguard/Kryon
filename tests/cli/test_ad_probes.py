"""AD/Windows probes — SMB signing (NTLM-relay enabler) + WinRM exposure.

The SMB signing parse is unit-tested against crafted SMB2 NEGOTIATE responses
(can't assume a live Samba/Windows host); WinRM + the dispatch are graceful-checked."""

from __future__ import annotations

import kryon.cli.ad_probes as ad
from kryon.cli.ad_probes import _smb2_negotiate_packet, run_ad_probes
from kryon.cli.engage import DiscoveredService


def _fake_smb2_resp(security_mode: int) -> bytes:
    # NetBIOS(4) + SMB2 header(64, magic at 4) + body StructureSize(2) + SecurityMode(2) + pad
    return b"\x00\x00\x00\x4e" + b"\xfeSMB" + b"\x00" * 60 + b"\x41\x00" + security_mode.to_bytes(2, "little") + b"\x00" * 10


def test_smb2_negotiate_packet_well_formed():
    pkt = _smb2_negotiate_packet()
    assert int.from_bytes(pkt[1:4], "big") == len(pkt) - 4  # NetBIOS length matches payload
    assert pkt[4:8] == b"\xfeSMB"  # SMB2 magic


def test_smb_signing_not_required_detected(monkeypatch):
    # SecurityMode 0x0001 = SIGNING_ENABLED but NOT required → relayable.
    monkeypatch.setattr(ad, "_tcp", lambda *a, **k: _fake_smb2_resp(0x0001))
    svc = DiscoveredService(host="10.0.0.5", port=445, state="open", service="smb")
    f = ad._check_smb_signing(svc)
    assert f is not None and f.rule_id == "smb-signing-not-required"
    assert f.cwe == "CWE-287"


def test_smb_signing_required_no_finding(monkeypatch):
    # 0x0003 = SIGNING_ENABLED | SIGNING_REQUIRED → safe, no finding.
    monkeypatch.setattr(ad, "_tcp", lambda *a, **k: _fake_smb2_resp(0x0003))
    svc = DiscoveredService(host="10.0.0.5", port=445, state="open", service="smb")
    assert ad._check_smb_signing(svc) is None


def test_smb_signing_non_smb_response(monkeypatch):
    monkeypatch.setattr(ad, "_tcp", lambda *a, **k: b"not an smb response at all....................")
    svc = DiscoveredService(host="10.0.0.5", port=445, state="open", service="smb")
    assert ad._check_smb_signing(svc) is None


def test_run_ad_probes_graceful_on_dead_hosts():
    for port in (445, 5985, 5986, 139):
        svc = DiscoveredService(host="127.0.0.1", port=port, state="open", service="")
        assert isinstance(run_ad_probes(svc), list)  # never raises
