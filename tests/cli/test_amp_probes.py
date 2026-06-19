"""Batch L — UDP reflector / info-leak probes (open DNS resolver, memcached-UDP,
NetBIOS-NS, mDNS). UDP responses mocked; packet shape + graceful behavior checked.
"""

from __future__ import annotations

import kryon.cli.amp_probes as amp
from kryon.cli.amp_probes import _AMP_PROBES, _dns_query, run_amp_probes
from kryon.cli.engage import DiscoveredService

_DEAD = "127.0.0.1"


def _svc(port: int) -> DiscoveredService:
    return DiscoveredService(host=_DEAD, port=port, state="open", service="")


def test_run_amp_probes_graceful_on_dead_ports():
    for port in (53, 11211, 137, 5353):
        assert isinstance(run_amp_probes(_svc(port)), list)


def test_dispatch_table_well_formed():
    assert len(_AMP_PROBES) == 4
    for matches, probe in _AMP_PROBES:
        assert callable(matches) and callable(probe)


def test_dns_query_encoding():
    q = _dns_query("dns.google")
    assert q[:2] == b"\x13\x37" and q[2:4] == b"\x01\x00"  # id + RD flag
    assert b"\x03dns\x06google\x00" in q
    assert q[-4:] == b"\x00\x01\x00\x01"  # qtype A + class IN


def test_dns_open_resolver_detected(monkeypatch):
    # RA bit set (0x80), rcode 0, ancount 1.
    resp = b"\x13\x37\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + b"\x00" * 20
    monkeypatch.setattr(amp, "_udp", lambda *a, **k: resp)
    assert amp._check_dns_open_resolver(_svc(53)).rule_id == "dns-open-resolver"


def test_dns_no_recursion_returns_none(monkeypatch):
    # RA not set, ancount 0 → not an open resolver.
    resp = b"\x13\x37\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    monkeypatch.setattr(amp, "_udp", lambda *a, **k: resp)
    assert amp._check_dns_open_resolver(_svc(53)) is None


def test_memcached_udp_amplification(monkeypatch):
    monkeypatch.setattr(amp, "_udp", lambda *a, **k: b"\x00\x00\x00\x00\x00\x01\x00\x00STAT pid 123\r\n")
    f = amp._check_memcached_udp(_svc(11211))
    assert f is not None and f.severity == "HIGH" and f.rule_id == "memcached-udp-amplification"


def test_memcached_udp_silent_returns_none(monkeypatch):
    monkeypatch.setattr(amp, "_udp", lambda *a, **k: None)
    assert amp._check_memcached_udp(_svc(11211)) is None


def test_netbios_ns_exposed(monkeypatch):
    monkeypatch.setattr(amp, "_udp", lambda *a, **k: b"\xa2\x48\x84\x00\x00\x00\x00\x01" + b"\x00" * 40)
    assert amp._check_netbios_ns(_svc(137)).rule_id == "netbios-ns-exposed"


def test_netbios_wrong_transid_returns_none(monkeypatch):
    monkeypatch.setattr(amp, "_udp", lambda *a, **k: b"\xff\xff\x84\x00" + b"\x00" * 20)
    assert amp._check_netbios_ns(_svc(137)) is None


def test_mdns_exposed(monkeypatch):
    # QR response bit (0x80) set in flags byte 2.
    monkeypatch.setattr(amp, "_udp", lambda *a, **k: b"\x00\x00\x84\x00\x00\x00\x00\x01" + b"\x00" * 20)
    assert amp._check_mdns(_svc(5353)).rule_id == "mdns-exposed"


def test_mdns_query_not_response_returns_none(monkeypatch):
    monkeypatch.setattr(amp, "_udp", lambda *a, **k: b"\x00\x00\x00\x00\x00\x01\x00\x00" + b"\x00" * 20)
    assert amp._check_mdns(_svc(5353)) is None
