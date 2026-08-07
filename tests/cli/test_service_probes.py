"""Deterministic service-probe detectors (gap-closers: Redis/Mongo/Elastic no-auth,
SNMP, FTP, RDP, VNC, rsync, Postgres-trust, NTP, LDAP, Telnet, SMTP).

The probes are network-touching, so unit tests pin the two invariants that must hold
without a live service: (1) every probe degrades gracefully (None/[] — never raises)
when the target is unreachable, and (2) the dispatch routes each service/port to the
right detector. The positive path (true-positive + no-false-positive) is verified
live against a real Redis in the build (see commit message)."""

from __future__ import annotations

import pytest

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import (
    PROBES,
    _f,
    run_service_probes,
)

# Loopback + a closed port → TCP refuses instantly (fast), so the graceful path is
# exercised without 4s connect-timeouts per probe. (UDP probes still wait, but few.)
_DEAD = "127.0.0.1"


@pytest.mark.parametrize("name, _matcher, probe", PROBES, ids=[p[0] for p in PROBES])
def test_probe_is_graceful_on_unreachable_host(name, _matcher, probe):
    svc = DiscoveredService(host=_DEAD, port=9, state="open", service=name)
    # Must return None (or []) and never raise, even with the service hint set.
    result = probe(svc)
    assert result is None or result == [] or isinstance(result, list)


def test_run_service_probes_never_raises_and_returns_list():
    for port in (6379, 27017, 9200, 21, 161, 23, 5900, 873, 3389, 5432, 123, 25, 389, 80):
        svc = DiscoveredService(host=_DEAD, port=port, state="open", service="")
        out = run_service_probes(svc)
        assert isinstance(out, list)  # graceful, no exception


@pytest.mark.parametrize(
    "port, expected_rule_substr",
    [
        (6379, "redis"),
        (9200, "elasticsearch"),
        (21, "ftp"),
        (161, "snmp"),
        (23, "telnet"),
        (873, "rsync"),
        (3389, "rdp"),
        (5432, "postgres"),
        (389, "ldap"),
        (111, "nfs"),
        (1433, "mssql"),
    ],
)
def test_dispatch_matches_port_to_detector(port, expected_rule_substr):
    # The matcher for the expected service must fire for its canonical port.
    fired = [
        name for name, matches, _ in PROBES if matches(DiscoveredService(host="x", port=port, state="open", service=""))
    ]
    assert any(expected_rule_substr in name for name in fired), (
        f"port {port} not routed to {expected_rule_substr}: {fired}"
    )


def test_finding_helper_shape():
    svc = DiscoveredService(host="10.0.0.5", port=6379, state="open", service="redis")
    f = _f(svc, "CWE-306", "CRITICAL", "redis-noauth", "msg", "evidence", "fix it")
    assert isinstance(f, Finding)
    assert f.host == "10.0.0.5:6379"
    assert f.cwe == "CWE-306" and f.severity == "CRITICAL"
    assert f.severity_rank == 0  # CRITICAL ranks first


def test_telnet_matcher_does_not_catch_web():
    # A plain web port (80) must NOT trigger telnet/redis/etc.
    fired = [
        name
        for name, matches, _ in PROBES
        if matches(DiscoveredService(host="x", port=80, state="open", service="http"))
    ]
    assert fired == [], f"web port 80 wrongly routed to: {fired}"


def test_nfs_cred_regex_catches_creds_not_prose():
    from kryon.cli.service_probes import _NFS_CRED_RE

    blob = (
        "ftp creds :\nftpuser:W3stV1rg1n14M0un741nM4m4\npassword = hunter2\n"
        "just a normal sentence here\n-----BEGIN OPENSSH PRIVATE KEY-----"
    )
    hits = [m.group(0).strip() for m in _NFS_CRED_RE.finditer(blob)]
    assert "ftpuser:W3stV1rg1n14M0un741nM4m4" in hits  # THM Hijack's leaked FTP cred
    assert any("password" in h for h in hits) and any("PRIVATE KEY" in h for h in hits)
    assert "just a normal sentence here" not in hits


def test_nfs_loot_exports_extracts_secret(monkeypatch):
    """The Hijack gap: a detect-only NFS check left the FTP creds (in a 0700 file owned by a service UID)
    on the table. The auto-exploit must enumerate the export and surface the UID-spoofed credential."""
    import kryon.cli.service_probes as sp

    monkeypatch.setattr(sp, "_nfs_enum_exports", lambda host: ["/mnt/share"])
    monkeypatch.setattr(
        sp,
        "_nfs_loot_export",
        lambda host, exp: [("for_employees.txt", "ftp creds :\nftpuser:W3stV1rg1n14M0un741nM4m4")],
    )
    out = sp._nfs_loot_exports(DiscoveredService(host="10.0.0.5", port=111, state="open", service="rpcbind"))
    rules = [f.rule_id for f in out]
    assert "nfs-exports-listed" in rules
    secret = [f for f in out if f.rule_id == "nfs-readable-secret"]
    assert secret and "ftpuser:W3stV1rg1n14M0un741nM4m4" in secret[0].message


def test_nfs_loot_exports_empty_without_exports(monkeypatch):
    import kryon.cli.service_probes as sp

    monkeypatch.setattr(sp, "_nfs_enum_exports", lambda host: [])
    assert sp._nfs_loot_exports(DiscoveredService(host="x", port=111, state="open", service="rpcbind")) == []


def _rdp_resp(selected_protocol: int) -> bytes:
    """Craft a minimal RDP X.224 negotiation response: TPKT header 0x0300,
    type byte 0x02 at offset 11, selectedProtocol low byte at offset 15."""
    b = bytearray(b"\x03\x00" + b"\x00" * 14)  # len 16
    b[11] = 0x02
    b[15] = selected_protocol
    return bytes(b)


@pytest.mark.parametrize(
    "proto,expect_finding",
    [
        (0, True),  # standard security — no NLA
        (1, True),  # TLS-only — STILL no NLA (the false-negative the fix closes)
        (2, False),  # CredSSP/NLA
        (8, False),  # HYBRID_EX — NLA
    ],
)
def test_rdp_nla_detection_requires_protocol_ge_2(monkeypatch, proto, expect_finding):
    import kryon.cli.service_probes as sp

    monkeypatch.setattr(sp, "_tcp", lambda host, port, payload, n: _rdp_resp(proto))
    svc = DiscoveredService(host="10.0.0.9", port=3389, state="open", service="ms-wbt-server")
    finding = sp._check_rdp(svc)
    if expect_finding:
        assert finding is not None and finding.rule_id == "rdp-no-nla"
    else:
        assert finding is None or finding.rule_id != "rdp-no-nla"
