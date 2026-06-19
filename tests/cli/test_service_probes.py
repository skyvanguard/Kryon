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
    ],
)
def test_dispatch_matches_port_to_detector(port, expected_rule_substr):
    # The matcher for the expected service must fire for its canonical port.
    fired = [name for name, matches, _ in PROBES if matches(DiscoveredService(host="x", port=port, state="open", service=""))]
    assert any(expected_rule_substr in name for name in fired), f"port {port} not routed to {expected_rule_substr}: {fired}"


def test_finding_helper_shape():
    svc = DiscoveredService(host="10.0.0.5", port=6379, state="open", service="redis")
    f = _f(svc, "CWE-306", "CRITICAL", "redis-noauth", "msg", "evidence", "fix it")
    assert isinstance(f, Finding)
    assert f.host == "10.0.0.5:6379"
    assert f.cwe == "CWE-306" and f.severity == "CRITICAL"
    assert f.severity_rank == 0  # CRITICAL ranks first


def test_telnet_matcher_does_not_catch_web():
    # A plain web port (80) must NOT trigger telnet/redis/etc.
    fired = [name for name, matches, _ in PROBES if matches(DiscoveredService(host="x", port=80, state="open", service="http"))]
    assert fired == [], f"web port 80 wrongly routed to: {fired}"
