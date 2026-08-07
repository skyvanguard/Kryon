"""Probe registry — gates, scheme resolution, dispatch, and module resolution."""

from __future__ import annotations

import kryon.cli.probe_registry as pr
from kryon.cli.engage import DiscoveredService


def _svc(port: int, service: str = "") -> DiscoveredService:
    return DiscoveredService(host="10.0.0.1", port=port, state="open", service=service)


def test_all_registry_modules_resolve():
    resolved = pr._resolve()
    assert len(resolved) == len(pr._REGISTRY) == 14  # every probe module wires up


def test_gates():
    assert pr._is_http(_svc(80)) and pr._is_http(_svc(443)) and pr._is_http(_svc(8080))
    assert not pr._is_http(_svc(22))
    assert pr._is_ssh(_svc(22)) and pr._is_ssh(_svc(2222)) and pr._is_ssh(_svc(0, "ssh"))
    assert pr._is_tls(_svc(443)) and pr._is_tls(_svc(993)) and not pr._is_tls(_svc(80))
    assert pr._is_vpn(_svc(443)) and pr._is_vpn(_svc(10443)) and not pr._is_vpn(_svc(80))
    assert all(pr._always(_svc(p)) for p in (1, 80, 9999))


def test_scheme_for():
    assert pr.scheme_for(_svc(443)) == "https"
    assert pr.scheme_for(_svc(8443)) == "https"
    assert pr.scheme_for(_svc(4443)) == "https"  # vpn port forced https
    assert pr.scheme_for(_svc(5001)) == "https"  # infra (docker registry TLS)
    assert pr.scheme_for(_svc(80)) == "http"
    assert pr.scheme_for(_svc(0, "https")) == "https"


def test_dispatch_passes_scheme_correctly(monkeypatch):
    calls = []

    def fake_scheme_runner(svc, scheme):
        calls.append(("scheme", svc.port, scheme))
        return [f"finding-{svc.port}"]

    def fake_plain_runner(svc):
        calls.append(("plain", svc.port))
        return []

    # Replace the resolved table with two fakes (one scheme-taking, one not).
    monkeypatch.setattr(pr, "_RESOLVED", [
        (pr._Entry("x", "f", pr._is_http, True), fake_scheme_runner),
        (pr._Entry("y", "g", pr._always, False), fake_plain_runner),
    ])
    out = pr.run_all_probes(_svc(443))
    assert ("scheme", 443, "https") in calls   # scheme runner got https
    assert ("plain", 443) in calls             # plain runner called without scheme
    assert out == ["finding-443"]


def test_gate_blocks_non_matching(monkeypatch):
    called = []
    monkeypatch.setattr(pr, "_RESOLVED", [
        (pr._Entry("x", "f", pr._is_http, False), lambda s: called.append(s.port) or []),
    ])
    pr.run_all_probes(_svc(22))  # not http → gate blocks
    assert called == []


def test_runner_exception_isolated(monkeypatch):
    def boom(svc):
        raise RuntimeError("probe crashed")

    monkeypatch.setattr(pr, "_RESOLVED", [
        (pr._Entry("bad", "f", pr._always, False), boom),
        (pr._Entry("good", "g", pr._always, False), lambda s: ["ok"]),
    ])
    assert pr.run_all_probes(_svc(80)) == ["ok"]  # one crash doesn't kill the rest


def test_run_all_probes_graceful_on_dead_host():
    # Real probes against a closed port → empty list, never raises.
    assert isinstance(pr.run_all_probes(_svc(9)), list)


def test_run_all_probes_deadline_abandons_hung_probe(monkeypatch):
    """R1: a hung probe must NOT block the whole sweep. run_all_probes returns
    within the wall-clock deadline and keeps the findings that DID complete —
    same failure class as the 180s compliance hang, now bounded."""
    import time

    def fast(svc):
        return ["fast-finding"]

    def hung(svc):
        time.sleep(10)  # simulates a slowloris peer holding the socket open
        return ["never"]

    monkeypatch.setattr(pr, "_RESOLVED", [
        (pr._Entry("fast", "f", pr._always, False), fast),
        (pr._Entry("hung", "g", pr._always, False), hung),
    ])
    monkeypatch.setenv("KRYON_PROBE_DEADLINE_S", "1")

    t0 = time.monotonic()
    out = pr.run_all_probes(_svc(80))
    elapsed = time.monotonic() - t0

    assert elapsed < 5.0, f"run_all_probes blocked {elapsed:.1f}s on the hung probe"
    assert "fast-finding" in out   # fast probe's finding collected before the deadline
    assert "never" not in out      # hung probe abandoned, not awaited
