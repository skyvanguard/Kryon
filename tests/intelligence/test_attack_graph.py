"""Tests for the first-class attack-graph state."""

from __future__ import annotations

from kryon.intelligence.attack_graph import AttackGraph, Capability, graph_from_facts


def _chain() -> AttackGraph:
    g = AttackGraph()
    anon = Capability("access", "anonymous", "h1")
    secret = Capability("secret", "jwt_key", "h1")
    admin = Capability("token", "admin_jwt", "h1")
    rce = Capability("rce", "", "h1")
    assert g.add_edge(None, anon, "recon")
    assert g.add_edge(anon, secret, "dll_string_scan")
    assert g.add_edge(secret, admin, "forge_jwt")
    assert g.add_edge(admin, rce, "traversal_upload")
    return g


def test_confirmed_edges_build_capabilities():
    g = _chain()
    assert g.has_capability("secret", "jwt_key", "h1")
    assert g.has_capability("rce")
    assert len(g.edges()) == 4
    assert len(g.capabilities()) == 4


def test_unconfirmed_edge_is_rejected():
    g = AttackGraph()
    g.add_edge(None, Capability("access", "anon", "h"), "recon")
    added = g.add_edge(Capability("access", "anon", "h"), Capability("user", "x"), "guess", confirmed=False)
    assert added is False
    assert not g.has_capability("user", "x")


def test_impact_reached_and_paths():
    g = _chain()
    assert g.impact_reached() is True
    paths = g.impact_paths()
    assert len(paths) == 1
    assert len(paths[0]) == 4  # entry -> anon -> secret -> admin -> rce
    exploits = [e.exploit for e in paths[0]]
    assert exploits == ["recon", "dll_string_scan", "forge_jwt", "traversal_upload"]


def test_no_impact_when_only_recon():
    g = AttackGraph()
    g.add_edge(None, Capability("access", "anonymous", "h1"), "recon")
    assert g.impact_reached() is False
    assert g.impact_paths() == []


class _FakeFacts:
    hosts = ("10.0.0.1",)
    users = ("admin", "svc")
    creds = (("admin", "pw123"),)
    hashes = ("deadbeef",)
    domains = ("corp.local",)


def test_graph_from_facts_maps_capabilities():
    g = graph_from_facts(_FakeFacts())
    assert g.has_capability("access", "recon", "10.0.0.1")
    assert g.has_capability("user", "admin")
    assert g.has_capability("user", "svc")
    assert g.has_capability("cred", "admin")
    assert g.has_capability("secret", "hash")
    assert g.has_capability("domain", "corp.local")


def test_graph_from_facts_empty_is_safe():
    class _Empty:
        pass

    g = graph_from_facts(_Empty())
    assert g.capabilities() == []
    assert "No capabilities" in g.summary_for_prompt()


def test_summary_for_prompt():
    g = AttackGraph()
    assert "No capabilities" in g.summary_for_prompt()
    g.add_edge(None, Capability("secret", "aws_key", "h1"), "leak")
    s = g.summary_for_prompt()
    assert "secret=aws_key@h1" in s
    assert "Impact reached: False" in s
