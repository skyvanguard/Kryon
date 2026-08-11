"""Tests for attack-path synthesis (proven graph from confirmed evidence)."""

from __future__ import annotations

import json
from types import SimpleNamespace

from kryon.cli.engage import make_finding
from kryon.intelligence.attack_graph import AttackGraph, Capability
from kryon.intelligence.attack_path import (
    add_confirmed_validation,
    build_attack_graph,
    confirmed_validation_finding,
    format_attack_paths,
    is_proven,
    plan_path_pursuit,
    populate_attack_graph,
)


class TestConfirmedValidationFinding:
    """confirmed_validation_finding — the live finding descriptor a validate_*
    confirmation streams to a front-end. Shares add_confirmed_validation's gate."""

    def test_confirmed_sqli_is_critical_impact(self):
        vf = confirmed_validation_finding("validate_sqli", _vres("confirmed"), host="10.0.0.1")
        assert vf == {
            "severity": "CRITICAL",  # sqli → db_takeover reaches impact
            "detail": "sqli-dump confirmado (validate_sqli)",
            "cwe": "CWE-89",
            "location": "10.0.0.1",
            "verified": True,
        }

    def test_confirmed_xss_is_high_not_impact(self):
        vf = confirmed_validation_finding("validate_xss", _vres("confirmed"))
        assert vf is not None
        assert vf["severity"] == "HIGH"  # session_risk is not an IMPACT kind
        assert vf["cwe"] == "CWE-79"

    def test_confirmed_rce_and_auth_bypass_are_critical(self):
        assert confirmed_validation_finding("validate_rce", _vres("confirmed"))["severity"] == "CRITICAL"
        assert confirmed_validation_finding("validate_auth_bypass", _vres("confirmed"))["severity"] == "CRITICAL"

    def test_unconfirmed_verdict_is_none(self):
        assert confirmed_validation_finding("validate_sqli", _vres("not_confirmed")) is None
        assert confirmed_validation_finding("validate_sqli", _vres("")) is None

    def test_non_validation_tool_is_none(self):
        assert confirmed_validation_finding("nmap", _vres("confirmed")) is None
        assert confirmed_validation_finding("", _vres("confirmed")) is None
        assert confirmed_validation_finding(None, _vres("confirmed")) is None

    def test_unparseable_output_is_none(self):
        assert confirmed_validation_finding("validate_sqli", "garbage not json") is None

    def test_stays_in_lockstep_with_graph_edge(self):
        # Whenever the finding fires, the graph edge is added too (same gate).
        for tool in ("validate_sqli", "validate_rce", "validate_xss", "validate_auth_bypass"):
            vf = confirmed_validation_finding(tool, _vres("confirmed"))
            g = AttackGraph()
            added = add_confirmed_validation(g, tool, _vres("confirmed"))
            assert (vf is not None) == added


def _vres(status: str) -> str:
    return json.dumps({"validation_status": status, "exploit_proof": "p", "validation_method": "m", "details": ""})


def _f(cwe: str, *, level: str = "confirmed", host: str = "t", needs_verif: bool = False):
    f = make_finding(cwe=cwe, severity="HIGH", host=host, rule_id="r", message=f"{cwe} on {host}", evidence="ev")
    f.verification_level = level
    f.needs_verification = needs_verif
    return f


def _facts(**kw):
    base = dict(hosts=(), users=(), creds=(), hashes=(), domains=(), hints=(), services=(), paths=(), versions=())
    base.update(kw)
    return SimpleNamespace(**base)


# ── validate-each-link gate ──────────────────────────────────────────────────


def test_is_proven_only_confirmed():
    assert is_proven(_f("CWE-89", level="confirmed")) is True
    assert is_proven(_f("CWE-89", level="judge-confirmed")) is True
    assert is_proven(_f("CWE-89", level="inferred", needs_verif=True)) is False
    assert is_proven(_f("CWE-89", level="heuristic", needs_verif=True)) is False
    assert is_proven(_f("CWE-89", level="confirmed", needs_verif=True)) is False  # needs_verif overrides


def test_inferred_finding_creates_no_edge():
    g = build_attack_graph(_facts(hosts=("t",)), [_f("CWE-89", level="inferred", needs_verif=True)])
    assert g.impact_reached() is False  # unproven → no db_takeover edge


# ── single-hop proven impact ─────────────────────────────────────────────────


def test_confirmed_sqli_reaches_db_takeover():
    g = build_attack_graph(_facts(hosts=("t",)), [_f("CWE-89")])
    assert g.impact_reached() is True
    assert g.has_capability("db_takeover")
    md = format_attack_paths(g)
    assert "db_takeover" in md and "sqli-dump" in md


def test_confirmed_rce_variants():
    for cwe, kind in [("CWE-78", "rce"), ("CWE-434", "rce"), ("CWE-502", "rce"), ("CWE-22", "data_exfil")]:
        g = build_attack_graph(_facts(hosts=("t",)), [_f(cwe)])
        assert g.has_capability(kind), cwe


# ── the low+low→critical chain ───────────────────────────────────────────────


def test_info_leak_plus_idor_chains_to_account_takeover():
    # CWE-200 (info, low) + CWE-639 (IDOR) → access→info→account_takeover
    g = build_attack_graph(_facts(hosts=("t",)), [_f("CWE-639"), _f("CWE-200")])
    assert g.has_capability("account_takeover")
    assert g.has_capability("info")
    md = format_attack_paths(g)
    assert "account_takeover" in md
    assert "low+low→critical" in md  # the chain traverses 2 confirmed exploits


def test_idor_alone_is_single_hop_not_chained():
    g = build_attack_graph(_facts(hosts=("t",)), [_f("CWE-639")])
    md = format_attack_paths(g)
    assert "account_takeover" in md
    assert "low+low→critical" not in md  # only one exploit edge


# ── facts-level chains (AD / privesc / hints) ────────────────────────────────


def test_creds_plus_domain_chains_to_admin():
    g = build_attack_graph(_facts(hosts=("dc",), creds=(("svc", "pw"),), domains=("corp.local",)), [])
    assert g.has_capability("admin")
    md = format_attack_paths(g)
    assert "admin" in md and "secretsdump" in md.lower()


def test_privesc_hint_reaches_root():
    g = build_attack_graph(_facts(hosts=("h",), hints=("privesc:sudo-nopasswd:vim",)), [])
    assert g.has_capability("root")


def test_sqli_confirmed_hint_reaches_db():
    g = build_attack_graph(_facts(hosts=("h",), hints=("sqli-confirmed",)), [])
    assert g.has_capability("db_takeover")


# ── robustness ───────────────────────────────────────────────────────────────


def test_empty_is_safe():
    g = build_attack_graph(None, [])
    assert g.impact_reached() is False
    assert format_attack_paths(g) == ""


def test_host_derived_from_findings_when_no_facts():
    g = build_attack_graph(None, [_f("CWE-89", host="web")])
    assert g.has_capability("db_takeover")


def test_unmapped_cwe_ignored():
    g = build_attack_graph(_facts(hosts=("t",)), [_f("CWE-99999")])
    assert g.impact_reached() is False


# ── v2 live confirm-then-add-edge ────────────────────────────────────────────


class TestLiveConfirmation:
    def test_confirmed_sqli_adds_impact_edge_live(self):
        g = AttackGraph()
        added = add_confirmed_validation(g, "validate_sqli", _vres("confirmed"))
        assert added is True
        assert g.has_capability("db_takeover")
        assert g.impact_reached() is True
        # the edge is tagged as live-validated + reachable from ENTRY (path exists)
        assert format_attack_paths(g)
        assert "live-validated" in format_attack_paths(g)

    def test_false_positive_adds_no_edge(self):
        g = AttackGraph()
        assert add_confirmed_validation(g, "validate_sqli", _vres("false_positive")) is False
        assert g.impact_reached() is False

    def test_potential_adds_no_edge(self):
        g = AttackGraph()
        assert add_confirmed_validation(g, "validate_rce", _vres("potential")) is False

    def test_rce_and_auth_bypass_map_correctly(self):
        g = AttackGraph()
        add_confirmed_validation(g, "validate_rce", _vres("confirmed"))
        add_confirmed_validation(g, "validate_auth_bypass", _vres("confirmed"))
        assert g.has_capability("rce") and g.has_capability("admin")

    def test_non_validation_tool_is_noop(self):
        g = AttackGraph()
        assert add_confirmed_validation(g, "run_command", "uid=0(root)") is False
        assert add_confirmed_validation(g, "nmap", _vres("confirmed")) is False

    def test_unparseable_output_is_noop(self):
        g = AttackGraph()
        assert add_confirmed_validation(g, "validate_sqli", "not json at all") is False

    def test_grows_seeded_graph_without_clobbering(self):
        # seed with a confirmed IDOR (account_takeover), then a live SQLi lands
        g = build_attack_graph(_facts(hosts=("t",)), [_f("CWE-639")])
        assert g.has_capability("account_takeover")
        add_confirmed_validation(g, "validate_sqli", _vres("confirmed"))
        # both survive
        assert g.has_capability("account_takeover") and g.has_capability("db_takeover")


class TestIdempotency:
    def test_populate_twice_no_duplicate_edges(self):
        g = AttackGraph()
        facts = _facts(hosts=("t",))
        findings = [_f("CWE-89"), _f("CWE-200"), _f("CWE-639")]
        populate_attack_graph(g, facts, findings)
        n1 = len(g.edges())
        populate_attack_graph(g, facts, findings)  # re-fold same evidence
        assert len(g.edges()) == n1  # add_edge dedups identical (src,dst,exploit)

    def test_add_edge_dedups_identical(self):
        from kryon.intelligence.attack_graph import Capability

        g = AttackGraph()
        a, b = Capability("access", "", "h"), Capability("rce", "", "h")
        assert g.add_edge(a, b, "x") is True
        assert g.add_edge(a, b, "x") is False  # identical → rejected
        assert len(g.edges()) == 1


# ── v3 goal-directed path-pursuit ────────────────────────────────────────────


class TestPathPursuit:
    def _access(self):
        g = AttackGraph()
        g.add_edge(None, Capability("access", "recon", "t"), "recon")
        return g

    def test_empty_when_impact_reached(self):
        g = self._access()
        g.add_edge(Capability("access", "recon", "t"), Capability("rce", "", "t"), "cmd-inj")
        assert plan_path_pursuit(g) == ""  # already won → nothing to pursue

    def test_access_only_names_a_one_hop_impact(self):
        out = plan_path_pursuit(self._access())
        assert out.startswith("🎯 Path-pursuit")
        assert "1 step" in out and "NEXT LINK to prove" in out

    def test_leverages_held_info_for_idor(self):
        # holding a leaked `info` cap → pursuit prefers info→account_takeover (IDOR)
        g = self._access()
        g.add_edge(Capability("access", "recon", "t"), Capability("info", "", "t"), "info-exposure")
        out = plan_path_pursuit(g)
        assert "account_takeover" in out
        assert "from `info`" in out and "idor" in out.lower()

    def test_leverages_held_cred_for_admin(self):
        g = self._access()
        g.add_edge(Capability("access", "recon", "t"), Capability("cred", "svc", "t"), "credential-capture")
        out = plan_path_pursuit(g)
        assert "from `cred`" in out and "admin" in out

    def test_deterministic(self):
        g1 = self._access()
        g1.add_edge(Capability("access", "recon", "t"), Capability("info", "", "t"), "info-exposure")
        g2 = self._access()
        g2.add_edge(Capability("access", "recon", "t"), Capability("info", "", "t"), "info-exposure")
        assert plan_path_pursuit(g1) == plan_path_pursuit(g2)

    def test_empty_graph_still_pursues_from_entry_access(self):
        # even a bare graph implies `access` (ENTRY) → a 1-hop impact objective
        assert plan_path_pursuit(AttackGraph()).startswith("🎯 Path-pursuit")


# ── v4: XSS impact edge + operator-selectable target ─────────────────────────


class TestV4:
    def test_confirmed_xss_is_session_risk_not_impact(self):
        # honest: confirmed XSS grants session_risk but is NOT a proven impact
        g = build_attack_graph(_facts(hosts=("t",)), [_f("CWE-79")])
        assert g.has_capability("session_risk")
        assert g.has_capability("account_takeover") is False
        assert g.impact_reached() is False

    def test_validate_xss_grows_graph_live_non_impact(self):
        g = AttackGraph()
        assert add_confirmed_validation(g, "validate_xss", _vres("confirmed")) is True
        assert g.has_capability("session_risk")
        assert g.impact_reached() is False

    def test_cwe_79_is_not_exploitable(self):
        from kryon.intelligence.attack_path import cwe_reaches_impact

        assert cwe_reaches_impact("CWE-79") is False  # reflection ≠ proven impact

    def test_operator_target_pins_impact(self):
        g = AttackGraph()
        g.add_edge(None, Capability("access", "recon", "t"), "recon")
        g.add_edge(Capability("access", "recon", "t"), Capability("info", "", "t"), "info-exposure")
        # nearest would be account_takeover (from info); pinning rce redirects
        assert "rce" in plan_path_pursuit(g, target="rce")
        assert "account_takeover" in plan_path_pursuit(g)

    def test_unknown_target_is_empty(self):
        g = AttackGraph()
        g.add_edge(None, Capability("access", "recon", "t"), "recon")
        assert plan_path_pursuit(g, target="not-an-impact") == ""

    def test_pinned_target_still_pursued_when_another_impact_reached(self):
        # C3: admin already reached, but operator pins rce (not yet proven) →
        # must STILL emit a pursuit objective, not "" because impact_reached().
        g = AttackGraph()
        g.add_edge(None, Capability("access", "recon", "t"), "recon")
        g.add_edge(Capability("access", "recon", "t"), Capability("admin", "", "t"), "auth-bypass")
        assert g.impact_reached() is True
        assert "rce" in plan_path_pursuit(g, target="rce")  # pinned goal not reached
        assert plan_path_pursuit(g, target="admin") == ""  # pinned goal reached → done
        assert plan_path_pursuit(g) == ""  # no pin + impact reached → done
