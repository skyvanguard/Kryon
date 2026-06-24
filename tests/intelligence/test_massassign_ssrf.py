"""The remaining Rabbit Store chain pieces, built general: mass-assignment registration (CWE-915) →
privileged account+JWT, and SSRF over URL-fetching endpoints (CWE-918) → internal API discovery.
Payload/endpoint-driven like the eval/LFI/SSTI rules; THM Rabbit Store's {"subscription":"active"}
register + /api/store-url SSRF are covered by the general field/endpoint lists, not hardcoded."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_mass_assignment_register,
    _rule_ssrf_internal_probe,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEB = ExtractedFacts(services=((80, "http"),), hosts=("cloudsite.thm",), paths=("/login", "/register"))


def test_mass_assignment_adds_privilege_fields():
    rec = _rule_mass_assignment_register(_WEB, [], "")
    assert rec is not None
    for field in ("subscription", "isAdmin", "role", "activated", "verified"):
        assert field in rec.args
    assert "/api/register" in rec.args and "REGISTER-PRIV" in rec.args


def test_mass_assignment_abstains_with_creds_or_no_surface():
    assert _rule_mass_assignment_register(ExtractedFacts(services=((80, "http"),), creds=(("a", "b"),), paths=("/x",)), [], "") is None
    assert _rule_mass_assignment_register(ExtractedFacts(services=((80, "http"),), hosts=("x",)), [], "") is None


def test_ssrf_probes_internal_targets_and_harvests_routes():
    rec = _rule_ssrf_internal_probe(_WEB, [], "")
    assert rec is not None
    assert "127.0.0.1" in rec.args and "169.254.169.254" in rec.args  # localhost + cloud metadata
    assert "store-url" in rec.args and "SSRF-HIT" in rec.args
    assert "/api/" in rec.args  # harvests internal routes


def test_both_abstain_once_run():
    assert _rule_mass_assignment_register(_WEB, ["[REGISTER-PRIV ...]"], "") is None
    assert _rule_ssrf_internal_probe(_WEB, [": ssrf_probe [SSRF-HIT ...]"], "") is None


def test_ssrf_abstains_without_web():
    assert _rule_ssrf_internal_probe(ExtractedFacts(hosts=("x",), paths=("/a",)), [], "") is None
