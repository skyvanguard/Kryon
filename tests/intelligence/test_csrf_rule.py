"""CSRF state-change rule (CWE-352).

Unlike the read-only disclosure proofs, CSRF proof REQUIRES a state change — so this reads the
current value, performs the cross-origin no-token POST (the attack), confirms the state changed, and
RESTORES the original (reversible, non-destructive). It reuses the ecosystem session cookie
(/tmp/loot_jwt). This is a mutation → offensive profile / authorized targets only. Validated shape
against OWASP Juice Shop's /profile (cookie-auth, no Origin check, no CSRF token).
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_csrf_state_change
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEB = ExtractedFacts(services=((80, "http"),), hosts=("shop.thm",), paths=("/profile",))


def test_csrf_closes_state_change_proof():
    rec = _rule_csrf_state_change(_WEB, [], "")
    assert rec is not None
    assert "CSRF-STATECHANGE" in rec.args
    # reuses the ecosystem session cookie (cred-reuse/mass-assign saved it)
    assert "/tmp/loot_jwt" in rec.args
    # the attack: cross-origin POST from an external Origin, no CSRF token
    assert "Origin:" in rec.args and "evil" in rec.args.lower()
    assert "username=" in rec.args  # state-changing field
    # reversible: the original value is restored (non-destructive proof)
    assert "$ORIG" in rec.args
    assert "restaurado" in rec.args.lower()
    # target endpoint + guards
    assert "/profile" in rec.args
    assert "<target>" not in rec.args
    assert "shop.thm" in rec.args
    assert "|| true" in rec.args


def test_csrf_abstains_without_web_or_surface():
    assert _rule_csrf_state_change(ExtractedFacts(hosts=("x",), paths=("/profile",)), [], "") is None
    assert _rule_csrf_state_change(ExtractedFacts(services=((80, "http"),), hosts=("x",)), [], "") is None
    assert _rule_csrf_state_change(_WEB, ["csrf_probe ran"], "") is None
