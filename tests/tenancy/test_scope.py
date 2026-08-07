"""F146 — Multi-tenancy + scope tests."""

from __future__ import annotations

import json
from pathlib import Path

from kryon.tenancy import (
    ScopePolicy,
    TenantContext,
    is_target_in_scope,
    load_scope_policy,
    namespaced_engagement_id,
    namespaced_path,
)

# ---------------------------------------------------------------------------
# TenantContext
# ---------------------------------------------------------------------------


def test_tenant_slug_normalises():
    assert TenantContext("Example Bank S.A.").slug == "Example_Bank_S_A"


def test_empty_tenant_falls_back_to_default():
    assert TenantContext("").slug == "default"


# ---------------------------------------------------------------------------
# Scope matching
# ---------------------------------------------------------------------------


def test_target_matches_literal():
    policy = ScopePolicy(tenant_id="t", allowed_targets=("x.com",))
    ok, _ = is_target_in_scope("x.com", policy)
    assert ok is True


def test_target_matches_glob():
    policy = ScopePolicy(tenant_id="t", allowed_targets=("*.example.com",))
    ok, _ = is_target_in_scope("app.example.com", policy)
    assert ok is True


def test_target_matches_cidr():
    policy = ScopePolicy(tenant_id="t", allowed_targets=("192.0.2.0/24",))
    ok, reason = is_target_in_scope("192.0.2.50", policy)
    assert ok is True


def test_target_blocked_wins_over_allowed():
    policy = ScopePolicy(
        tenant_id="t",
        allowed_targets=("*.x.com",),
        blocked_targets=("api.x.com",),
    )
    ok, reason = is_target_in_scope("api.x.com", policy)
    assert ok is False
    assert "blocked" in reason


def test_default_deny_rejects_unlisted():
    policy = ScopePolicy(tenant_id="t", allowed_targets=("x.com",), default_deny=True)
    ok, reason = is_target_in_scope("z.com", policy)
    assert ok is False
    assert "default_deny" in reason


def test_default_allow_lets_unlisted_through():
    policy = ScopePolicy(tenant_id="t", allowed_targets=("x.com",), default_deny=False)
    ok, _ = is_target_in_scope("z.com", policy)
    assert ok is True


def test_no_policy_allows_everything():
    ok, reason = is_target_in_scope("anything.com", None)
    assert ok is True
    assert "no scope policy" in reason


def test_cidr_outside_range_rejected():
    policy = ScopePolicy(tenant_id="t", allowed_targets=("10.0.0.0/8",), default_deny=True)
    ok, _ = is_target_in_scope("192.168.1.1", policy)
    assert ok is False


# ---------------------------------------------------------------------------
# load_scope_policy
# ---------------------------------------------------------------------------


def _write_policy(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_load_missing_returns_none(tmp_path):
    assert load_scope_policy("example", path=tmp_path / "no.json") is None


def test_load_parses_tenant_block(tmp_path):
    p = tmp_path / "scope.json"
    _write_policy(
        p,
        {
            "tenants": {
                "example": {
                    "allowed_targets": ["www.example.com"],
                    "blocked_targets": ["www.competitor.com"],
                }
            },
            "default_deny": True,
        },
    )
    pol = load_scope_policy("example", path=p)
    assert pol is not None
    assert "www.example.com" in pol.allowed_targets
    assert pol.default_deny is True


def test_load_unknown_tenant_returns_empty_lists(tmp_path):
    p = tmp_path / "scope.json"
    _write_policy(p, {"tenants": {"other": {"allowed_targets": ["x"]}}, "default_deny": True})
    pol = load_scope_policy("example", path=p)
    assert pol is not None
    assert pol.allowed_targets == ()
    assert pol.default_deny is True


def test_load_malformed_returns_none(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text("not json", encoding="utf-8")
    assert load_scope_policy("example", path=p) is None


# ---------------------------------------------------------------------------
# Namespacing
# ---------------------------------------------------------------------------


def test_namespaced_engagement_id_with_tenant():
    tc = TenantContext("example")
    assert namespaced_engagement_id("eng-1", tenant=tc) == "example/eng-1"


def test_namespaced_engagement_id_without_tenant():
    assert namespaced_engagement_id("eng-1", tenant=None) == "eng-1"
    assert namespaced_engagement_id("eng-1", tenant=TenantContext("")) == "eng-1"


def test_namespaced_path_with_tenant():
    base = Path(".kryon") / "audit"
    out = namespaced_path(base, tenant=TenantContext("example"))
    assert out == base / "example"


def test_namespaced_path_without_tenant():
    base = Path(".kryon") / "audit"
    assert namespaced_path(base, tenant=None) == base
