"""Tests for scope enforcement guardrails."""

from __future__ import annotations

import pytest

from kryon.agents.scope import ScopeEnforcer, ScopeRule


class TestScopeEnforcer:
    """Test ScopeEnforcer target validation."""

    def _make_enforcer(self, rules: list[dict]) -> ScopeEnforcer:
        return ScopeEnforcer([ScopeRule(**r) for r in rules])

    def test_cidr_match(self):
        enforcer = self._make_enforcer([{"rule_type": "cidr", "value": "10.0.0.0/24"}])
        allowed, reason = enforcer.is_allowed("10.0.0.50")
        assert allowed is True
        assert reason is None

    def test_cidr_no_match(self):
        enforcer = self._make_enforcer([{"rule_type": "cidr", "value": "10.0.0.0/24"}])
        allowed, reason = enforcer.is_allowed("192.168.1.1")
        assert allowed is False
        assert "not in scope" in reason

    def test_domain_exact_match(self):
        enforcer = self._make_enforcer([{"rule_type": "domain", "value": "example.com"}])
        allowed, _ = enforcer.is_allowed("example.com")
        assert allowed is True

    def test_domain_subdomain_match(self):
        enforcer = self._make_enforcer([{"rule_type": "domain", "value": "example.com"}])
        allowed, _ = enforcer.is_allowed("sub.example.com")
        assert allowed is True

    def test_domain_no_match(self):
        enforcer = self._make_enforcer([{"rule_type": "domain", "value": "example.com"}])
        allowed, reason = enforcer.is_allowed("evil.com")
        assert allowed is False

    def test_ip_exact_match(self):
        enforcer = self._make_enforcer([{"rule_type": "ip", "value": "8.8.8.8"}])
        allowed, _ = enforcer.is_allowed("8.8.8.8")
        assert allowed is True

    def test_ip_no_match(self):
        enforcer = self._make_enforcer([{"rule_type": "ip", "value": "8.8.8.8"}])
        allowed, _ = enforcer.is_allowed("1.1.1.1")
        assert allowed is False

    def test_url_prefix_match(self):
        enforcer = self._make_enforcer([{"rule_type": "url_prefix", "value": "https://target.com/api"}])
        allowed, _ = enforcer.is_allowed("https://target.com/api/v1/test")
        assert allowed is True

    def test_empty_rules_allows_all(self):
        enforcer = self._make_enforcer([])
        allowed, _ = enforcer.is_allowed("anything.com")
        assert allowed is True

    def test_validate_targets_mixed(self):
        enforcer = self._make_enforcer(
            [
                {"rule_type": "cidr", "value": "10.0.0.0/24"},
                {"rule_type": "domain", "value": "target.com"},
            ]
        )
        violations = enforcer.validate_targets(["10.0.0.1", "target.com", "evil.com", "192.168.1.1"])
        assert len(violations) == 2
        assert any("evil.com" in v for v in violations)
        assert any("192.168.1.1" in v for v in violations)

    def test_extract_and_validate_finds_ips(self):
        enforcer = self._make_enforcer([{"rule_type": "cidr", "value": "10.0.0.0/24"}])
        text = "Scanning target at 10.0.0.5 and also 172.16.0.1"
        violations = enforcer.extract_and_validate(text)
        assert len(violations) >= 1
        assert any("172.16.0.1" in v for v in violations)
