"""Tests for network egress policy."""

from __future__ import annotations

import pytest

from kryon.agents.network_policy import NetworkEgressPolicy


class TestNetworkEgressPolicy:
    """Test network policy enforcement."""

    def test_blocks_rfc1918_10(self):
        policy = NetworkEgressPolicy()
        allowed, reason = policy.is_allowed("10.0.0.1")
        assert allowed is False
        assert "private" in reason.lower() or "internal" in reason.lower()

    def test_blocks_rfc1918_172(self):
        policy = NetworkEgressPolicy()
        allowed, _ = policy.is_allowed("172.16.5.10")
        assert allowed is False

    def test_blocks_rfc1918_192(self):
        policy = NetworkEgressPolicy()
        allowed, _ = policy.is_allowed("192.168.1.1")
        assert allowed is False

    def test_blocks_loopback(self):
        policy = NetworkEgressPolicy()
        allowed, _ = policy.is_allowed("127.0.0.1")
        assert allowed is False

    def test_allows_public_ip(self):
        policy = NetworkEgressPolicy()
        allowed, _ = policy.is_allowed("8.8.8.8")
        assert allowed is True

    def test_explicit_deny(self):
        policy = NetworkEgressPolicy(denied_cidrs=["8.8.8.0/24"])
        allowed, reason = policy.is_allowed("8.8.8.8")
        assert allowed is False
        assert "denied" in reason.lower()

    def test_explicit_allow_private(self):
        policy = NetworkEgressPolicy(allow_private=True)
        allowed, _ = policy.is_allowed("10.0.0.1")
        assert allowed is True

    def test_allowed_cidrs_whitelist(self):
        policy = NetworkEgressPolicy(allowed_cidrs=["10.10.0.0/16"])
        allowed, _ = policy.is_allowed("10.10.5.5")
        assert allowed is True

    def test_unresolvable_hostname(self):
        policy = NetworkEgressPolicy()
        allowed, reason = policy.is_allowed("this-host-does-not-exist-xyz123.invalid")
        assert allowed is False
        assert "resolve" in reason.lower()
