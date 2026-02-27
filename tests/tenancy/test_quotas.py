"""Tests for tenant quota enforcement."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kryon.tenancy.models import TIER_LIMITS, Tenant, TenantQuota
from kryon.tenancy.quotas import ResourceQuotaEnforcer


class TestResourceQuotaEnforcer:
    @pytest.fixture
    def mock_store(self):
        store = MagicMock()
        store.get_tenant_quotas.return_value = [
            {"resource": "scans", "max_value": 10, "current_value": 5},
            {"resource": "users", "max_value": 3, "current_value": 3},
            {"resource": "storage_mb", "max_value": 100, "current_value": 50},
        ]
        store.get_tenant.return_value = {"id": "t1", "tier": "free"}
        return store

    def test_scan_quota_allowed(self, mock_store):
        with patch("kryon.server.deps.get_store", return_value=mock_store):
            enforcer = ResourceQuotaEnforcer()
            allowed, reason = enforcer.check_quota("t1", "scans", 1)
            assert allowed is True
            assert reason is None

    def test_user_quota_exceeded(self, mock_store):
        with patch("kryon.server.deps.get_store", return_value=mock_store):
            enforcer = ResourceQuotaEnforcer()
            allowed, reason = enforcer.check_quota("t1", "users", 1)
            assert allowed is False
            assert "exceeded" in reason.lower()

    def test_storage_quota_within_limit(self, mock_store):
        with patch("kryon.server.deps.get_store", return_value=mock_store):
            enforcer = ResourceQuotaEnforcer()
            allowed, _ = enforcer.check_quota("t1", "storage_mb", 30)
            assert allowed is True

    def test_storage_quota_exceeded(self, mock_store):
        with patch("kryon.server.deps.get_store", return_value=mock_store):
            enforcer = ResourceQuotaEnforcer()
            allowed, reason = enforcer.check_quota("t1", "storage_mb", 60)
            assert allowed is False

    def test_consume_quota_success(self, mock_store):
        mock_store.increment_quota_usage.return_value = True
        with patch("kryon.server.deps.get_store", return_value=mock_store):
            enforcer = ResourceQuotaEnforcer()
            assert enforcer.consume_quota("t1", "scans", 1) is True

    def test_consume_quota_denied(self, mock_store):
        with patch("kryon.server.deps.get_store", return_value=mock_store):
            enforcer = ResourceQuotaEnforcer()
            assert enforcer.consume_quota("t1", "users", 1) is False


class TestTierLimits:
    def test_free_tier_limits(self):
        limits = TIER_LIMITS["free"]
        assert limits["scans"] == 10
        assert limits["users"] == 3
        assert limits["storage_mb"] == 100

    def test_standard_tier_limits(self):
        limits = TIER_LIMITS["standard"]
        assert limits["scans"] == 100
        assert limits["users"] == 10
        assert limits["storage_mb"] == 1024

    def test_enterprise_tier_limits(self):
        limits = TIER_LIMITS["enterprise"]
        assert limits["scans"] > 1000
        assert limits["users"] > 1000

    def test_all_tiers_defined(self):
        assert "free" in TIER_LIMITS
        assert "standard" in TIER_LIMITS
        assert "enterprise" in TIER_LIMITS


class TestTenantMiddleware:
    def test_default_tenant_context(self):
        from kryon.tenancy import get_tenant, set_tenant
        set_tenant({"id": "test", "name": "Test", "tier": "free"})
        tenant = get_tenant()
        assert tenant["id"] == "test"
        set_tenant(None)  # cleanup

    def test_extract_subdomain(self):
        from kryon.tenancy.middleware import TenantResolutionMiddleware
        mw = TenantResolutionMiddleware(app=None, enabled=False)
        assert mw._extract_subdomain("acme.kryon.app") == "acme"
        assert mw._extract_subdomain("kryon.app") is None
        assert mw._extract_subdomain("localhost:8700") is None
