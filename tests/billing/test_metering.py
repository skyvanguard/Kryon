"""Tests for usage metering."""

import pytest

from kryon.billing.metering import TIER_LIMITS, check_limit, get_usage_summary, record_usage
from kryon.memory.store import MemoryStore


@pytest.fixture
def store(tmp_path):
    s = MemoryStore(db_path=tmp_path / "test.db")
    yield s
    s.close()


def test_record_usage(store):
    """Test recording usage."""
    record_usage(store, "tenant-1", "scans", 1)
    summary = get_usage_summary(store, "tenant-1")
    assert len(summary) == 1
    assert summary[0]["resource"] == "scans"
    assert summary[0]["total"] == 1


def test_get_usage_summary(store):
    """Test getting usage summary with multiple resources."""
    record_usage(store, "tenant-1", "scans", 5)
    record_usage(store, "tenant-1", "findings", 20)
    record_usage(store, "tenant-1", "scans", 3)
    summary = get_usage_summary(store, "tenant-1")
    # Convert to dict for easy lookup
    by_resource = {s["resource"]: s["total"] for s in summary}
    assert by_resource["scans"] == 8
    assert by_resource["findings"] == 20


def test_check_limit_within(store):
    """Test checking usage within limits."""
    record_usage(store, "tenant-1", "scans", 5)
    allowed, remaining = check_limit(store, "tenant-1", "scans", tier="free")
    assert allowed is True
    assert remaining == TIER_LIMITS["free"]["scans"] - 5


def test_check_limit_exceeded(store):
    """Test checking usage exceeding limits."""
    record_usage(store, "tenant-1", "scans", 15)
    allowed, remaining = check_limit(store, "tenant-1", "scans", tier="free")
    assert allowed is False
    assert remaining == 0


def test_enterprise_unlimited(store):
    """Test that enterprise tier has unlimited usage."""
    record_usage(store, "tenant-1", "scans", 1000)
    allowed, remaining = check_limit(store, "tenant-1", "scans", tier="enterprise")
    assert allowed is True
    assert remaining == -1


def test_usage_summary_empty(store):
    """Test usage summary for tenant with no usage."""
    summary = get_usage_summary(store, "new-tenant")
    assert isinstance(summary, list)
    assert len(summary) == 0
