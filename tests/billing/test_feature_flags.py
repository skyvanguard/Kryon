"""Tests for feature flags."""

import pytest

from kryon.billing.feature_flags import FEATURE_FLAGS, get_tier_features, is_feature_available


def test_free_tier():
    features = get_tier_features("free")
    assert "basic_scanning" in features
    assert "api_access" in features
    assert "engagements" not in features


def test_standard_tier():
    features = get_tier_features("standard")
    assert "basic_scanning" in features
    assert "engagements" in features
    assert "siem_integration" not in features


def test_enterprise_tier():
    features = get_tier_features("enterprise")
    assert "siem_integration" in features
    assert "attack_paths" in features
    assert "llm_security" in features


def test_unknown_tier_defaults_free():
    features = get_tier_features("unknown")
    assert features == FEATURE_FLAGS["free"]


def test_is_feature_available():
    assert is_feature_available("enterprise", "siem_integration") is True
    assert is_feature_available("free", "siem_integration") is False
    assert is_feature_available("standard", "engagements") is True
