"""Tests for license validation."""

import pytest
from kryon.billing.license_validator import LicenseValidator


def test_validate_no_key():
    validator = LicenseValidator(public_key="")
    result = validator.validate("some.jwt.token")
    assert result is None


def test_is_feature_enabled():
    validator = LicenseValidator()
    payload = {"features": ["basic_scanning", "api_access"]}
    assert validator.is_feature_enabled(payload, "basic_scanning") is True


def test_is_feature_disabled():
    validator = LicenseValidator()
    payload = {"features": ["basic_scanning"]}
    assert validator.is_feature_enabled(payload, "siem_integration") is False


def test_is_feature_none_payload():
    validator = LicenseValidator()
    assert validator.is_feature_enabled(None, "basic_scanning") is False


def test_generate_requires_private_key():
    validator = LicenseValidator()
    with pytest.raises(ValueError, match="Private key required"):
        validator.generate_license("tenant-1", "standard", ["basic_scanning"])
