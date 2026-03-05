import pytest
from kryon.intelligence.models import Finding, Severity, ValidationStatus


def test_validation_status_enum():
    assert ValidationStatus.UNVALIDATED == "unvalidated"
    assert ValidationStatus.CONFIRMED == "confirmed"
    assert ValidationStatus.POTENTIAL == "potential"
    assert ValidationStatus.FALSE_POSITIVE == "false_positive"


def test_finding_has_validation_fields():
    f = Finding(
        title="SQL Injection",
        description="SQLi in login",
        severity=Severity.HIGH,
        affected_asset="https://example.com/login",
    )
    assert f.validation_status == ValidationStatus.UNVALIDATED
    assert f.exploit_proof == ""
    assert f.validated_at is None
    assert f.validation_method == ""


def test_finding_confirmed_with_proof():
    f = Finding(
        title="SQL Injection",
        description="SQLi in login",
        severity=Severity.HIGH,
        affected_asset="https://example.com/login",
        validation_status=ValidationStatus.CONFIRMED,
        exploit_proof="Successfully extracted admin table via UNION SELECT",
        validation_method="sqlmap --dump",
    )
    assert f.validation_status == ValidationStatus.CONFIRMED
    assert "admin table" in f.exploit_proof


def test_finding_false_positive():
    f = Finding(
        title="Potential XSS",
        description="Reflected XSS attempt",
        severity=Severity.MEDIUM,
        affected_asset="https://example.com/search",
        validation_status=ValidationStatus.FALSE_POSITIVE,
        validation_method="dalfox",
    )
    assert f.validation_status == ValidationStatus.FALSE_POSITIVE


def test_validation_status_serialization():
    f = Finding(
        title="Test",
        description="Test",
        severity=Severity.LOW,
        affected_asset="test",
        validation_status=ValidationStatus.CONFIRMED,
    )
    data = f.model_dump()
    assert data["validation_status"] == "confirmed"
