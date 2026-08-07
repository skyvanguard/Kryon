"""Tests for reporting models."""

from kryon.reporting.models import ReportConfig, ReportData, ReportType


def test_report_type_enum():
    assert ReportType.EXECUTIVE.value == "executive"
    assert ReportType.COMPLIANCE.value == "compliance"


def test_report_config_defaults():
    config = ReportConfig()
    assert config.report_type == ReportType.TECHNICAL
    assert config.format == "html"
    assert config.include_mitre is True
    assert config.date != ""


def test_report_data():
    data = ReportData(config=ReportConfig(client_name="Test"))
    assert data.config.client_name == "Test"
    assert data.findings == []
    assert data.generated_at != ""
