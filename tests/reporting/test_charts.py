"""Tests for SVG chart generation."""

import pytest

from kryon.reporting.charts import (
    generate_remediation_status_svg,
    generate_risk_gauge_svg,
    generate_severity_pie_svg,
    generate_trend_chart_svg,
)


def test_risk_gauge_low():
    svg = generate_risk_gauge_svg(15.0)
    assert "<svg" in svg
    assert "15" in svg  # Score shown
    assert "Low" in svg


def test_risk_gauge_critical():
    svg = generate_risk_gauge_svg(90.0)
    assert "<svg" in svg
    assert "90" in svg
    assert "Critical" in svg


def test_risk_gauge_medium():
    svg = generate_risk_gauge_svg(35.0)
    assert "<svg" in svg
    assert "Medium" in svg


def test_severity_pie_empty():
    svg = generate_severity_pie_svg({})
    assert "<svg" in svg
    assert "No data" in svg


def test_severity_pie_with_data():
    svg = generate_severity_pie_svg({"critical": 3, "high": 5, "medium": 10})
    assert "<svg" in svg
    assert "18" in svg  # Total shown in center


def test_trend_chart_empty():
    svg = generate_trend_chart_svg([])
    assert "<svg" in svg
    assert "No trend data" in svg


def test_trend_chart_with_data():
    data = [{"value": 10}, {"value": 20}, {"value": 15}]
    svg = generate_trend_chart_svg(data)
    assert "<svg" in svg
    assert "polyline" in svg


def test_remediation_status_svg():
    stats = {"open": 10, "remediated": 5, "accepted": 2, "false_positive": 1}
    svg = generate_remediation_status_svg(stats)
    assert "<svg" in svg
    assert "open" in svg
    assert "remediated" in svg
