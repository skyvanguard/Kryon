"""Tests for report branding utilities."""

import pytest

from kryon.reporting.branding import BrandingConfig, apply_branding


def test_branding_config_defaults():
    b = BrandingConfig()
    assert b.primary_color == "#00d4ff"
    assert b.company_name == "KRYON Security"
    assert b.logo_url == ""


def test_apply_branding_with_body():
    html = "<html><body><h1>Report</h1></body></html>"
    branding = BrandingConfig(
        company_name="ACME Corp", primary_color="#ff0000", logo_url="https://example.com/logo.png"
    )
    result = apply_branding(html, branding)
    assert "ACME Corp" in result
    assert "#ff0000" in result
    assert "logo.png" in result


def test_apply_branding_no_logo():
    html = "<html><body><h1>Report</h1></body></html>"
    branding = BrandingConfig(company_name="TestCo")
    result = apply_branding(html, branding)
    assert "TestCo" in result
    assert "<img" not in result  # No img tag if no logo


def test_apply_branding_footer():
    html = "<html><body>content</body></html>"
    branding = BrandingConfig(footer_text="Custom Footer")
    result = apply_branding(html, branding)
    assert "Custom Footer" in result


def test_apply_branding_no_body_tag():
    html = "<h1>No body tag</h1>"
    branding = BrandingConfig(company_name="Corp")
    result = apply_branding(html, branding)
    assert "Corp" in result
