"""E2E tests for report generation."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.e2e]


@pytest.mark.e2e
def test_reports_page_loads(authenticated_page):
    """Reports page should be accessible."""
    page = authenticated_page
    page.goto("/reports")
    page.wait_for_timeout(1000)
    assert "report" in page.url.lower() or page.locator("h1, h2, main").first.is_visible()
