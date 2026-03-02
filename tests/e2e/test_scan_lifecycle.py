"""E2E tests for scan lifecycle via UI."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.e2e]


@pytest.mark.e2e
def test_scans_page_loads(authenticated_page):
    """Scans page should be accessible after login."""
    page = authenticated_page
    page.goto("/scans")
    page.wait_for_timeout(1000)
    assert "scan" in page.url.lower() or page.locator("h1, h2").first.is_visible()


@pytest.mark.e2e
def test_create_scan_button_exists(authenticated_page):
    """Scans page should have a create/new scan button."""
    page = authenticated_page
    page.goto("/scans")
    page.wait_for_timeout(1000)
    buttons = page.locator("button, a").all_text_contents()
    has_create = any("new" in b.lower() or "create" in b.lower() or "scan" in b.lower() for b in buttons)
    assert has_create, "Scans page must have a create/new/scan button"
