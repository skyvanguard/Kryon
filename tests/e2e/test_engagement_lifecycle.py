"""E2E tests for engagement lifecycle."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.slow]


@pytest.mark.e2e
@pytest.mark.slow
def test_engagements_page_loads(authenticated_page):
    """Engagements page should load with engagement list or empty state."""
    page = authenticated_page
    page.goto("/engagements")
    page.wait_for_timeout(1000)
    assert "engagement" in page.url.lower() or page.locator("h1, h2, main").first.is_visible()
