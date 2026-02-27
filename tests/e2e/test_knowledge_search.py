"""E2E tests for knowledge/RAG search."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.e2e]


@pytest.mark.e2e
def test_knowledge_page_loads(authenticated_page):
    """Knowledge page should be accessible."""
    page = authenticated_page
    page.goto("/knowledge")
    page.wait_for_timeout(1000)
    assert "knowledge" in page.url.lower() or page.locator("h1, h2, main").first.is_visible()
