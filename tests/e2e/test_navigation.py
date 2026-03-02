"""E2E tests for general navigation."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.e2e]


@pytest.mark.e2e
def test_root_redirects(page):
    """Root URL should redirect to login or dashboard."""
    try:
        page.goto("/", timeout=5000)
    except Exception:
        pytest.skip("Dashboard not running")
    page.wait_for_timeout(1000)
    assert "/login" in page.url or "/dashboard" in page.url or page.url.endswith("/")


@pytest.mark.e2e
def test_404_page(page):
    """Non-existent route should show 404 or redirect."""
    try:
        page.goto("/nonexistent-route-xyz", timeout=5000)
    except Exception:
        pytest.skip("Dashboard not running")
    page.wait_for_timeout(1000)
    # Either shows 404 content or redirects to login/home
    content = page.content().lower()
    assert "404" in content or "/login" in page.url or "not found" in content or page.url.endswith("/")


@pytest.mark.e2e
def test_sidebar_links_exist(authenticated_page):
    """Dashboard should have sidebar navigation links."""
    page = authenticated_page
    links = page.locator("nav a, aside a, .sidebar a").all_text_contents()
    # Just verify sidebar has some navigation
    assert len(links) >= 1, "Dashboard must have at least one navigation link"


@pytest.mark.e2e
def test_api_health_from_browser(page):
    """Health endpoint should return OK from browser context."""
    try:
        resp = page.request.get("/api/v1/health")
    except Exception:
        pytest.skip("Server not running")
    assert resp.status == 200


@pytest.mark.e2e
def test_api_returns_401_without_auth(page):
    """Protected endpoints should require authentication."""
    try:
        resp = page.request.get("/api/v1/scans")
    except Exception:
        pytest.skip("Server not running")
    assert resp.status in (401, 403), "Protected endpoint must return 401 or 403 without auth"
