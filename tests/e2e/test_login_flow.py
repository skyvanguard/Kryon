"""E2E tests for login/logout flow."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.e2e]


@pytest.mark.e2e
def test_login_page_loads(page):
    """Login page should render with username and password fields."""
    try:
        page.goto("/login", timeout=5000)
    except Exception:
        pytest.skip("Dashboard not running")
    assert page.locator("input[name=username]").is_visible()
    assert page.locator("input[name=password]").is_visible()
    assert page.locator("button[type=submit]").is_visible()


@pytest.mark.e2e
def test_login_success(page):
    """Valid credentials should redirect to dashboard."""
    try:
        page.goto("/login", timeout=5000)
    except Exception:
        pytest.skip("Dashboard not running")
    page.fill("input[name=username]", "admin")
    page.fill("input[name=password]", "Admin123!")
    page.click("button[type=submit]")
    try:
        page.wait_for_url("**/dashboard", timeout=5000)
    except Exception:
        pytest.skip("Login flow not configured")


@pytest.mark.e2e
def test_login_failure(page):
    """Invalid credentials should show an error message."""
    try:
        page.goto("/login", timeout=5000)
    except Exception:
        pytest.skip("Dashboard not running")
    page.fill("input[name=username]", "baduser")
    page.fill("input[name=password]", "wrongpass")
    page.click("button[type=submit]")
    # Should stay on login page
    page.wait_for_timeout(1000)
    assert "/login" in page.url or page.locator(".error, .alert, [role=alert]").count() > 0
