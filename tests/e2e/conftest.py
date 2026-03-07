"""E2E test fixtures using Playwright."""

from __future__ import annotations

import pytest

# All tests in this directory require the e2e marker
pytestmark = pytest.mark.e2e


@pytest.fixture(scope="session")
def browser():
    """Launch a headless Chromium browser for the test session."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def context(browser):
    """Create a new browser context per test."""
    ctx = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
    )
    yield ctx
    ctx.close()


@pytest.fixture
def page(context):
    """Create a new page per test."""
    p = context.new_page()
    yield p
    p.close()
