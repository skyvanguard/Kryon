"""E2E test helpers and page object shortcuts."""

from __future__ import annotations

API_BASE = "/api/v1"


def login(page, username: str = "admin", password: str = "Admin123!"):
    """Helper to log in via the dashboard UI."""
    page.goto("/login")
    page.fill("input[name=username]", username)
    page.fill("input[name=password]", password)
    page.click("button[type=submit]")
    page.wait_for_url("**/dashboard", timeout=5000)


def api_login(page, username: str = "admin", password: str = "Admin123!") -> str:
    """Login via API and return JWT token."""
    resp = page.request.post(f"{API_BASE}/auth/login", data={
        "username": username,
        "password": password,
    })
    return resp.json().get("access_token", "")
