"""F191 — multi-endpoint sqlmap discovery hook tests."""

from __future__ import annotations

import pytest

from kryon.skills.playbooks.pre_hooks.endpoint_discovery_sqlmap_hook import (
    KNOWN_INJECTABLE_ENDPOINTS,
    _is_responsive,
    _looks_injection_positive,
    _summarize_endpoint_results,
)

# ---------------------------------------------------------------------------
# Endpoint catalog
# ---------------------------------------------------------------------------


def test_known_endpoints_cover_common_apps():
    """Catalog must include the endpoint patterns we've seen vulnerable
    across the bench universe (Juice Shop, DVWA, WebGoat)."""
    paths = {e["path"] for e in KNOWN_INJECTABLE_ENDPOINTS}
    # Juice Shop's known SQLi endpoint
    assert "/rest/user/login" in paths
    # Common API auth endpoints
    assert any("/api/" in p and "login" in p for p in paths)
    # Common search GET endpoints with q= param
    assert any("search" in p for p in paths)


def test_each_endpoint_has_required_fields():
    for e in KNOWN_INJECTABLE_ENDPOINTS:
        assert "path" in e
        assert "method" in e
        assert e["method"] in {"GET", "POST"}
        if e["method"] == "POST":
            # POST needs --data
            assert "data" in e
            assert "content_type" in e


# ---------------------------------------------------------------------------
# _is_responsive — HTTP status filter
# ---------------------------------------------------------------------------


def test_responsive_accepts_2xx_3xx_4xx_5xx():
    """Anything in 200-599 means the path exists / handler ran. We
    don't filter by status because sqlmap can inject through 401/500
    handlers (proven in F187)."""
    for code in (200, 201, 301, 302, 400, 401, 403, 404, 500, 503):
        # 404 alone wouldn't be useful, but the helper returns True so
        # the caller decides — `_is_responsive` is just "did the server
        # answer at all?"
        assert _is_responsive(code) is True


def test_responsive_rejects_connection_failure():
    """0 / negative codes indicate connection failed — endpoint doesn't
    exist or server is down."""
    assert _is_responsive(0) is False
    assert _is_responsive(-1) is False
    assert _is_responsive(None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Sqlmap output positive detection
# ---------------------------------------------------------------------------


def test_positive_detected_on_injection_point_keyword():
    sqlmap_out = """\
[INFO] testing connection
sqlmap identified the following injection point(s)
Parameter: q (GET)
    Type: boolean-based blind
"""
    assert _looks_injection_positive(sqlmap_out) is True


def test_positive_detected_on_is_vulnerable():
    out = "GET parameter 'id' is vulnerable. Do you want to keep testing?"
    assert _looks_injection_positive(out) is True


def test_negative_when_no_keywords():
    out = """\
[INFO] testing connection
[INFO] heuristic test shows parameter not injectable
[ERROR] all tested parameters do not appear to be injectable
"""
    assert _looks_injection_positive(out) is False


def test_negative_on_empty():
    assert _looks_injection_positive("") is False
    assert _looks_injection_positive(None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Per-endpoint summary block
# ---------------------------------------------------------------------------


def test_summary_marks_positive_endpoints_explicitly():
    results = [
        {
            "endpoint": "/rest/user/login",
            "method": "POST",
            "status": 401,
            "sqlmap_summary": "Parameter: JSON email\nType: boolean-based blind",
            "injectable": True,
        },
        {
            "endpoint": "/search",
            "method": "GET",
            "status": 200,
            "sqlmap_summary": "not injectable",
            "injectable": False,
        },
    ]
    out = _summarize_endpoint_results(results)
    assert "POSITIVE" in out or "VULNERABLE" in out.upper()
    assert "/rest/user/login" in out
    assert "boolean-based blind" in out


def test_summary_empty_when_no_endpoints_probed():
    """If discovery + probing returned 0 results, the summary should
    say so explicitly so the model doesn't pretend it ran tests."""
    out = _summarize_endpoint_results([])
    assert "no endpoints" in out.lower() or "no results" in out.lower()


def test_summary_counts_positive_negative():
    results = [
        {"endpoint": "/a", "method": "GET", "status": 200, "sqlmap_summary": "vuln", "injectable": True},
        {"endpoint": "/b", "method": "GET", "status": 200, "sqlmap_summary": "ok", "injectable": False},
        {"endpoint": "/c", "method": "POST", "status": 401, "sqlmap_summary": "vuln", "injectable": True},
    ]
    out = _summarize_endpoint_results(results)
    # Count line present somewhere
    assert "2" in out and "3" in out  # 2 positive, 3 tested
