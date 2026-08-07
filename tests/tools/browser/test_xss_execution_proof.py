"""browser_test_xss execution-proof helpers.

The proof-of-exploit for XSS is a fired ``alert(marker)`` dialog — that means the JS EXECUTED
in a real browser, unlike curl/nuclei which only see (correct, un-damning) raw JSON. These tests
pin the pure pieces (marker-carrying payloads + injection-point URLs); the headless execution
itself is covered by the live smoke against Juice Shop's DOM-XSS search route.
"""

from __future__ import annotations

from kryon.tools.browser.playwright_tools import (
    _XSS_EXEC_MARKER,
    _xss_candidate_urls,
    _xss_exec_payloads,
)


def test_xss_payloads_carry_unique_marker():
    payloads = _xss_exec_payloads(_XSS_EXEC_MARKER)
    # every payload calls alert(marker): a dialog carrying the marker proves execution,
    # and the marker is unique so an incidental app alert can't false-positive.
    assert payloads and all(_XSS_EXEC_MARKER in p for p in payloads)
    assert all("alert(" in p for p in payloads)
    # covers the reliable auto-firing sinks + the canonical Juice Shop javascript: iframe
    assert any("onerror=" in p for p in payloads)
    assert any("onload=" in p for p in payloads)
    assert any("javascript:alert" in p for p in payloads)


def test_xss_candidate_urls_cover_query_and_spa_hash():
    urls = _xss_candidate_urls("http://shop:3000", "<svg/onload=alert('X')>")
    # query-param family (server-reflected XSS)
    assert any("?q=" in u for u in urls)
    # SPA hash-route family (DOM XSS — the payload never reaches the server)
    assert any("/#/search?q=" in u for u in urls)
    # payload is percent-encoded — raw angle brackets must not leak into the URL
    assert all("<svg" not in u for u in urls)
    assert any("%3Csvg" in u for u in urls)


def test_xss_candidate_urls_respects_existing_query():
    urls = _xss_candidate_urls("http://shop/app?x=1", "P")
    assert any("?x=1&q=" in u for u in urls)
