"""Tests for global HTTP header injection (custom extra HTTP headers)."""

from __future__ import annotations

import pytest

from kryon.util import http_headers


def test_unset_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KRYON_HTTP_EXTRA_HEADERS", raising=False)
    assert http_headers.extra_http_headers() == {}
    assert http_headers.header_lines() == []
    assert http_headers.header_semicolon_string() == ""


def test_single_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_HTTP_EXTRA_HEADERS", "X-Research-Id: research-team")
    assert http_headers.extra_http_headers() == {"X-Research-Id": "research-team"}
    assert http_headers.header_lines() == ["X-Research-Id: research-team"]


def test_multiple_headers_double_pipe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "KRYON_HTTP_EXTRA_HEADERS",
        "X-Research-Id: me || X-Bug-Bounty: true",
    )
    got = http_headers.extra_http_headers()
    assert got == {"X-Research-Id": "me", "X-Bug-Bounty": "true"}
    assert http_headers.header_semicolon_string() == "X-Research-Id: me; X-Bug-Bounty: true"


def test_value_may_contain_colon(monkeypatch: pytest.MonkeyPatch) -> None:
    # partition on the FIRST colon — a value like a URL keeps its colons.
    monkeypatch.setenv("KRYON_HTTP_EXTRA_HEADERS", "Referer: https://example.com/x")
    assert http_headers.extra_http_headers() == {"Referer": "https://example.com/x"}


def test_malformed_fragments_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_HTTP_EXTRA_HEADERS", "no-colon-here || X-Ok: 1 ||   || : novalue")
    assert http_headers.extra_http_headers() == {"X-Ok": "1"}


def test_whitespace_trimmed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRYON_HTTP_EXTRA_HEADERS", "   X-A :  v1   ")
    assert http_headers.extra_http_headers() == {"X-A": "v1"}


# --------------------------------------------------------------------------- #
# End-to-end: the header must ACTUALLY be sent on the wire by web_fetch_smart. #
# --------------------------------------------------------------------------- #


def test_web_fetch_smart_sends_the_header_on_the_wire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Proof the wiring works: a local server records the inbound request headers,
    and X-Research-Id must appear when KRYON_HTTP_EXTRA_HEADERS is set."""
    import http.server
    import socketserver
    import threading

    from kryon.tools.web.web_fetch_smart import web_fetch_smart

    seen: dict[str, str] = {}

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a, **_k) -> None:
            return

        def do_GET(self) -> None:
            for k, v in self.headers.items():
                seen[k] = v
            body = b"<html><title>ok</title><body>hi</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = socketserver.TCPServer(("127.0.0.1", 0), _H)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setenv("KRYON_HTTP_EXTRA_HEADERS", "X-Research-Id: research-team")
        fn = getattr(web_fetch_smart, "_raw_fn", None) or web_fetch_smart
        fn(f"http://127.0.0.1:{port}/")
    finally:
        httpd.shutdown()
        httpd.server_close()

    # HTTP header names are case-insensitive; urllib normalizes the case on the
    # wire (X-Research-Id), which the server matches all the same.
    seen_ci = {k.lower(): v for k, v in seen.items()}
    assert seen_ci.get("x-research-id") == "research-team", f"header not sent; got {sorted(seen)}"
