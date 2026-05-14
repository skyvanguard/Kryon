"""F108 — integration tests for the Crawler against a local HTTP server."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from kryon.tools.crawler.crawler import (
    Crawler,
    CrawlerConfig,
    CrawlResult,
)

# =====================================================================
# Test HTTP server fixture
# =====================================================================


# Routes are stored as: path → (status, content_type, body_bytes)
_ROUTES: dict[str, tuple[int, str, bytes]] = {}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # silence
        return

    def _serve(self, path: str) -> None:
        route = _ROUTES.get(path)
        if route is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>404</h1>")
            return
        status, content_type, body = route
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._serve(self.path)

    def do_HEAD(self) -> None:
        route = _ROUTES.get(self.path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, content_type, body = route
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()


@pytest.fixture
def server():
    """Spin up a local HTTPServer on a random port; populated via
    _ROUTES dict that the test sets up."""
    _ROUTES.clear()
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base
    finally:
        httpd.shutdown()
        httpd.server_close()


def _route(path: str, body: str, content_type: str = "text/html; charset=utf-8", status: int = 200) -> None:
    _ROUTES[path] = (status, content_type, body.encode("utf-8"))


# =====================================================================
# Smoke
# =====================================================================


def _make_config(seeds: list[str], **overrides) -> CrawlerConfig:
    defaults = dict(
        seeds=tuple(seeds),
        max_pages=20,
        max_depth=3,
        max_concurrency=2,
        rate_limit_per_second=50.0,
        per_request_timeout_seconds=3.0,
        respect_robots=False,  # easier for tests
        block_internal_ips=False,  # tests run against 127.0.0.1
    )
    defaults.update(overrides)
    return CrawlerConfig(**defaults)


def test_single_page_no_links(server):
    _route("/", "<html><body>Hello</body></html>")
    result = Crawler(_make_config([server + "/"])).crawl()
    assert len(result.pages) == 1
    assert result.pages[0].http_status == 200
    assert "Hello" in result.pages[0].body_snippet


def test_follows_link(server):
    _route("/", '<a href="/about">about</a>')
    _route("/about", "<h1>About</h1>")
    result = Crawler(_make_config([server + "/"])).crawl()
    urls = {p.url for p in result.pages}
    assert server + "/" in urls
    assert server + "/about" in urls


def test_respects_max_pages(server):
    _route("/", '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>')
    for ch in "abc":
        _route(f"/{ch}", f"<h1>{ch}</h1>")
    result = Crawler(_make_config([server + "/"], max_pages=2)).crawl()
    assert len(result.pages) <= 2


def test_respects_max_depth(server):
    _route("/", '<a href="/d1">d1</a>')
    _route("/d1", '<a href="/d2">d2</a>')
    _route("/d2", '<a href="/d3">d3</a>')
    _route("/d3", "<h1>d3</h1>")
    result = Crawler(_make_config([server + "/"], max_depth=1)).crawl()
    urls = {p.url for p in result.pages}
    # Depth 0 = root; depth 1 = /d1. /d2 should not be reached.
    assert server + "/" in urls
    assert server + "/d1" in urls
    assert server + "/d2" not in urls


def test_dedupes_visited_urls(server):
    _route("/", '<a href="/x">x</a><a href="/x">x</a><a href="/x">x</a>')
    _route("/x", "<h1>x</h1>")
    result = Crawler(_make_config([server + "/"])).crawl()
    urls = [p.url for p in result.pages]
    assert urls.count(server + "/x") == 1


def test_off_origin_blocked(server):
    """Link to a different host should NOT be crawled when same_origin_only=True."""
    _route("/", '<a href="http://other.example/">other</a><a href="/local">local</a>')
    _route("/local", "<h1>local</h1>")
    result = Crawler(_make_config([server + "/"])).crawl()
    urls = {p.url for p in result.pages}
    assert "http://other.example/" not in urls
    assert server + "/local" in urls


def test_off_origin_endpoint_still_recorded(server):
    """Off-origin link is not crawled, but IS recorded as a discovered endpoint."""
    _route("/", '<a href="http://other.example/foo">other</a>')
    result = Crawler(_make_config([server + "/"])).crawl()
    ep_urls = {e.url for e in result.endpoints}
    assert "http://other.example/foo" in ep_urls


def test_form_extracted(server):
    body = """
    <form action="/login" method="post">
      <input name="username" type="text">
      <input name="password" type="password">
    </form>
    """
    _route("/", body)
    result = Crawler(_make_config([server + "/"])).crawl()
    assert len(result.forms) == 1
    f = result.forms[0]
    assert f.action == server + "/login"
    assert f.method == "POST"
    field_names = {name for name, _ in f.fields}
    assert "username" in field_names
    assert "password" in field_names


def test_external_js_fetched_and_endpoints_extracted(server):
    _route("/", '<script src="/bundle.js"></script>')
    _route(
        "/bundle.js",
        'fetch("/api/users"); axios.get("/api/account");',
        content_type="application/javascript",
    )
    result = Crawler(_make_config([server + "/"])).crawl()
    ep_urls = {e.url for e in result.endpoints}
    assert server + "/api/users" in ep_urls
    assert server + "/api/account" in ep_urls


def test_javascript_href_blocked(server):
    _route("/", '<a href="javascript:alert(1)">evil</a>')
    result = Crawler(_make_config([server + "/"])).crawl()
    urls = [p.url for p in result.pages]
    assert len(urls) == 1  # only root, no javascript: navigation


def test_404_does_not_crash(server):
    _route("/", '<a href="/missing">m</a><a href="/exists">e</a>')
    _route("/exists", "<h1>exists</h1>")
    result = Crawler(_make_config([server + "/"])).crawl()
    statuses = {p.http_status for p in result.pages}
    assert 200 in statuses
    assert 404 in statuses


def test_max_body_bytes_enforced(server):
    big_body = "<html><body>" + ("X" * 10_000) + "</body></html>"
    _route("/", big_body)
    result = Crawler(_make_config([server + "/"], max_body_bytes=500)).crawl()
    # body_snippet should be capped at max_body_bytes
    assert len(result.pages[0].body_snippet) <= 500


def test_auth_headers_sent(server):
    """Operator-supplied auth_headers should be on every request."""
    seen_headers: list[str] = []

    class _AuthHandler(_Handler):
        def do_GET(self):
            seen_headers.append(self.headers.get("X-Custom-Token", ""))
            return super().do_GET()

    _ROUTES.clear()
    _route("/", "<h1>ok</h1>")
    httpd = HTTPServer(("127.0.0.1", 0), _AuthHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = _make_config(
            [f"http://127.0.0.1:{port}/"],
            auth_headers=(("X-Custom-Token", "secret-token-123"),),
        )
        Crawler(cfg).crawl()
        assert "secret-token-123" in seen_headers
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_seeds_required():
    with pytest.raises(ValueError):
        Crawler(CrawlerConfig(seeds=()))


def test_internal_ip_blocked_when_configured():
    """When block_internal_ips=True, 127.0.0.1 should be refused."""
    cfg = CrawlerConfig(
        seeds=("http://127.0.0.1:1/",),
        respect_robots=False,
        block_internal_ips=True,
    )
    result = Crawler(cfg).crawl()
    assert any(e.reason == "out-of-scope" for e in result.errors)


def test_meta_tags_captured(server):
    _route(
        "/",
        '<head><meta name="generator" content="WordPress 6.4"><meta name="csrf-token" content="abc"></head><body></body>',
    )
    result = Crawler(_make_config([server + "/"])).crawl()
    # meta_tags shape: ((page_url, ((name, content), ...)), ...)
    found_keys: set[str] = set()
    for page_url, pairs in result.meta_tags:
        for name, content in pairs:
            found_keys.add(name)
    assert "generator" in found_keys
    assert "csrf-token" in found_keys


def test_script_urls_recorded(server):
    _route("/", '<script src="/a.js"></script><script src="/b.js"></script>')
    _route("/a.js", "console.log(1)", content_type="application/javascript")
    _route("/b.js", "console.log(2)", content_type="application/javascript")
    result = Crawler(_make_config([server + "/"])).crawl()
    assert server + "/a.js" in result.script_urls
    assert server + "/b.js" in result.script_urls


def test_elapsed_time_recorded(server):
    _route("/", "<h1>ok</h1>")
    result = Crawler(_make_config([server + "/"])).crawl()
    # Just confirm the field is populated (>=0 since time.monotonic()
    # is monotonic non-decreasing). Strict >0 is flaky on Windows due
    # to monotonic clock granularity for tiny intervals.
    assert result.elapsed_seconds >= 0


def test_rate_limit_applied(server):
    """With a very low rate limit, multiple fetches should take a
    measurable amount of time."""
    _route("/", '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>')
    for ch in "abc":
        _route(f"/{ch}", "<h1>x</h1>")
    cfg = _make_config([server + "/"], rate_limit_per_second=2.0, max_concurrency=1)
    start = time.monotonic()
    Crawler(cfg).crawl()
    elapsed = time.monotonic() - start
    # 4 requests at 2/s should take ~1s minimum
    assert elapsed >= 1.0, f"expected ≥ 1s, got {elapsed}"


def test_disable_external_js_fetch(server):
    """When fetch_external_js=False, JS bundles are listed but not fetched."""
    _route("/", '<script src="/big.js"></script>')
    _route("/big.js", 'fetch("/api/x")', content_type="application/javascript")
    cfg = _make_config([server + "/"], fetch_external_js=False)
    result = Crawler(cfg).crawl()
    # big.js should be in script_urls but NOT in pages
    page_urls = {p.url for p in result.pages}
    assert server + "/big.js" not in page_urls
    assert server + "/big.js" in result.script_urls


def test_seed_with_trailing_path_works(server):
    """Seed can be a subpage, not just root."""
    _route("/app/", '<a href="/app/dashboard">dash</a>')
    _route("/app/dashboard", "<h1>dash</h1>")
    result = Crawler(_make_config([server + "/app/"])).crawl()
    urls = {p.url for p in result.pages}
    assert server + "/app/dashboard" in urls
