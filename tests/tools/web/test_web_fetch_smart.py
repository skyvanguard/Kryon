"""F203.B — Tests for web_fetch_smart (smart HTML/JSON fetcher).

Cubre:
- HTML parsing → markdown extraction
- Meta tags + links extraction
- JSON content-type pretty-print
- Error paths (timeout, HTTP errors, scheme rejection)
- Size truncation
- Banca-safe contract (no POST/cookies/auth)
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.tools.web.web_fetch_smart import (
    _MarkdownExtractor,
    web_fetch_smart,
)

# ---------------------------------------------------------------------------
# _MarkdownExtractor — pure unit tests, no network
# ---------------------------------------------------------------------------


class TestMarkdownExtractor:
    def test_basic_html_to_markdown(self):
        html = "<html><body><h1>Hi</h1><p>Hello world</p></body></html>"
        p = _MarkdownExtractor()
        p.feed(html)
        p.close()
        md = p.get_markdown()
        assert "# Hi" in md
        assert "Hello world" in md

    def test_drops_script_tags(self):
        html = """<html><body>
            <p>Visible content</p>
            <script>alert('xss')</script>
            <style>body{display:none}</style>
        </body></html>"""
        p = _MarkdownExtractor()
        p.feed(html)
        p.close()
        md = p.get_markdown()
        assert "Visible content" in md
        assert "alert" not in md
        assert "display:none" not in md

    def test_extracts_links(self):
        html = """<html><body>
            <a href="https://example.com/foo">Foo link</a>
            <a href="/relative/path">Relative</a>
        </body></html>"""
        p = _MarkdownExtractor()
        p.feed(html)
        p.close()
        assert "https://example.com/foo" in p.links
        assert "/relative/path" in p.links
        md = p.get_markdown()
        assert "[Foo link](https://example.com/foo)" in md

    def test_extracts_meta_tags(self):
        html = """<html><head>
            <meta name="description" content="A test page">
            <meta name="generator" content="WordPress 6.4.1">
            <meta property="og:title" content="OG Title">
        </head><body>X</body></html>"""
        p = _MarkdownExtractor()
        p.feed(html)
        p.close()
        assert p.meta.get("description") == "A test page"
        assert p.meta.get("generator") == "WordPress 6.4.1"
        assert p.meta.get("og:title") == "OG Title"

    def test_extracts_title(self):
        html = "<html><head><title>My FIUNA Page</title></head><body>x</body></html>"
        p = _MarkdownExtractor()
        p.feed(html)
        p.close()
        assert p.title == "My FIUNA Page"

    def test_headings_levels(self):
        html = "<h1>One</h1><h2>Two</h2><h3>Three</h3>"
        p = _MarkdownExtractor()
        p.feed(html)
        p.close()
        md = p.get_markdown()
        assert "# One" in md
        assert "## Two" in md
        assert "### Three" in md

    def test_collapses_whitespace(self):
        html = "<p>Hello    world\n\n\n\nMore   text</p>"
        p = _MarkdownExtractor()
        p.feed(html)
        p.close()
        md = p.get_markdown()
        # No 4+ consecutive newlines, no double spaces
        assert "\n\n\n" not in md
        assert "Hello world" in md


# ---------------------------------------------------------------------------
# web_fetch_smart — integration with mocked network
# ---------------------------------------------------------------------------


def _patch_fetch_raw(status, headers, body, final_url):
    return patch(
        "kryon.tools.web.web_fetch_smart._fetch_raw",
        return_value=(status, headers, body, final_url),
    )


# FunctionTool wraps the raw callable on `_raw_fn`. Tests need direct access.
_raw = web_fetch_smart._raw_fn


class TestWebFetchSmartHTML:
    def test_html_response_parsed(self):
        html = b"""<html><head><title>Test</title>
        <meta name="generator" content="WordPress 6.4">
        </head><body><h1>Welcome</h1>
        <a href="/admin">Admin</a></body></html>"""
        with _patch_fetch_raw(200, {"content-type": "text/html; charset=utf-8"}, html, "http://test.local/"):
            result_json = _raw(url="http://test.local/")
        result = json.loads(result_json)
        assert result["status"] == 200
        assert result["content_type"].startswith("text/html")
        assert result["title"] == "Test"
        assert result["meta"]["generator"] == "WordPress 6.4"
        assert "# Welcome" in result["body_md"]
        assert "/admin" in result["links"]


class TestWebFetchSmartJSON:
    def test_json_response_pretty_printed(self):
        payload = b'{"version": "1.0", "endpoints": ["/login", "/api/v1"]}'
        with _patch_fetch_raw(200, {"content-type": "application/json"}, payload, "http://api.local/"):
            result_json = _raw(url="http://api.local/")
        result = json.loads(result_json)
        assert result["status"] == 200
        assert "json_keys" in result
        assert "version" in result["json_keys"]
        assert "endpoints" in result["json_keys"]
        assert "/login" in result["body_json_preview"]

    def test_invalid_json_falls_back_to_text(self):
        payload = b"not valid json {{{"
        with _patch_fetch_raw(200, {"content-type": "application/json"}, payload, "http://api.local/"):
            result_json = _raw(url="http://api.local/")
        result = json.loads(result_json)
        assert "body_text" in result


class TestWebFetchSmartErrors:
    def test_rejects_non_http_scheme(self):
        result = json.loads(_raw(url="file:///etc/passwd"))
        assert "error" in result
        assert "scheme" in result["error"].lower()

    def test_rejects_ftp_scheme(self):
        result = json.loads(_raw(url="ftp://example.com/file"))
        assert "error" in result

    def test_http_error_returns_status(self):
        import urllib.error

        err = urllib.error.HTTPError("http://test/", 404, "Not Found", {}, None)
        with patch("kryon.tools.web.web_fetch_smart._fetch_raw", side_effect=err):
            result = json.loads(_raw(url="http://test.local/"))
        assert result["status"] == 404
        assert "404" in result["error"]

    def test_url_error_handled(self):
        import urllib.error

        with patch(
            "kryon.tools.web.web_fetch_smart._fetch_raw",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            result = json.loads(_raw(url="http://nope.local/"))
        assert "URLError" in result["error"]


class TestWebFetchSmartTruncation:
    def test_truncated_flag_when_oversize(self):
        big_html = b"<html><body>" + (b"x" * 100) + b"</body></html>"
        with _patch_fetch_raw(
            200, {"content-type": "text/html", "_kryon_truncated": "true (capped at 50)"}, big_html, "http://big.local/"
        ):
            result = json.loads(_raw(url="http://big.local/"))
        assert result["truncated"] is True


class TestBancaSafeContract:
    """Verify the GET-only / no-auth contract is enforced in source."""

    def test_no_post_put_delete_in_source(self):
        from pathlib import Path

        src = Path(__file__).resolve().parents[3] / "src" / "kryon" / "tools" / "web" / "web_fetch_smart.py"
        text = src.read_text(encoding="utf-8")
        # method=POST should never appear
        assert 'method="POST"' not in text
        assert 'method="PUT"' not in text
        assert 'method="DELETE"' not in text
        # urlopen on req with method=GET only
        assert 'method="GET"' in text
