"""Fase 2 — deterministic headless replay validators (XSS / SSRF / IDOR).

Pure adjudication with an injected fake fetcher — no network, no external tool.
The double gate (KRYON_REPLAY_FIRE + fire=True) is exercised for every class.
"""

from __future__ import annotations

import pytest

from kryon.tools.validation.http_replay import (
    HttpResponse,
    ReplayResult,
    _inject_param,
    is_replay_verifiable,
    replay_idor,
    replay_reflected_ssrf,
    replay_reflected_xss,
    replay_type_for_cwe,
    validate_web_finding,
)


def _fetcher(responses):
    """Build a fake HttpFetch. ``responses`` maps a substring-of-url -> HttpResponse
    (first match wins); a bare HttpResponse is returned for every call."""

    def fetch(method, url, headers, timeout):
        if isinstance(responses, HttpResponse):
            return responses
        for needle, resp in responses.items():
            if needle in url:
                return resp
        return HttpResponse(status=404, body="", headers={})

    return fetch


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------


class TestDoubleGate:
    def test_dry_run_without_env(self, monkeypatch):
        monkeypatch.delenv("KRYON_REPLAY_FIRE", raising=False)
        r = replay_reflected_xss("http://t/p", "q", fire=True, fetch=_fetcher(HttpResponse(200, "x", {})))
        assert r.verdict == "dry_run"

    def test_dry_run_without_kwarg(self, monkeypatch):
        monkeypatch.setenv("KRYON_REPLAY_FIRE", "true")
        r = replay_reflected_xss("http://t/p", "q", fire=False, fetch=_fetcher(HttpResponse(200, "x", {})))
        assert r.verdict == "dry_run"

    def test_fires_when_both_set(self, monkeypatch):
        monkeypatch.setenv("KRYON_REPLAY_FIRE", "1")
        r = replay_reflected_xss("http://t/p", "q", fire=True, fetch=_fetcher(HttpResponse(200, "clean", {})))
        assert r.verdict != "dry_run"


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------


class TestReflectedXss:
    @pytest.fixture(autouse=True)
    def _fire(self, monkeypatch):
        monkeypatch.setenv("KRYON_REPLAY_FIRE", "true")

    def test_confirmed_when_marker_reflected_unescaped(self):
        # Echo the injected value verbatim (vulnerable sink). unquote_plus mirrors
        # how a real server decodes '+' back to a space in the query string.
        def fetch(method, url, headers, timeout):
            from urllib.parse import unquote_plus

            return HttpResponse(200, f"<html>hi {unquote_plus(url.split('q=')[1])} bye</html>", {})

        r = replay_reflected_xss("http://t/s", "q", fire=True, fetch=fetch)
        assert r.verdict == "confirmed"
        assert r.cwe == "CWE-79"
        assert "kryonxss" in r.evidence

    def test_not_reproduced_when_escaped(self):
        # Sink HTML-escapes the value (safe).
        def fetch(method, url, headers, timeout):
            import html
            from urllib.parse import unquote_plus

            reflected = html.escape(unquote_plus(url.split("q=")[1]), quote=False)
            return HttpResponse(200, f"<html>{reflected}</html>", {})

        r = replay_reflected_xss("http://t/s", "q", fire=True, fetch=fetch)
        assert r.verdict == "not-reproduced"
        assert "escaped" in r.evidence

    def test_not_reproduced_when_not_reflected(self):
        r = replay_reflected_xss("http://t/s", "q", fire=True, fetch=_fetcher(HttpResponse(200, "static page", {})))
        assert r.verdict == "not-reproduced"

    def test_inconclusive_on_transport_error(self):
        r = replay_reflected_xss(
            "http://t/s", "q", fire=True, fetch=_fetcher(HttpResponse(0, "", {}, error="URLError: refused"))
        )
        assert r.verdict == "inconclusive"
        assert "URLError" in r.evidence


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------


class TestReflectedSsrf:
    @pytest.fixture(autouse=True)
    def _fire(self, monkeypatch):
        monkeypatch.setenv("KRYON_REPLAY_FIRE", "true")

    def test_confirmed_when_marker_content_echoed(self):
        body = "fetched: ami-id ABCTOKEN123 from metadata"
        r = replay_reflected_ssrf(
            "http://t/fetch",
            "u",
            "http://169.254.169.254/",
            "ABCTOKEN123",
            fire=True,
            fetch=_fetcher(HttpResponse(200, body, {})),
        )
        assert r.verdict == "confirmed"
        assert r.cwe == "CWE-918"
        assert "ABCTOKEN123" in r.evidence

    def test_not_reproduced_when_token_absent(self):
        r = replay_reflected_ssrf(
            "http://t/fetch",
            "u",
            "http://169.254.169.254/",
            "ABCTOKEN123",
            fire=True,
            fetch=_fetcher(HttpResponse(200, "nothing fetched", {})),
        )
        assert r.verdict == "not-reproduced"

    def test_inconclusive_without_expected_token(self):
        r = replay_reflected_ssrf(
            "http://t/fetch",
            "u",
            "http://x/",
            "  ",
            fire=True,
            fetch=_fetcher(HttpResponse(200, "x", {})),
        )
        assert r.verdict == "inconclusive"


# ---------------------------------------------------------------------------
# IDOR
# ---------------------------------------------------------------------------


class TestIdor:
    @pytest.fixture(autouse=True)
    def _fire(self, monkeypatch):
        monkeypatch.setenv("KRYON_REPLAY_FIRE", "true")

    def test_confirmed_when_sibling_returns_distinct_data(self):
        responses = {
            "id=1001": HttpResponse(200, '{"user":"me","ssn":"111"}', {}),
            "id=1002": HttpResponse(200, '{"user":"victim","ssn":"999"}', {}),
        }
        r = replay_idor(
            "http://t/account",
            "id",
            "1001",
            "1002",
            fire=True,
            fetch=_fetcher(responses),
        )
        assert r.verdict == "confirmed"
        assert r.cwe == "CWE-639"
        assert "victim" in r.evidence

    def test_not_reproduced_when_sibling_forbidden(self):
        responses = {
            "id=1001": HttpResponse(200, '{"user":"me"}', {}),
            "id=1002": HttpResponse(403, "Forbidden", {}),
        }
        r = replay_idor(
            "http://t/account",
            "id",
            "1001",
            "1002",
            fire=True,
            fetch=_fetcher(responses),
        )
        assert r.verdict == "not-reproduced"
        assert "403" in r.evidence

    def test_not_reproduced_when_sibling_body_identical(self):
        # Same generic page for any id (e.g. a login redirect) → not IDOR.
        responses = {
            "id=1001": HttpResponse(200, "please log in", {}),
            "id=1002": HttpResponse(200, "please log in", {}),
        }
        r = replay_idor(
            "http://t/account",
            "id",
            "1001",
            "1002",
            fire=True,
            fetch=_fetcher(responses),
        )
        assert r.verdict == "not-reproduced"

    def test_inconclusive_on_transport_error(self):
        responses = {
            "id=1001": HttpResponse(200, "me", {}),
            "id=1002": HttpResponse(0, "", {}, error="TimeoutError: slow"),
        }
        r = replay_idor(
            "http://t/account",
            "id",
            "1001",
            "1002",
            fire=True,
            fetch=_fetcher(responses),
        )
        assert r.verdict == "inconclusive"


# ---------------------------------------------------------------------------
# dispatcher + helpers
# ---------------------------------------------------------------------------


class TestDispatcher:
    def test_routes_xss(self, monkeypatch):
        monkeypatch.setenv("KRYON_REPLAY_FIRE", "true")
        r = validate_web_finding(
            "reflected_xss",
            "http://t/s",
            parameter="q",
            fire=True,
            fetch=_fetcher(HttpResponse(200, "clean", {})),
        )
        assert r.cwe == "CWE-79"

    def test_routes_bola_alias_to_idor(self, monkeypatch):
        monkeypatch.setenv("KRYON_REPLAY_FIRE", "true")
        responses = {
            "id=1": HttpResponse(200, "a", {}),
            "id=2": HttpResponse(403, "no", {}),
        }
        r = validate_web_finding(
            "BOLA",
            "http://t/o",
            parameter="id",
            own_id="1",
            other_id="2",
            fire=True,
            fetch=_fetcher(responses),
        )
        assert r.cwe == "CWE-639"

    def test_unsupported_type(self):
        r = validate_web_finding("sqli", "http://t/s", parameter="q")
        assert r.verdict == "unsupported"
        assert isinstance(r, ReplayResult)


class TestInjectParam:
    def test_appends_when_absent(self):
        assert _inject_param("http://t/s", "q", "V") == "http://t/s?q=V"

    def test_replaces_when_present(self):
        out = _inject_param("http://t/s?q=old&z=keep", "q", "NEW")
        assert "q=NEW" in out and "z=keep" in out and "q=old" not in out

    def test_url_encodes_payload(self):
        out = _inject_param("http://t/s", "q", '"><tag>')
        assert "%3E" in out or "%3C" in out  # angle brackets encoded


class TestCweApplicabilityGate:
    def test_maps_known_cwes(self):
        assert replay_type_for_cwe("CWE-79") == "xss"
        assert replay_type_for_cwe("CWE-918") == "ssrf"
        assert replay_type_for_cwe("CWE-639") == "idor"

    def test_case_and_whitespace_insensitive(self):
        assert replay_type_for_cwe("  cwe-79 ") == "xss"

    def test_unknown_cwe_returns_none(self):
        assert replay_type_for_cwe("CWE-89") is None  # SQLi → not a replay class
        assert is_replay_verifiable("CWE-89") is False

    def test_is_replay_verifiable_true_for_mapped(self):
        assert is_replay_verifiable("CWE-918") is True
