"""Deterministic web-hygiene detectors: header QUALITY (CSP unsafe-*, HSTS includeSubDomains) and
POST/data-form CSRF token absence. These produce reliable findings the (weak local) LLM kept fetching
past — validated live on example.com."""

from __future__ import annotations

from kryon.cli import engage
from kryon.cli.engage import DiscoveredService, _check_form_csrf, _check_header_quality

_SVC = DiscoveredService(host="example.com", port=443, state="open", service="https")


def test_header_quality_flags_unsafe_csp_and_weak_hsts(monkeypatch):
    monkeypatch.setattr(
        engage,
        "_fetch_response_headers",
        lambda url, **k: {
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "strict-transport-security": "max-age=31536000",
        },
    )
    rules = {f.rule_id: f for f in _check_header_quality(_SVC)}
    assert "csp-unsafe-directives" in rules and rules["csp-unsafe-directives"].cwe == "CWE-1021"
    assert "hsts-no-includesubdomains" in rules
    assert "csp-no-object-src" in rules  # CSP present but no object-src 'none'


def test_header_quality_clean_on_hardened_headers(monkeypatch):
    monkeypatch.setattr(
        engage,
        "_fetch_response_headers",
        lambda url, **k: {
            "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        },
    )
    assert _check_header_quality(_SVC) == []


def test_header_quality_empty_when_no_headers(monkeypatch):
    monkeypatch.setattr(engage, "_fetch_response_headers", lambda url, **k: {})
    assert _check_header_quality(_SVC) == []


_LOGIN_FORM = '<form method="post" action="/login.php"><input type="password" name="pw"></form>'
_CONTACT_AJAX = '<form class="needs-validation" novalidate><input name="email"><textarea name="message"></textarea></form>'
_FORM_WITH_TOKEN = '<form method="post" action="/login"><input type="password"><input type="hidden" name="csrf_token" value="x"></form>'
_SEARCH_GET = '<form method="get" action="/search"><input name="q"></form>'


def _serve(pages: dict[str, str]):
    def _get(url, **k):
        for path, html in pages.items():
            if url.endswith(path):
                return 200, html
        return 404, ""
    return _get


def test_form_csrf_flags_explicit_post_password_form(monkeypatch):
    monkeypatch.setattr(engage, "_http_get", _serve({"/login.php": _LOGIN_FORM}))
    found = _check_form_csrf(_SVC)
    assert any(f.cwe == "CWE-352" and f.severity == "MEDIUM" for f in found)


def test_form_csrf_flags_js_contact_form_at_low(monkeypatch):
    # method set via JS (no method attr) but email + message → CSRF-relevant, flagged LOW
    monkeypatch.setattr(engage, "_http_get", _serve({"/contacto.php": _CONTACT_AJAX}))
    found = _check_form_csrf(_SVC)
    assert any(f.rule_id == "form-no-csrf-token" and f.severity == "LOW" for f in found)


def test_form_csrf_ignores_token_form_and_get_search(monkeypatch):
    monkeypatch.setattr(engage, "_http_get", _serve({"/login": _FORM_WITH_TOKEN, "/": _SEARCH_GET}))
    assert _check_form_csrf(_SVC) == []


def test_header_quality_flags_weak_referrer_policy(monkeypatch):
    monkeypatch.setattr(
        engage, "_fetch_response_headers",
        lambda url, **k: {"referrer-policy": "no-referrer-when-downgrade"},
    )
    rules = {f.rule_id for f in _check_header_quality(_SVC)}
    assert "weak-referrer-policy" in rules


def test_header_quality_ok_referrer_policy_clean(monkeypatch):
    monkeypatch.setattr(
        engage, "_fetch_response_headers",
        lambda url, **k: {"referrer-policy": "strict-origin-when-cross-origin"},
    )
    assert all(f.rule_id != "weak-referrer-policy" for f in _check_header_quality(_SVC))
