"""Deterministic web probes (.git/.env/actuator/server-status/backups, TRACE,
WebDAV, admin panels). Graceful-on-unreachable + signature precision (a catch-all
200 HTML page must not false-trigger). Positive path verified live against an
http.server serving .git/HEAD + .env in the build (see commit message)."""

from __future__ import annotations

import kryon.cli.web_probes as wp
from kryon.cli.engage import DiscoveredService
from kryon.cli.web_probes import _SENSITIVE_FILES, _looks_html, run_web_probes

_DEAD = "127.0.0.1"  # closed port → fast graceful path


def _svc(port: int = 80) -> DiscoveredService:
    return DiscoveredService(host=_DEAD, port=port, state="open", service="http")


def _mock_http(monkeypatch, responses):
    monkeypatch.setattr(wp, "_http_get", lambda host, port, path, scheme="http", **kw: responses.get(path))


def test_run_web_probes_graceful_on_closed_port():
    svc = DiscoveredService(host=_DEAD, port=9, state="open", service="http")
    out = run_web_probes(svc, "http")
    assert isinstance(out, list)  # never raises


def _sig(rule_id):
    return next(s for path, r, *_rest, s, _l, _f in _SENSITIVE_FILES if r == rule_id)


def test_git_signature():
    sig = _sig("git-exposed")
    assert sig("ref: refs/heads/main\n") is True
    assert sig("<html><body>404 Not Found</body></html>") is False


def test_env_signature_rejects_html_catchall():
    sig = _sig("env-exposed")
    assert sig("DB_PASSWORD=secret\nAPP_KEY=base64:x\n") is True
    # A SPA/catch-all that 200s every path must NOT be read as an .env leak.
    assert sig("<!doctype html><html><body>app</body></html>") is False
    assert sig("just some text without secrets") is False


def test_actuator_signature():
    assert _sig("spring-actuator-env")('{"activeProfiles":[],"propertySources":[]}') is True
    assert _sig("spring-actuator-env")("<html>not actuator</html>") is False


def test_looks_html():
    assert _looks_html("<!DOCTYPE html><html>") is True
    assert _looks_html("  <HTML>") is True
    assert _looks_html("DB_PASSWORD=x") is False


def test_swagger_spec_detected(monkeypatch):
    _mock_http(monkeypatch, {"/v3/api-docs": (200, '{"openapi":"3.0.1","paths":{"/users":{}}}')})
    f = wp._check_swagger(_svc(), "http")
    assert f is not None and f.rule_id == "swagger-exposed"


def test_swagger_ui_detected(monkeypatch):
    _mock_http(monkeypatch, {"/swagger-ui.html": (200, "<html><div id='swagger-ui'>Swagger UI</div></html>")})
    f = wp._check_swagger(_svc(), "http")
    assert f is not None and f.rule_id == "swagger-exposed"


def test_swagger_absent_returns_none(monkeypatch):
    _mock_http(monkeypatch, {})  # everything 404/None
    assert wp._check_swagger(_svc(), "http") is None


def test_wordpress_user_enum_and_xmlrpc(monkeypatch):
    _mock_http(monkeypatch, {
        "/wp-json/wp/v2/users": (200, '[{"id":1,"name":"admin","slug":"admin"}]'),
        "/xmlrpc.php": (405, "XML-RPC server accepts POST requests only."),
    })
    out = wp._check_wordpress(_svc(), "http")
    rules = {f.rule_id for f in out}
    assert rules == {"wordpress-user-enum", "wordpress-xmlrpc"}


def test_wordpress_absent_no_findings(monkeypatch):
    _mock_http(monkeypatch, {
        "/wp-json/wp/v2/users": (404, "<html>Not Found</html>"),
        "/xmlrpc.php": (404, "<html>Not Found</html>"),
    })
    assert wp._check_wordpress(_svc(), "http") == []
