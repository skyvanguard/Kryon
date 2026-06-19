"""Deterministic web probes (.git/.env/actuator/server-status/backups, TRACE,
WebDAV, admin panels). Graceful-on-unreachable + signature precision (a catch-all
200 HTML page must not false-trigger). Positive path verified live against an
http.server serving .git/HEAD + .env in the build (see commit message)."""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService
from kryon.cli.web_probes import _SENSITIVE_FILES, _looks_html, run_web_probes

_DEAD = "127.0.0.1"  # closed port → fast graceful path


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
