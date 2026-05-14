"""F114.A — TDD contract for the Active Open Redirect Probe.

The double-gate (fire=True + KRYON_OPENREDIRECT_FIRE=true) is
exercised both ways: blocked + unblocked."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from kryon.tools.active_probes.open_redirect_active import (
    OpenRedirectActiveConfig,
    _build_probe_url,
    build_redirect_payloads,
    probe_open_redirect_active,
)

# =====================================================================
# Pure functions
# =====================================================================


def test_build_redirect_payloads_includes_classic_bypasses():
    payloads = build_redirect_payloads("evil.example")
    joined = "|".join(payloads)
    # Direct scheme
    assert "https://evil.example/" in joined
    # Scheme-relative
    assert "//evil.example" in joined
    # Userinfo bypass
    assert "@evil.example" in joined
    # URL-encoded variant
    assert "https%3A%2F%2Fevil.example" in joined


def test_build_probe_url_replaces_existing_param():
    out = _build_probe_url("https://target.com/login?next=before&keep=1", "next", "AFTER")
    assert "next=AFTER" in out
    assert "keep=1" in out
    assert "next=before" not in out


def test_build_probe_url_appends_when_not_present():
    out = _build_probe_url("https://target.com/login?keep=1", "next", "VAL")
    assert "next=VAL" in out
    assert "keep=1" in out


def test_build_probe_url_no_existing_query():
    out = _build_probe_url("https://target.com/login", "next", "VAL")
    assert "next=VAL" in out


# =====================================================================
# Double-gate behavior
# =====================================================================


def test_dry_run_when_fire_false(monkeypatch):
    monkeypatch.setenv("KRYON_OPENREDIRECT_FIRE", "true")
    cfg = OpenRedirectActiveConfig(
        endpoint_url="https://127.0.0.1:1/login",
        parameter_name="next",
        fire=False,  # gate 1 closed
    )
    result = probe_open_redirect_active(cfg)
    assert result.fired is False
    assert "fire=False" in result.fire_gate_state
    assert len(result.payloads_built) > 0  # still reports payloads
    assert result.attempts == ()


def test_dry_run_when_env_not_set(monkeypatch):
    monkeypatch.delenv("KRYON_OPENREDIRECT_FIRE", raising=False)
    cfg = OpenRedirectActiveConfig(
        endpoint_url="https://127.0.0.1:1/login",
        parameter_name="next",
        fire=True,  # gate 1 open
    )
    result = probe_open_redirect_active(cfg)
    assert result.fired is False
    assert "KRYON_OPENREDIRECT_FIRE" in result.fire_gate_state


def test_dry_run_when_env_value_not_true(monkeypatch):
    monkeypatch.setenv("KRYON_OPENREDIRECT_FIRE", "yes-please")
    cfg = OpenRedirectActiveConfig(
        endpoint_url="https://127.0.0.1:1/login",
        parameter_name="next",
        fire=True,
    )
    result = probe_open_redirect_active(cfg)
    assert result.fired is False


def test_invalid_endpoint_url_rejected(monkeypatch):
    monkeypatch.setenv("KRYON_OPENREDIRECT_FIRE", "true")
    cfg = OpenRedirectActiveConfig(
        endpoint_url="ftp://target.com/login",  # not http(s)
        parameter_name="next",
        fire=True,
    )
    result = probe_open_redirect_active(cfg)
    assert result.fired is False
    assert "scheme" in result.fire_gate_state


# =====================================================================
# Live probe against a local HTTP server
# =====================================================================


# Server: /redirect?next=<value> echoes the value into the Location header.
# Vulnerable behavior simulating naive servers.
class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self) -> None:
        if self.path.startswith("/redirect"):
            # Naively extract value of `next`
            import urllib.parse

            parsed = urllib.parse.urlparse(self.path)
            qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            target = qs.get("next", "")
            if target:
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/safe-redirect"):
            # SAFE: only redirects to internal paths
            import urllib.parse

            parsed = urllib.parse.urlparse(self.path)
            qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            target = qs.get("next", "/")
            # Block off-site
            if target.startswith(("http://", "https://", "//", "\\\\")):
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(302)
            self.send_header("Location", target if target.startswith("/") else "/" + target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def vuln_server():
    httpd = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_live_probe_confirms_vulnerable_redirect(monkeypatch, vuln_server):
    monkeypatch.setenv("KRYON_OPENREDIRECT_FIRE", "true")
    cfg = OpenRedirectActiveConfig(
        endpoint_url=f"{vuln_server}/redirect?next=",
        parameter_name="next",
        canary_host="canary.kryon-test",
        fire=True,
        rate_limit_per_second=50,  # fast for test
    )
    result = probe_open_redirect_active(cfg)
    assert result.fired is True
    # Server echoes Location → F103 analyzer fires OR-002 / OR-003
    assert len(result.findings) > 0
    rule_ids = {f.rule_id for f in result.findings}
    # At least one of these classes should fire on the vulnerable handler
    assert rule_ids & {"OR-001", "OR-002", "OR-003", "OR-006"}


def test_live_probe_safe_handler_no_critical_findings(monkeypatch, vuln_server):
    monkeypatch.setenv("KRYON_OPENREDIRECT_FIRE", "true")
    cfg = OpenRedirectActiveConfig(
        endpoint_url=f"{vuln_server}/safe-redirect?next=",
        parameter_name="next",
        canary_host="canary.kryon-test",
        fire=True,
        rate_limit_per_second=50,
    )
    result = probe_open_redirect_active(cfg)
    assert result.fired is True
    # OR-001 (heuristic on param name) might still fire because
    # "next" matches the heuristic — that's OK.
    # OR-002/OR-003 (CONFIRMED redirect) should NOT fire.
    critical_rules = {"OR-002", "OR-003"}
    fired_critical = {f.rule_id for f in result.findings} & critical_rules
    assert not fired_critical


def test_live_probe_attempts_recorded(monkeypatch, vuln_server):
    monkeypatch.setenv("KRYON_OPENREDIRECT_FIRE", "true")
    cfg = OpenRedirectActiveConfig(
        endpoint_url=f"{vuln_server}/redirect",
        parameter_name="next",
        canary_host="canary.kryon-test",
        fire=True,
        rate_limit_per_second=50,
    )
    result = probe_open_redirect_active(cfg)
    assert len(result.attempts) == len(result.payloads_built)
    # Each attempt should have a status > 0 (server is reachable)
    statuses = [a.http_status for a in result.attempts]
    assert all(s > 0 for s in statuses)


def test_unreachable_target_classifies_attempts_as_errors(monkeypatch):
    monkeypatch.setenv("KRYON_OPENREDIRECT_FIRE", "true")
    cfg = OpenRedirectActiveConfig(
        endpoint_url="http://127.0.0.1:1/login",  # unreachable
        parameter_name="next",
        fire=True,
        timeout_seconds=1.0,
    )
    result = probe_open_redirect_active(cfg)
    assert result.fired is True
    # All attempts should be errors
    assert all(a.error or a.http_status == 0 for a in result.attempts)
    # No findings since no server confirmed anything
    assert result.findings == ()
