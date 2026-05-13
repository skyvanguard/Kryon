"""F111 — TDD contract for the AuthFlowRunner.

Uses a local HTTP server fixture that simulates a real login form
with CSRF token + Set-Cookie response."""

from __future__ import annotations

import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from kryon.tools.auth.runner import (
    AuthFlowConfig,
    AuthFlowRunner,
    AuthSession,
    AuthSuccessSignal,
    LoginCredentials,
    _classify_response,
    _looks_like_csrf,
    _is_session_like,
    execute_auth_flow,
)


# =====================================================================
# Pure-function smoke
# =====================================================================


@pytest.mark.parametrize(
    "name,expected",
    [
        ("csrf_token", True),
        ("csrftoken", True),
        ("_csrf", True),
        ("_token", True),
        ("authenticity_token", True),
        ("csrfmiddlewaretoken", True),
        ("__RequestVerificationToken", True),
        ("username", False),
        ("password", False),
    ],
)
def test_looks_like_csrf(name, expected):
    assert _looks_like_csrf(name) is expected


@pytest.mark.parametrize(
    "name,expected",
    [
        ("PHPSESSID", True),
        ("session", True),
        ("auth_token", True),
        ("jwt", True),
        ("connect.sid", True),
        ("laravel_session", True),
        ("locale", False),
        ("cf_clearance", False),
    ],
)
def test_is_session_like(name, expected):
    assert _is_session_like(name) is expected


# =====================================================================
# Local login-form HTTP fixture
# =====================================================================


# State shared with the fixture: configured behaviour
_VALID_USER = "alice"
_VALID_PASS = "correct-horse-battery-staple"
_CSRF_VALUE = "csrf-token-xyz-12345"


class _LoginHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self) -> None:
        if self.path == "/login":
            body = f"""
            <html><body>
            <form method="post" action="/login">
              <input type="hidden" name="csrf_token" value="{_CSRF_VALUE}">
              <input type="text" name="username" required>
              <input type="password" name="password" required>
              <input type="submit" value="Login">
            </form>
            </body></html>
            """.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "csrftoken_cookie=set-on-get; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/dashboard":
            body = b"<h1>Welcome to your dashboard</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"not found")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        fields = dict(urllib.parse.parse_qsl(raw))
        if self.path != "/login":
            self.send_response(404)
            self.end_headers()
            return
        # CSRF check
        if fields.get("csrf_token") != _CSRF_VALUE:
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>CSRF token mismatch</h1>")
            return
        if (
            fields.get("username") == _VALID_USER
            and fields.get("password") == _VALID_PASS
        ):
            # Success: 302 to /dashboard + Set-Cookie session
            self.send_response(302)
            self.send_header("Set-Cookie", "session=abc-xyz-123; Path=/; HttpOnly")
            self.send_header("Location", "/dashboard")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # Failure: 200 with error message in body
        body = b"<h1>Login failed</h1><p>Invalid credentials</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def login_server():
    httpd = HTTPServer(("127.0.0.1", 0), _LoginHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base
    finally:
        httpd.shutdown()
        httpd.server_close()


# =====================================================================
# Happy path
# =====================================================================


def test_successful_login(login_server):
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password=_VALID_PASS),
    )
    session = execute_auth_flow(cfg)
    assert session.success is True
    assert session.csrf_token == _CSRF_VALUE
    cookie_names = {n for n, _ in session.cookies}
    assert "session" in cookie_names
    assert session.detected_signal  # some signal fired


def test_csrf_token_auto_extracted(login_server):
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password=_VALID_PASS),
    )
    session = execute_auth_flow(cfg)
    assert session.csrf_token == _CSRF_VALUE
    # X-CSRF-Token header in the captured headers
    header_names = {n for n, _ in session.headers}
    assert "X-CSRF-Token" in header_names


def test_failed_login_wrong_password(login_server):
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password="WRONG"),
    )
    session = execute_auth_flow(cfg)
    assert session.success is False
    assert "invalid credentials" in session.failure_reason.lower() or "no signal" in session.failure_reason.lower()


def test_no_form_csrf_when_auto_detect_off(login_server):
    """With auto_detect_form=False, CSRF won't be extracted —
    login will fail because POST is blocked by CSRF check."""
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password=_VALID_PASS),
        auto_detect_form=False,
    )
    session = execute_auth_flow(cfg)
    assert session.success is False


def test_explicit_status_signal(login_server):
    """expected_status=302 should match the 302 issued on success."""
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password=_VALID_PASS),
        success_signal=AuthSuccessSignal(expected_status=302),
        follow_redirects=False,
    )
    session = execute_auth_flow(cfg)
    assert session.success is True
    assert session.detected_signal == "status-match"


def test_explicit_cookie_signal(login_server):
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password=_VALID_PASS),
        success_signal=AuthSuccessSignal(expected_cookie_name="session"),
    )
    session = execute_auth_flow(cfg)
    assert session.success is True
    assert session.detected_signal == "cookie-match"


def test_explicit_body_signal(login_server):
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password=_VALID_PASS),
        success_signal=AuthSuccessSignal(expected_body_substring="welcome to your dashboard"),
    )
    session = execute_auth_flow(cfg)
    assert session.success is True


def test_explicit_redirect_signal(login_server):
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password=_VALID_PASS),
        success_signal=AuthSuccessSignal(expected_redirect_path="/dashboard"),
    )
    session = execute_auth_flow(cfg)
    assert session.success is True


def test_require_explicit_signal_blocks_heuristic(login_server):
    """With require_explicit_signal=True + no signals supplied,
    even a successful login should report failure."""
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(username=_VALID_USER, password=_VALID_PASS),
        require_explicit_signal=True,
    )
    session = execute_auth_flow(cfg)
    assert session.success is False
    assert "require_explicit_signal" in session.failure_reason


def test_extra_post_fields_passed(login_server):
    """Operator-supplied extra_fields override discovered ones."""
    cfg = AuthFlowConfig(
        login_url=f"{login_server}/login",
        credentials=LoginCredentials(
            username=_VALID_USER,
            password=_VALID_PASS,
            extra_fields=(("remember_me", "1"),),
        ),
    )
    session = execute_auth_flow(cfg)
    assert session.success is True


# =====================================================================
# Banca-safety
# =====================================================================


def test_off_origin_form_action_rejected():
    """Form action pointing to a different origin should be blocked
    to prevent credential leakage."""
    cfg = AuthFlowConfig(
        login_url="http://127.0.0.1:54321/login",
        credentials=LoginCredentials(username="x", password="y"),
        form_action_override="http://evil.example/steal-creds",
    )
    session = execute_auth_flow(cfg)
    assert session.success is False
    assert "off-origin" in session.failure_reason


def test_empty_login_url_rejected():
    with pytest.raises(ValueError):
        AuthFlowRunner(
            AuthFlowConfig(
                login_url="",
                credentials=LoginCredentials(username="x", password="y"),
            )
        )


def test_connection_failure_handled():
    """Unreachable target should return failure, not crash."""
    cfg = AuthFlowConfig(
        login_url="http://127.0.0.1:1/login",  # port 1 = unreachable
        credentials=LoginCredentials(username="x", password="y"),
        timeout_seconds=2.0,
    )
    session = execute_auth_flow(cfg)
    assert session.success is False
    assert "GET login page failed" in session.failure_reason


def test_jwt_in_body_signal():
    """When a JWT-shaped string appears in the response body and
    expected_jwt_in_body=True, that should count as success +
    captured as Bearer header."""
    import requests
    from unittest.mock import MagicMock, patch

    # We build a synthetic response with a JWT in the body.
    fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.AbcdefghIJKL"
    fake_resp = MagicMock(spec=requests.Response)
    fake_resp.status_code = 200
    fake_resp.url = "http://127.0.0.1:9999/login"
    fake_resp.text = f'{{"token": "{fake_jwt}"}}'
    fake_resp.history = []
    fake_resp.headers = {}
    fake_resp.cookies = []

    from kryon.tools.auth.runner import _classify_response

    cfg = AuthFlowConfig(
        login_url="http://127.0.0.1:9999/login",
        credentials=LoginCredentials(username="x", password="y"),
        success_signal=AuthSuccessSignal(expected_jwt_in_body=True),
    )
    ok, signal, reason = _classify_response(cfg, fake_resp, fake_resp.text, history=[])
    assert ok is True
    assert signal == "jwt-in-body"


# =====================================================================
# AuthSession dataclass guarantees
# =====================================================================


def test_auth_session_is_frozen():
    from dataclasses import FrozenInstanceError

    s = AuthSession(success=True)
    with pytest.raises(FrozenInstanceError):
        s.success = False  # type: ignore[misc]
