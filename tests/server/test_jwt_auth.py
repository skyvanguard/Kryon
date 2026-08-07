"""Tests for JWT authentication system."""

import time

import jwt as pyjwt
import pytest

from kryon.server.auth.jwt_auth import (
    configure_jwt,
    create_access_token,
    create_refresh_token,
    decode_token,
    is_jwt_configured,
)
from kryon.server.auth.password import hash_password, verify_password


@pytest.fixture(autouse=True)
def setup_jwt():
    """Configure JWT for all tests in this module."""
    configure_jwt("test-secret-key-0123456789abcdef", access_ttl_minutes=60)
    yield
    configure_jwt("", access_ttl_minutes=60)  # Reset


def test_jwt_configured():
    assert is_jwt_configured() is True
    configure_jwt("")
    assert is_jwt_configured() is False
    configure_jwt("test-secret-key-0123456789abcdef")


def test_configure_jwt_rejects_short_secret():
    """A non-empty secret below 32 chars is a weak HMAC key for HS256 and must
    be rejected loudly at startup, not accepted silently."""
    with pytest.raises(ValueError, match="too short"):
        configure_jwt("short-key-21-bytes-xx")  # 21 chars
    # Restore a valid secret so the autouse teardown/other tests are unaffected.
    configure_jwt("test-secret-key-0123456789abcdef")


def test_configure_jwt_allows_empty_reset():
    """Empty string is the 'unconfigured' sentinel — must stay valid."""
    configure_jwt("")
    assert is_jwt_configured() is False
    configure_jwt("test-secret-key-0123456789abcdef")
    assert is_jwt_configured() is True


def test_configure_jwt_accepts_32_char_secret():
    """A 32-char secret meets the minimum and is accepted."""
    configure_jwt("a" * 32)
    assert is_jwt_configured() is True
    configure_jwt("test-secret-key-0123456789abcdef")


def test_create_access_token():
    token = create_access_token("user-1", "admin", "admin")
    payload = decode_token(token)
    assert payload["sub"] == "user-1"
    assert payload["username"] == "admin"
    assert payload["role"] == "admin"
    assert payload["type"] == "access"


def test_create_refresh_token():
    token = create_refresh_token("user-1")
    payload = decode_token(token)
    assert payload["sub"] == "user-1"
    assert payload["type"] == "refresh"


def test_decode_invalid_token():
    with pytest.raises(pyjwt.PyJWTError):
        decode_token("invalid.token.here")


def test_decode_wrong_secret():
    token = create_access_token("user-1", "admin", "admin")
    configure_jwt("different-secret-0123456789abcdef")
    with pytest.raises(pyjwt.PyJWTError):
        decode_token(token)
    configure_jwt("test-secret-key-0123456789abcdef")


def test_password_hashing():
    pw = "my-secure-password"
    hashed = hash_password(pw)
    assert hashed != pw
    assert verify_password(pw, hashed) is True
    assert verify_password("wrong", hashed) is False


def test_token_has_expiry():
    token = create_access_token("user-1", "admin", "admin")
    payload = decode_token(token)
    assert "exp" in payload
    assert payload["exp"] > time.time()


def test_refresh_token_longer_expiry():
    access = create_access_token("user-1", "admin", "admin")
    refresh = create_refresh_token("user-1")
    a_payload = decode_token(access)
    r_payload = decode_token(refresh)
    assert r_payload["exp"] > a_payload["exp"]
