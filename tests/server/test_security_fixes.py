"""Tests for the #4 security fixes: RBAC on operational routes + SIEM token
encryption at rest."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from kryon.integrations.siem_secret import _MARKER, decrypt_token, encrypt_token
from kryon.server.auth.rbac import _has_permission, require_permission


# ------------------------------------------------------------------ RBAC ----
def test_viewer_cannot_write_analyst_can():
    assert _has_permission("analyst", "scans:write") is True
    assert _has_permission("viewer", "scans:write") is False
    assert _has_permission("analyst", "findings:write") is True
    assert _has_permission("viewer", "findings:write") is False
    assert _has_permission("viewer", "scans:read") is True  # reads still allowed
    assert _has_permission("admin", "scans:write") is True  # admin wildcard


async def test_require_permission_allows_api_key_mode():
    """user=None (API-key deployment, no JWT) must NOT be blocked for non-admin
    perms — otherwise the appliance breaks."""
    dep = require_permission("scans:write")
    assert await dep(user=None) is None


async def test_require_permission_blocks_viewer_write():
    from kryon.server.auth.models import User

    viewer = User(id="u1", username="v", email="v@example.com", role="viewer", password_hash="x")
    dep = require_permission("scans:write")
    with pytest.raises(HTTPException) as exc:
        await dep(user=viewer)
    assert exc.value.status_code == 403


# --------------------------------------------------------- SIEM token enc ----
def test_token_encryption_roundtrip_with_key(monkeypatch):
    from kryon.onboarding.vault import CredentialVault

    monkeypatch.setenv("KRYON_CREDENTIAL_KEY", CredentialVault.generate_key().decode())
    enc = encrypt_token("super-secret-splunk-token")
    assert enc.startswith(_MARKER)
    assert "super-secret" not in enc  # ciphertext, not plaintext
    assert decrypt_token(enc) == "super-secret-splunk-token"


def test_no_key_stores_plaintext(monkeypatch):
    """Without a key configured, tokens pass through (setup never fails)."""
    monkeypatch.delenv("KRYON_CREDENTIAL_KEY", raising=False)
    assert encrypt_token("tok") == "tok"
    assert decrypt_token("tok") == "tok"


def test_legacy_plaintext_passes_through_decrypt(monkeypatch):
    """A pre-existing unmarked token is returned unchanged even with a key set."""
    from kryon.onboarding.vault import CredentialVault

    monkeypatch.setenv("KRYON_CREDENTIAL_KEY", CredentialVault.generate_key().decode())
    assert decrypt_token("legacy-plaintext-token") == "legacy-plaintext-token"


def test_empty_token():
    assert encrypt_token("") == ""
    assert decrypt_token("") == ""
