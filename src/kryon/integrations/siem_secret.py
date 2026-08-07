"""Encrypt SIEM integration tokens at rest.

Client credentials already go through the Fernet vault; SIEM tokens were the one
secret stored in plaintext. This closes that gap. Design:

- Gated on ``KRYON_CREDENTIAL_KEY`` (the same key the credential vault uses). If
  no key is configured, tokens are stored as-is (legacy behavior) — encryption
  is an opt-in hardening, never a hard dependency that breaks SIEM setup.
- Encrypted values carry a ``enc:v1:`` marker, so pre-existing plaintext tokens
  (no marker) pass through ``decrypt_token`` unchanged. Backward compatible.
"""

from __future__ import annotations

import os

_MARKER = "enc:v1:"


def _vault():
    key = os.getenv("KRYON_CREDENTIAL_KEY")
    if not key:
        return None
    try:
        from kryon.onboarding.vault import CredentialVault

        return CredentialVault(key)
    except Exception:
        return None


def encrypt_token(token: str) -> str:
    """Encrypt a SIEM token for storage. Returns plaintext unchanged when no
    encryption key is configured (so setup never fails on a missing key)."""
    if not token:
        return token
    vault = _vault()
    if vault is None:
        return token
    return _MARKER + vault.encrypt_credential({"t": token})


def decrypt_token(stored: str) -> str:
    """Decrypt a stored SIEM token. Plaintext (unmarked) legacy values pass
    through unchanged; a marked value with no key available yields ""."""
    if not stored or not stored.startswith(_MARKER):
        return stored
    vault = _vault()
    if vault is None:
        return ""
    try:
        return vault.decrypt_credential(stored[len(_MARKER) :]).get("t", "")
    except Exception:
        return ""
