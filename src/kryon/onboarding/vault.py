"""Credential vault — Fernet symmetric encryption for stored credentials."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


class CredentialVault:
    """Symmetric encryption vault for credentials using Fernet."""

    def __init__(self, encryption_key: bytes | str):
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise ImportError("cryptography is required. Install with: pip install cryptography") from exc

        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()
        self._fernet = Fernet(encryption_key)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new Fernet encryption key."""
        from cryptography.fernet import Fernet

        return Fernet.generate_key()

    def encrypt_credential(self, data: dict) -> str:
        """Encrypt credential data. Returns base64-encoded encrypted string."""
        plaintext = json.dumps(data).encode()
        return self._fernet.encrypt(plaintext).decode()

    def decrypt_credential(self, encrypted: str) -> dict:
        """Decrypt credential data. Returns original dict."""
        plaintext = self._fernet.decrypt(encrypted.encode())
        return json.loads(plaintext.decode())
