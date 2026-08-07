"""F1.4 — Persistent named credential store on top of the Fernet vault.

``CredentialVault`` only encrypts/decrypts a dict; it has no persistence or
per-engagement management. This adds a named store so an auditor can register a
credential once (``kryon credential add --name proxmox1 ...``) and reference it
(``kryon engage 10.0.0.1 --use-credential proxmox1``) instead of passing
secrets on the command line / SSHPASS each run.

Layout (under ``~/.kryon``):
  - ``vault.key``        — Fernet key (auto-generated, 0600).
  - ``credentials.enc``  — Fernet-encrypted JSON ``{name: {host,user,...}}``.
"""

from __future__ import annotations

import os
from pathlib import Path

from kryon.onboarding.vault import CredentialVault

_CRED_FIELDS = ("host", "user", "password", "ssh_key_path", "ssh_port", "notes")


class CredentialStoreError(RuntimeError):
    """Raised when ``credentials.enc`` exists but cannot be decrypted.

    Treating that case as "empty" (the old behavior) let the next ``add`` overwrite
    the file with a single credential, silently destroying every stored secret. We
    fail loudly instead so the operator can fix the key or move the file aside.
    """


class CredentialStore:
    """Encrypted, named credential store for engagements."""

    def __init__(self, base_dir: Path | None = None):
        self.base = Path(base_dir) if base_dir else (Path.home() / ".kryon")
        self.key_path = self.base / "vault.key"
        self.store_path = self.base / "credentials.enc"
        self._vault = CredentialVault(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes()
        self.base.mkdir(parents=True, exist_ok=True)
        key = CredentialVault.generate_key()
        self.key_path.write_bytes(key)
        _chmod_600(self.key_path)
        return key

    def _read_all(self) -> dict:
        if not self.store_path.exists():
            return {}
        raw = self.store_path.read_text(encoding="utf-8")
        if not raw.strip():
            return {}  # present but empty file — legitimately no credentials yet
        try:
            return self._vault.decrypt_credential(raw)
        except Exception as e:  # present but undecryptable — do NOT treat as empty
            # Returning {} here would let the caller's _write_all overwrite the
            # store with a single credential, destroying every stored secret.
            raise CredentialStoreError(
                f"'{self.store_path}' exists but could not be decrypted ({type(e).__name__}). "
                f"The vault key '{self.key_path}' may have been rotated or restored from a "
                "different backup. Refusing to treat the store as empty (that would overwrite "
                "and destroy stored credentials). Fix the key or move the store file aside."
            ) from e

    def _write_all(self, data: dict) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(self._vault.encrypt_credential(data), encoding="utf-8")
        _chmod_600(self.store_path)

    def add(self, name: str, **fields) -> None:
        """Store/overwrite a named credential (only known, non-empty fields)."""
        if not name:
            raise ValueError("credential name is required")
        data = self._read_all()
        data[name] = {k: v for k, v in fields.items() if k in _CRED_FIELDS and v}
        self._write_all(data)

    def get(self, name: str) -> dict | None:
        return self._read_all().get(name)

    def list_names(self) -> list[str]:
        return sorted(self._read_all().keys())

    def remove(self, name: str) -> bool:
        data = self._read_all()
        existed = name in data
        data.pop(name, None)
        self._write_all(data)
        return existed


def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)  # best-effort; no-op semantics on Windows
    except OSError:
        pass
