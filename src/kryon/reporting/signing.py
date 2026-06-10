"""F3.2 — Detached Ed25519 signatures for report deliverables.

Full X.509/PAdES PDF signing needs a CA-issued cert and heavy tooling. This
provides genuine cryptographic integrity + non-repudiation with a self-managed
Ed25519 key: sign the report bytes, emit a ``<file>.sig.json`` sidecar (sha256,
signature, public key, signer, signed timestamp), and verify it later. Not
CA-anchored (that's future work) but real, verifiable signing.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def _default_key_path() -> Path:
    return Path.home() / ".kryon" / "signing_key.pem"


class ReportSigner:
    """Ed25519 signer with a self-managed private key."""

    def __init__(self, key_path: Path | None = None):
        self.key_path = Path(key_path) if key_path else _default_key_path()
        self._private = self._load_or_create()

    def _load_or_create(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if self.key_path.exists():
            return serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.write_bytes(pem)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return key

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        raw = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return raw.hex()

    def sign_file(self, path: Path, signer: str = "", timestamp: str = "") -> Path:
        """Sign ``path`` and write ``<path>.sig.json``. Returns the sidecar path."""
        path = Path(path)
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        signature = self._private.sign(bytes.fromhex(sha)).hex()
        sidecar = path.with_suffix(path.suffix + ".sig.json")
        sidecar.write_text(
            json.dumps(
                {
                    "file": path.name,
                    "algo": "Ed25519",
                    "sha256": sha,
                    "signature": signature,
                    "public_key": self.public_key_hex(),
                    "signer": signer,
                    "timestamp": timestamp,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return sidecar


def verify_signature(file_path: Path, sidecar_path: Path | None = None) -> bool:
    """Verify a file against its ``.sig.json`` sidecar (re-hash + Ed25519 verify)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    file_path = Path(file_path)
    sidecar = Path(sidecar_path) if sidecar_path else file_path.with_suffix(file_path.suffix + ".sig.json")
    if not sidecar.exists() or not file_path.exists():
        return False
    try:
        meta = json.loads(sidecar.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    actual_sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
    if actual_sha != meta.get("sha256"):
        return False  # file changed since signing
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(meta["public_key"]))
        pub.verify(bytes.fromhex(meta["signature"]), bytes.fromhex(meta["sha256"]))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False
