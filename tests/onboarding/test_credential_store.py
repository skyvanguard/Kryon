"""Tests for the persistent named credential store (F1.4)."""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from kryon.onboarding.credential_store import CredentialStore, CredentialStoreError


def test_add_and_get_roundtrip(tmp_path):
    store = CredentialStore(base_dir=tmp_path)
    store.add("proxmox1", host="10.0.0.1", user="root", password="s3cret", ssh_port="22")
    cred = store.get("proxmox1")
    assert cred == {"host": "10.0.0.1", "user": "root", "password": "s3cret", "ssh_port": "22"}


def test_store_is_encrypted_on_disk(tmp_path):
    store = CredentialStore(base_dir=tmp_path)
    store.add("c1", host="h", user="u", password="PLAINTEXT_SECRET")
    blob = (tmp_path / "credentials.enc").read_text(encoding="utf-8")
    assert "PLAINTEXT_SECRET" not in blob  # encrypted at rest


def test_empty_fields_dropped(tmp_path):
    store = CredentialStore(base_dir=tmp_path)
    store.add("c1", host="h", user="", password="", notes="just a host")
    assert store.get("c1") == {"host": "h", "notes": "just a host"}


def test_list_and_remove(tmp_path):
    store = CredentialStore(base_dir=tmp_path)
    store.add("a", host="1")
    store.add("b", host="2")
    assert store.list_names() == ["a", "b"]
    assert store.remove("a") is True
    assert store.remove("missing") is False
    assert store.list_names() == ["b"]


def test_persists_across_instances(tmp_path):
    CredentialStore(base_dir=tmp_path).add("c1", host="h", user="u")
    # New instance reuses the same key file and decrypts the store.
    assert CredentialStore(base_dir=tmp_path).get("c1") == {"host": "h", "user": "u"}


def test_add_requires_name(tmp_path):
    store = CredentialStore(base_dir=tmp_path)
    with pytest.raises(ValueError, match="name is required"):
        store.add("", host="h")


def test_undecryptable_store_is_not_silently_wiped(tmp_path):
    """If the key no longer matches the store (rotated / restored from a different
    backup), reads/writes must fail loudly instead of returning {} — a prior bug
    let the next `add` overwrite credentials.enc with a single new credential,
    destroying every previously stored secret."""
    store = CredentialStore(base_dir=tmp_path)
    store.add("a", host="1", password="keep-me")
    store.add("b", host="2", password="keep-me-too")
    # Simulate a rotated key: regenerate vault.key so the existing store no longer decrypts.
    from kryon.onboarding.vault import CredentialVault

    (tmp_path / "vault.key").write_bytes(CredentialVault.generate_key())
    enc_before = (tmp_path / "credentials.enc").read_bytes()

    store2 = CredentialStore(base_dir=tmp_path)
    with pytest.raises(CredentialStoreError):
        store2.add("c", host="3")  # must NOT overwrite — must raise
    # The encrypted store on disk is untouched (no data loss).
    assert (tmp_path / "credentials.enc").read_bytes() == enc_before


def test_empty_store_file_is_legitimately_empty(tmp_path):
    """A present-but-empty store file is not a decrypt failure — treat as empty."""
    (tmp_path / "vault.key").write_bytes(
        __import__("kryon.onboarding.vault", fromlist=["x"]).CredentialVault.generate_key()
    )
    (tmp_path / "credentials.enc").write_text("", encoding="utf-8")
    store = CredentialStore(base_dir=tmp_path)
    assert store.list_names() == []
