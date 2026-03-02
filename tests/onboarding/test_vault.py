"""Tests for credential vault."""

import pytest

cryptography = pytest.importorskip("cryptography")

from kryon.onboarding.vault import CredentialVault


def test_generate_key():
    key = CredentialVault.generate_key()
    assert isinstance(key, bytes)
    assert len(key) > 0


def test_encrypt_decrypt():
    key = CredentialVault.generate_key()
    vault = CredentialVault(key)
    data = {"username": "admin", "password": "secret123"}
    encrypted = vault.encrypt_credential(data)
    assert isinstance(encrypted, str)
    assert encrypted != str(data)
    decrypted = vault.decrypt_credential(encrypted)
    assert decrypted == data


def test_decrypt_wrong_key():
    key1 = CredentialVault.generate_key()
    key2 = CredentialVault.generate_key()
    vault1 = CredentialVault(key1)
    vault2 = CredentialVault(key2)
    encrypted = vault1.encrypt_credential({"secret": "data"})
    with pytest.raises(Exception):  # noqa: B017
        vault2.decrypt_credential(encrypted)


def test_encrypt_empty_dict():
    key = CredentialVault.generate_key()
    vault = CredentialVault(key)
    encrypted = vault.encrypt_credential({})
    decrypted = vault.decrypt_credential(encrypted)
    assert decrypted == {}


def test_vault_with_string_key():
    key = CredentialVault.generate_key()
    vault = CredentialVault(key.decode())
    data = {"api_key": "test-key"}
    encrypted = vault.encrypt_credential(data)
    decrypted = vault.decrypt_credential(encrypted)
    assert decrypted == data
