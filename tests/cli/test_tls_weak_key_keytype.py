"""TLS weak-key check must be key-TYPE aware: an ECDSA P-256 cert (256-bit curve) is STRONG, not weak.
The old `< 2048` floor false-positived example.com's P-256 cert as CWE-326. EC floor is 256."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

from kryon.cli.service_probes import _tls_key_is_weak


def test_ecdsa_p256_is_strong():
    pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    weak, size, is_ec = _tls_key_is_weak(pub)
    assert is_ec and size == 256 and weak is False


def test_ecdsa_p192_is_weak():
    pub = ec.generate_private_key(ec.SECP192R1()).public_key()
    weak, size, is_ec = _tls_key_is_weak(pub)
    assert is_ec and size == 192 and weak is True


def test_rsa_1024_is_weak_2048_is_strong():
    assert _tls_key_is_weak(rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key())[0] is True
    assert _tls_key_is_weak(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())[0] is False


def test_dsa_1024_is_weak():
    assert _tls_key_is_weak(dsa.generate_private_key(key_size=1024).public_key())[0] is True


def test_ed25519_never_weak():
    weak, size, is_ec = _tls_key_is_weak(ed25519.Ed25519PrivateKey.generate().public_key())
    assert weak is False and size is None
