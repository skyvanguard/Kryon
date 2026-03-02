"""Tests for TLS certificate utilities."""

import pytest

from kryon.server.setup.tls import get_uvicorn_ssl_kwargs


def test_ssl_kwargs_disabled():
    """No SSL kwargs when HTTPS is disabled."""
    from kryon.server.config import ServerConfig

    config = ServerConfig(https_enabled=False)
    assert get_uvicorn_ssl_kwargs(config) == {}


def test_ssl_kwargs_enabled():
    """SSL kwargs when HTTPS is enabled with cert paths."""
    from kryon.server.config import ServerConfig

    config = ServerConfig(
        https_enabled=True,
        ssl_certfile="/path/to/cert.pem",
        ssl_keyfile="/path/to/key.pem",
    )
    kwargs = get_uvicorn_ssl_kwargs(config)
    assert kwargs["ssl_certfile"] == "/path/to/cert.pem"
    assert kwargs["ssl_keyfile"] == "/path/to/key.pem"


def test_generate_self_signed_cert(tmp_path):
    """Self-signed cert generation (only if cryptography is installed)."""
    try:
        from kryon.server.setup.tls import generate_self_signed_cert

        cert_path, key_path = generate_self_signed_cert(
            domain="test.local",
            output_dir=tmp_path / "tls",
        )
        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_path.read_bytes().startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    except ImportError:
        pytest.skip("cryptography not installed")
