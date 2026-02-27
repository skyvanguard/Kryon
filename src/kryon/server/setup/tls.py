"""TLS certificate utilities for HTTPS support."""

from __future__ import annotations

import datetime
import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_self_signed_cert(
    domain: str = "localhost",
    output_dir: Path | None = None,
    key_passphrase: bytes | None = None,
) -> tuple[Path, Path]:
    """Generate a self-signed TLS certificate.

    Returns (cert_path, key_path).
    Requires the `cryptography` library.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        raise ImportError(
            "TLS cert generation requires 'cryptography'. "
            "Install with: pip install cryptography"
        )

    if output_dir is None:
        output_dir = Path.home() / ".kryon" / "tls"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KRYON"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = output_dir / "cert.pem"
    key_path = output_dir / "key.pem"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    encryption = (
        serialization.BestAvailableEncryption(key_passphrase)
        if key_passphrase
        else serialization.NoEncryption()
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            encryption,
        )
    )

    logger.info("Self-signed cert generated: %s (domain=%s)", cert_path, domain)
    return cert_path, key_path


def get_uvicorn_ssl_kwargs(config) -> dict:
    """Get uvicorn SSL keyword arguments from ServerConfig."""
    if not config.https_enabled:
        return {}
    kwargs = {}
    if config.ssl_certfile:
        kwargs["ssl_certfile"] = config.ssl_certfile
    if config.ssl_keyfile:
        kwargs["ssl_keyfile"] = config.ssl_keyfile
    return kwargs
