"""F109 — TLS profile capture via stdlib ssl. Returns a TLSProfile
compatible with F100 analyze_tls_profile."""

from __future__ import annotations

import socket
import ssl

from kryon.tools.api.tls_audit import TLSCertificate, TLSProfile

__all__ = ["capture_tls_profile"]


def _negotiated(host: str, port: int, timeout: float) -> tuple[str, str, dict, bytes]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            proto = ssock.version() or ""
            cipher_info = ssock.cipher() or ("", "", 0)
            cipher_name = cipher_info[0]
            cert_dict = ssock.getpeercert() or {}
            der = ssock.getpeercert(binary_form=True) or b""
            return proto, cipher_name, cert_dict, der


def _probe_protocols(host: str, port: int, timeout: float) -> list[str]:
    accepted: list[str] = []
    protocols = {
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    }
    for legacy in ("TLSv1_1", "TLSv1"):
        v = getattr(ssl.TLSVersion, legacy, None)
        if v is not None:
            protocols[legacy.replace("_", ".")] = v
    for label, version in protocols.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    accepted.append(label)
        except Exception:
            pass
    return accepted


def _parse_cert(cert_dict: dict, der: bytes) -> TLSCertificate:
    def _cn(name_tuples) -> str:
        for rdn in name_tuples or ():
            for k, v in rdn:
                if k == "commonName":
                    return v
        return ""

    subject_cn = _cn(cert_dict.get("subject"))
    issuer_cn = _cn(cert_dict.get("issuer"))
    not_before = cert_dict.get("notBefore", "")
    not_after = cert_dict.get("notAfter", "")
    serial = cert_dict.get("serialNumber", "")
    san: list[str] = []
    for k, v in cert_dict.get("subjectAltName", ()):
        if k == "DNS":
            san.append(v)

    key_algo = ""
    key_bits = 0
    sig_algo = ""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import (
            dsa,
            ec,
            ed25519,
            ed448,
            rsa,
        )

        cert = x509.load_der_x509_certificate(der)
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key_algo = "RSA"
            key_bits = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_algo = "ECDSA"
            key_bits = pub.curve.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            key_algo = "DSA"
            key_bits = pub.key_size
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key_algo = "EdDSA"
            key_bits = 256
        sig_algo = cert.signature_algorithm_oid._name or sig_algo
    except Exception:
        pass

    return TLSCertificate(
        subject_common_name=subject_cn,
        issuer_common_name=issuer_cn,
        not_before=not_before,
        not_after=not_after,
        key_algorithm=key_algo,
        key_size_bits=key_bits,
        signature_algorithm=sig_algo,
        san_dns_names=tuple(san),
        is_self_signed=(subject_cn == issuer_cn and subject_cn != ""),
        serial_number=serial,
    )


def capture_tls_profile(
    host: str, port: int = 443, timeout: float = 5.0
) -> TLSProfile | None:
    """Open a live TLS connection to (host, port) and return a
    TLSProfile. Returns None if connection fails."""
    try:
        proto, cipher, cert_dict, der = _negotiated(host, port, timeout)
    except Exception:
        return None
    supported = _probe_protocols(host, port, timeout)
    cert = _parse_cert(cert_dict, der)
    return TLSProfile(
        hostname=host,
        port=port,
        negotiated_protocol=proto,
        supported_protocols=tuple(supported),
        negotiated_cipher=cipher,
        supported_ciphers=(),
        certificate=cert,
    )
