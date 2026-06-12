"""F100 TLS validation against cashbox.britimp.com.py.

Extracts the real TLS profile via stdlib ssl + cryptography (if
available), builds a TLSProfile, runs `analyze_tls_profile`."""

from __future__ import annotations

import socket
import ssl
import sys
from datetime import datetime, timezone

sys.path.insert(0, "src")

from kryon.tools.api.tls_audit import (
    TLSCertificate,
    TLSProfile,
    analyze_tls_profile,
)

HOST = "cashbox.britimp.com.py"
PORT = 443


def fetch_negotiated() -> tuple[str, str, dict, bytes]:
    """Open one TLS connection using default context.

    Returns (negotiated_protocol, negotiated_cipher, peer_cert_dict,
    der_bytes)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((HOST, PORT), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
            proto = ssock.version() or ""
            cipher_info = ssock.cipher() or ("", "", 0)
            cipher_name = cipher_info[0]
            cert_dict = ssock.getpeercert() or {}
            der = ssock.getpeercert(binary_form=True) or b""
            return proto, cipher_name, cert_dict, der


def probe_protocols() -> list[str]:
    """Try each protocol individually. Return list of accepted ones."""
    accepted: list[str] = []
    # Mapping from label → minimum_version constants. We try each
    # by forcing min=max.
    protocols = {
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        # The library may have removed older constants on modern
        # Pythons. We check via getattr.
    }
    for legacy in ("TLSv1_1", "TLSv1"):
        v = getattr(ssl.TLSVersion, legacy, None)
        if v is not None:
            label = legacy.replace("_", ".")
            protocols[label] = v

    for label, version in protocols.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((HOST, PORT), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=HOST):
                    accepted.append(label)
        except Exception:
            pass
    return accepted


def parse_cert(cert_dict: dict, der: bytes) -> TLSCertificate:
    """Convert ssl.getpeercert output → TLSCertificate."""
    # Subject + issuer are tuples-of-tuples-of-tuples in stdlib
    def _cn(name_tuples):
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
    # Try cryptography for richer cert info; degrade gracefully.
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import (
            ec, rsa, dsa, ed25519, ed448,
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


def main() -> int:
    print("=" * 72)
    print(f"F100 TLS VALIDATION — {HOST}:{PORT}")
    print(f"timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    try:
        proto, cipher, cert_dict, der = fetch_negotiated()
    except Exception as e:
        print(f"ERROR establishing TLS: {e}")
        return 1

    print(f"\nnegotiated_protocol: {proto}")
    print(f"negotiated_cipher:   {cipher}")

    print("\nprobing supported protocols (per-version handshakes)...")
    supported = probe_protocols()
    print(f"supported_protocols: {supported}")

    cert = parse_cert(cert_dict, der)
    print("\ncertificate:")
    print(f"  subject_cn:  {cert.subject_common_name}")
    print(f"  issuer_cn:   {cert.issuer_common_name}")
    print(f"  not_before:  {cert.not_before}")
    print(f"  not_after:   {cert.not_after}")
    print(f"  key:         {cert.key_algorithm} {cert.key_size_bits} bits")
    print(f"  sig_algo:    {cert.signature_algorithm}")
    print(f"  san:         {cert.san_dns_names}")
    print(f"  self_signed: {cert.is_self_signed}")

    profile = TLSProfile(
        hostname=HOST,
        port=PORT,
        negotiated_protocol=proto,
        supported_protocols=tuple(supported),
        negotiated_cipher=cipher,
        supported_ciphers=(),  # extracting full list would need openssl
        certificate=cert,
    )

    analysis = analyze_tls_profile(profile)
    print("\n" + "=" * 72)
    print(f"F100 ANALYSIS — {len(analysis.findings)} findings")
    print("=" * 72)
    by_sev: dict[str, int] = {}
    for f in analysis.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        print(f"  [{f.severity:8s}] {f.rule_id}: {f.title}")
    print("\nby severity:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in by_sev:
            print(f"  {sev:8s}: {by_sev[sev]}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
