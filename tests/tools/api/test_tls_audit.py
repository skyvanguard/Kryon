"""F100 — TDD contract for the TLS profile auditor.

Coverage:
  - Each TLS-NNN rule POSITIVE + NEGATIVE.
  - Helpers: ISO datetime parser, hostname/SAN matcher (RFC 6125).
  - Realistic fixtures: Let's Encrypt-style modern profile (0 HIGH+),
    legacy weak profile (many findings).
  - Drift test: cashbox.britimp.com.py-like profile (TLS 1.3 + LE R13)
    should produce minimal findings.
  - Frozen contracts + ALL_TLS_RULES pinned.
  - Tool wrapper.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from kryon.tools.api.tls_audit import (
    ALL_TLS_RULES,
    MIN_ECDSA_KEY_BITS,
    MIN_RSA_KEY_BITS,
    WEAK_CIPHER_PATTERNS,
    TLSAnalysis,
    TLSCertificate,
    TLSFinding,
    TLSProfile,
    _hostname_matches_dns_name,
    _parse_iso_datetime,
    analyze_tls_profile,
)


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _utc_iso(days_from_now: int) -> str:
    """Build an ISO 8601 UTC timestamp `days_from_now` days from
    now."""
    t = datetime.now(timezone.utc) + timedelta(days=days_from_now)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _good_cert(*, days_valid: int = 90) -> TLSCertificate:
    return TLSCertificate(
        subject_common_name="example.com",
        issuer_common_name="Let's Encrypt R13",
        not_before=_utc_iso(-1),
        not_after=_utc_iso(days_valid),
        key_algorithm="RSA",
        key_size_bits=2048,
        signature_algorithm="sha256WithRSAEncryption",
        san_dns_names=("example.com", "www.example.com"),
        is_self_signed=False,
    )


def _modern_profile() -> TLSProfile:
    return TLSProfile(
        hostname="example.com",
        port=443,
        negotiated_protocol="TLSv1.3",
        supported_protocols=("TLSv1.2", "TLSv1.3"),
        negotiated_cipher="TLS_AES_256_GCM_SHA384",
        supported_ciphers=("TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"),
        certificate=_good_cert(),
    )


# =====================================================================
# Helpers
# =====================================================================


def test_parse_iso_datetime_basic():
    dt = _parse_iso_datetime("2026-05-13T12:00:00Z")
    assert dt is not None
    assert dt.year == 2026


def test_parse_iso_datetime_with_subsecond():
    dt = _parse_iso_datetime("2026-05-13T12:00:00.123Z")
    assert dt is not None


def test_parse_iso_datetime_invalid_returns_none():
    assert _parse_iso_datetime("not a date") is None
    assert _parse_iso_datetime("") is None


def test_hostname_matches_exact():
    assert _hostname_matches_dns_name("example.com", "example.com") is True
    assert _hostname_matches_dns_name("Example.com", "example.com") is True  # case insensitive


def test_hostname_matches_wildcard_one_label():
    assert _hostname_matches_dns_name("foo.example.com", "*.example.com") is True


def test_hostname_does_not_match_wildcard_deep():
    """RFC 6125 wildcard matching is ONE label only."""
    assert _hostname_matches_dns_name("foo.bar.example.com", "*.example.com") is False


def test_hostname_mismatch():
    assert _hostname_matches_dns_name("example.com", "other.com") is False


# =====================================================================
# Group A — Protocols
# =====================================================================


def test_tls_001_tls_10_enabled_fires():
    p = _modern_profile()
    p = TLSProfile(**{**p.__dict__, "supported_protocols": ("TLSv1.0", "TLSv1.2", "TLSv1.3")})
    assert "TLS-001" in _ids(analyze_tls_profile(p).findings)


def test_tls_001_silent_when_no_tls_10():
    assert "TLS-001" not in _ids(analyze_tls_profile(_modern_profile()).findings)


def test_tls_002_tls_11_enabled_fires():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_protocols": ("TLSv1.1", "TLSv1.2", "TLSv1.3")})
    assert "TLS-002" in _ids(analyze_tls_profile(p).findings)


def test_tls_003_sslv3_fires_critical():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_protocols": ("SSLv3", "TLSv1.2", "TLSv1.3")})
    findings = analyze_tls_profile(p).findings
    crit = [f for f in findings if f.rule_id == "TLS-003"]
    assert crit and crit[0].severity == "CRITICAL"


def test_tls_003_sslv2_fires_critical():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_protocols": ("SSLv2",)})
    findings = analyze_tls_profile(p).findings
    assert any(f.rule_id == "TLS-003" and f.severity == "CRITICAL" for f in findings)


def test_tls_004_no_tls_13_fires_info():
    p = TLSProfile(
        **{**_modern_profile().__dict__, "supported_protocols": ("TLSv1.2",), "negotiated_protocol": "TLSv1.2"}
    )
    findings = analyze_tls_profile(p).findings
    info = [f for f in findings if f.rule_id == "TLS-004"]
    assert info and info[0].severity == "INFO"


def test_tls_004_with_tls_13_silent():
    assert "TLS-004" not in _ids(analyze_tls_profile(_modern_profile()).findings)


# =====================================================================
# Group B — Ciphers
# =====================================================================


def test_tls_010_rc4_fires_high():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_ciphers": ("ECDHE-RSA-RC4-SHA",)})
    findings = analyze_tls_profile(p).findings
    rc4 = [f for f in findings if f.rule_id == "TLS-010"]
    assert rc4 and rc4[0].severity == "HIGH"


def test_tls_010_3des_fires():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_ciphers": ("ECDHE-RSA-DES-CBC3-SHA",)})
    assert "TLS-010" in _ids(analyze_tls_profile(p).findings)


def test_tls_010_plain_des_fires():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_ciphers": ("TLS_RSA_WITH_DES_CBC_SHA",)})
    assert "TLS-010" in _ids(analyze_tls_profile(p).findings)


def test_tls_011_null_cipher_fires_critical():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_ciphers": ("TLS_RSA_WITH_NULL_SHA",)})
    findings = analyze_tls_profile(p).findings
    null = [f for f in findings if f.rule_id == "TLS-011"]
    assert null and null[0].severity == "CRITICAL"


def test_tls_011_anon_cipher_fires_critical():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_ciphers": ("TLS_DH_anon_WITH_AES_256_CBC_SHA",)})
    findings = analyze_tls_profile(p).findings
    anon = [f for f in findings if f.rule_id == "TLS-011"]
    assert anon and anon[0].severity == "CRITICAL"


def test_tls_012_export_cipher_fires_critical():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_ciphers": ("EXP-RC4-MD5",)})
    findings = analyze_tls_profile(p).findings
    exp = [f for f in findings if f.rule_id == "TLS-012"]
    assert exp and exp[0].severity == "CRITICAL"


def test_tls_013_no_forward_secrecy_fires():
    """Static RSA key exchange = no FS."""
    p = TLSProfile(**{**_modern_profile().__dict__, "negotiated_cipher": "AES256-SHA256"})
    assert "TLS-013" in _ids(analyze_tls_profile(p).findings)


def test_tls_013_ecdhe_silent():
    p = TLSProfile(**{**_modern_profile().__dict__, "negotiated_cipher": "ECDHE-RSA-AES256-GCM-SHA384"})
    assert "TLS-013" not in _ids(analyze_tls_profile(p).findings)


def test_tls_013_tls13_aead_silent():
    """TLS 1.3 builtin ciphers always have forward secrecy by
    construction."""
    p = _modern_profile()  # uses TLS_AES_256_GCM_SHA384
    assert "TLS-013" not in _ids(analyze_tls_profile(p).findings)


def test_tls_014_md5_mac_fires():
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_ciphers": ("ECDHE-RSA-AES128-SHA-MD5",)})
    # MD5 alone in cipher name
    p = TLSProfile(**{**_modern_profile().__dict__, "supported_ciphers": ("TLS_RSA_WITH_RC2_CBC_40_MD5",)})
    assert "TLS-014" in _ids(analyze_tls_profile(p).findings)


def test_weak_cipher_patterns_pinned():
    """Pin the categories so silent removal can't sneak through."""
    assert "RC4" in WEAK_CIPHER_PATTERNS
    assert "3DES" in WEAK_CIPHER_PATTERNS
    assert "NULL" in WEAK_CIPHER_PATTERNS
    assert "EXPORT" in WEAK_CIPHER_PATTERNS


# =====================================================================
# Group C — Key + Signature
# =====================================================================


def test_tls_020_rsa_1024_fires():
    cert = TLSCertificate(**{**_good_cert().__dict__, "key_size_bits": 1024})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    assert "TLS-020" in _ids(analyze_tls_profile(p).findings)


def test_tls_020_rsa_2048_silent():
    """Exactly 2048 should NOT fire."""
    p = _modern_profile()  # 2048-bit RSA
    assert "TLS-020" not in _ids(analyze_tls_profile(p).findings)


def test_tls_020_rsa_4096_silent():
    cert = TLSCertificate(**{**_good_cert().__dict__, "key_size_bits": 4096})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    assert "TLS-020" not in _ids(analyze_tls_profile(p).findings)


def test_tls_021_ecdsa_192_fires():
    cert = TLSCertificate(**{**_good_cert().__dict__, "key_algorithm": "EC", "key_size_bits": 192})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    assert "TLS-021" in _ids(analyze_tls_profile(p).findings)


def test_tls_021_ecdsa_256_silent():
    cert = TLSCertificate(**{**_good_cert().__dict__, "key_algorithm": "EC", "key_size_bits": 256})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    assert "TLS-021" not in _ids(analyze_tls_profile(p).findings)


def test_tls_022_sha1_signature_fires():
    cert = TLSCertificate(**{**_good_cert().__dict__, "signature_algorithm": "sha1WithRSAEncryption"})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    findings = analyze_tls_profile(p).findings
    sha1 = [f for f in findings if f.rule_id == "TLS-022"]
    assert sha1 and sha1[0].severity == "HIGH"


def test_tls_023_md5_signature_fires_critical():
    cert = TLSCertificate(**{**_good_cert().__dict__, "signature_algorithm": "md5WithRSAEncryption"})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    findings = analyze_tls_profile(p).findings
    md5 = [f for f in findings if f.rule_id == "TLS-023"]
    assert md5 and md5[0].severity == "CRITICAL"


def test_modern_sha256_signature_silent():
    p = _modern_profile()  # sha256WithRSAEncryption
    ids = _ids(analyze_tls_profile(p).findings)
    assert "TLS-022" not in ids
    assert "TLS-023" not in ids


# =====================================================================
# Group D — Certificate
# =====================================================================


def test_tls_030_expired_cert_fires_critical():
    cert = TLSCertificate(**{**_good_cert().__dict__, "not_after": _utc_iso(-5)})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    findings = analyze_tls_profile(p).findings
    expired = [f for f in findings if f.rule_id == "TLS-030"]
    assert expired and expired[0].severity == "CRITICAL"


def test_tls_031_expires_in_3_days_fires_critical():
    cert = TLSCertificate(**{**_good_cert().__dict__, "not_after": _utc_iso(3)})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    findings = analyze_tls_profile(p).findings
    soon = [f for f in findings if f.rule_id == "TLS-031"]
    assert soon and soon[0].severity == "CRITICAL"


def test_tls_032_expires_in_20_days_fires_high():
    cert = TLSCertificate(**{**_good_cert().__dict__, "not_after": _utc_iso(20)})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    findings = analyze_tls_profile(p).findings
    soon = [f for f in findings if f.rule_id == "TLS-032"]
    assert soon and soon[0].severity == "HIGH"


def test_tls_032_silent_when_well_in_future():
    p = _modern_profile()  # 90 days valid
    ids = _ids(analyze_tls_profile(p).findings)
    assert "TLS-030" not in ids
    assert "TLS-031" not in ids
    assert "TLS-032" not in ids


def test_tls_040_self_signed_fires():
    cert = TLSCertificate(**{**_good_cert().__dict__, "is_self_signed": True})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    findings = analyze_tls_profile(p).findings
    selfs = [f for f in findings if f.rule_id == "TLS-040"]
    assert selfs and selfs[0].severity == "HIGH"


def test_tls_041_hostname_not_in_san_fires():
    cert = TLSCertificate(**{**_good_cert().__dict__, "san_dns_names": ("other.example.org",)})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    findings = analyze_tls_profile(p).findings
    assert "TLS-041" in _ids(findings)


def test_tls_041_hostname_in_san_silent():
    p = _modern_profile()  # SAN has example.com which matches hostname
    assert "TLS-041" not in _ids(analyze_tls_profile(p).findings)


def test_tls_041_wildcard_san_matches():
    cert = TLSCertificate(**{**_good_cert().__dict__, "san_dns_names": ("*.example.com",)})
    p = TLSProfile(**{**_modern_profile().__dict__, "hostname": "app.example.com", "certificate": cert})
    assert "TLS-041" not in _ids(analyze_tls_profile(p).findings)


def test_tls_042_no_san_fires():
    cert = TLSCertificate(**{**_good_cert().__dict__, "san_dns_names": ()})
    p = TLSProfile(**{**_modern_profile().__dict__, "certificate": cert})
    findings = analyze_tls_profile(p).findings
    no_san = [f for f in findings if f.rule_id == "TLS-042"]
    assert no_san and no_san[0].severity == "MEDIUM"


# =====================================================================
# Realistic fixtures
# =====================================================================


def test_realistic_modern_profile_no_high_findings():
    """A correctly-configured modern banking endpoint should produce
    0 HIGH/CRITICAL/MEDIUM findings."""
    analysis = analyze_tls_profile(_modern_profile())
    severe = [f for f in analysis.findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
    assert not severe, f"Modern profile produced severe findings: {severe}"


def test_realistic_legacy_profile_surfaces_multiple_findings():
    """A legacy endpoint with TLS 1.0 + RC4 + RSA 1024 + SHA-1
    signature → many findings."""
    cert = TLSCertificate(
        subject_common_name="legacy.bank.example",
        issuer_common_name="Old CA",
        not_before=_utc_iso(-365),
        not_after=_utc_iso(180),
        key_algorithm="RSA",
        key_size_bits=1024,
        signature_algorithm="sha1WithRSAEncryption",
        san_dns_names=(),
        is_self_signed=False,
    )
    p = TLSProfile(
        hostname="legacy.bank.example",
        port=443,
        negotiated_protocol="TLSv1.0",
        supported_protocols=("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"),
        negotiated_cipher="ECDHE-RSA-RC4-SHA",
        supported_ciphers=("ECDHE-RSA-RC4-SHA", "ECDHE-RSA-DES-CBC3-SHA", "EXP-RC4-MD5"),
        certificate=cert,
    )
    ids = _ids(analyze_tls_profile(p).findings)
    expected = {
        "TLS-001",  # TLS 1.0
        "TLS-002",  # TLS 1.1
        "TLS-003",  # SSLv3
        "TLS-010",  # weak cipher (RC4 / 3DES)
        "TLS-012",  # export cipher
        "TLS-020",  # RSA 1024
        "TLS-022",  # SHA-1 signature
        "TLS-042",  # no SAN
    }
    assert expected <= ids, f"Legacy profile missing rules: {expected - ids}"


def test_cashbox_britimp_like_profile_minimal_findings():
    """Profile resembling cashbox.britimp.com.py (TLS 1.3 + AES-256-GCM
    + Let's Encrypt R13). The original probe confirmed strong TLS;
    F100 should agree."""
    cert = TLSCertificate(
        subject_common_name="cashbox.britimp.com.py",
        issuer_common_name="R13",
        not_before=_utc_iso(-30),
        not_after=_utc_iso(60),
        key_algorithm="EC",
        key_size_bits=256,
        signature_algorithm="ecdsa-with-SHA256",
        san_dns_names=("cashbox.britimp.com.py",),
        is_self_signed=False,
    )
    p = TLSProfile(
        hostname="cashbox.britimp.com.py",
        port=443,
        negotiated_protocol="TLSv1.3",
        supported_protocols=("TLSv1.2", "TLSv1.3"),
        negotiated_cipher="TLS_AES_256_GCM_SHA384",
        supported_ciphers=("TLS_AES_256_GCM_SHA384",),
        certificate=cert,
    )
    findings = analyze_tls_profile(p).findings
    # Modern profile → 0 HIGH/CRITICAL findings.
    severe = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert not severe, f"cashbox-like profile has unexpected severe findings: {severe}"


# =====================================================================
# Sorting + pinning
# =====================================================================


def test_findings_sorted_by_severity():
    """Mix CRITICAL + HIGH + MEDIUM + INFO findings; check ordering."""
    cert = TLSCertificate(
        **{**_good_cert().__dict__, "not_after": _utc_iso(-1), "signature_algorithm": "sha1WithRSAEncryption"}
    )
    p = TLSProfile(
        hostname="example.com",
        port=443,
        negotiated_protocol="TLSv1.2",
        supported_protocols=("SSLv3", "TLSv1.0", "TLSv1.2"),  # crit + high
        negotiated_cipher="AES256-SHA256",
        supported_ciphers=(),
        certificate=cert,
    )
    findings = analyze_tls_profile(p).findings
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_all_tls_rules_pinned():
    expected = (
        {f"TLS-00{i}" for i in range(1, 5)}
        | {f"TLS-01{i}" for i in range(0, 5)}
        | {f"TLS-02{i}" for i in range(0, 4)}
        | {f"TLS-03{i}" for i in range(0, 3)}
        | {f"TLS-04{i}" for i in range(0, 3)}
    )
    assert expected <= ALL_TLS_RULES


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    cert = _good_cert()
    with pytest.raises(FrozenInstanceError):
        cert.key_size_bits = 4096  # type: ignore[misc]

    p = TLSProfile()
    with pytest.raises(FrozenInstanceError):
        p.hostname = "x"  # type: ignore[misc]

    f = TLSFinding(rule_id="TLS-001", severity="HIGH", title="x", detail="x", remediation="x")
    with pytest.raises(FrozenInstanceError):
        f.severity = "LOW"  # type: ignore[misc]

    a = TLSAnalysis(hostname="x")
    with pytest.raises(FrozenInstanceError):
        a.hostname = "y"  # type: ignore[misc]


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_wrapper_dict_shape():
    from kryon.tools.api.tls_audit_tool import _analysis_to_dict

    analysis = analyze_tls_profile(_modern_profile())
    payload = _analysis_to_dict(analysis)
    assert payload["hostname"] == "example.com"
    assert payload["finding_count"] >= 0
    json.dumps(payload)


def test_tool_wrapper_handles_missing_cert():
    """A profile without cert info should still analyze the protocol +
    cipher side, just skip cert checks."""
    p = TLSProfile(
        hostname="example.com",
        supported_protocols=("TLSv1.0", "TLSv1.2"),
        negotiated_protocol="TLSv1.2",
        certificate=None,
    )
    analysis = analyze_tls_profile(p)
    ids = _ids(analysis.findings)
    assert "TLS-001" in ids
    # Cert-side checks silent.
    assert "TLS-030" not in ids
    assert "TLS-040" not in ids
