"""F100 — TLS Profile Audit (handshake + certificate).

Complements F97 HTTP Security Headers + F98 Cookie Security with
the transport layer below. Banking deployments routinely keep
deprecated TLS 1.0/1.1 enabled "for legacy clients" — that's where
real MITM ends up. Every banking engagement audit produces TLS
profile findings; F100 makes the analysis reproducible.

This module is PURE STATIC ANALYSIS. The operator probes the target
(`openssl s_client -connect host:443 -servername host`, nmap
`--script ssl-enum-ciphers`, sslyze, Python's `ssl.SSLContext`,
etc.), extracts the protocol version + cipher + certificate details,
and hands them to the analyzer.

17 rules across 4 groups (stable TLS-NNN IDs):

  Group A — Protocols (CRITICAL / HIGH / MEDIUM)
    TLS-001  TLS 1.0 enabled
    TLS-002  TLS 1.1 enabled
    TLS-003  SSLv2/SSLv3 enabled
    TLS-004  No TLS 1.3 support announced (modern baseline)

  Group B — Ciphers (CRITICAL / HIGH / MEDIUM)
    TLS-010  Weak symmetric cipher (RC4 / DES / 3DES)
    TLS-011  NULL / anonymous (DH_anon) cipher
    TLS-012  Export-grade cipher (40/56-bit)
    TLS-013  No forward secrecy (no ECDHE/DHE in negotiated)
    TLS-014  MD5-based MAC

  Group C — Key + Signature (HIGH / CRITICAL)
    TLS-020  RSA key < 2048 bits
    TLS-021  ECDSA key < 256 bits
    TLS-022  SHA-1 certificate signature
    TLS-023  MD5 certificate signature

  Group D — Certificate (CRITICAL / HIGH / MEDIUM)
    TLS-030  Certificate expired
    TLS-031  Certificate expires within 7 days
    TLS-032  Certificate expires within 30 days
    TLS-040  Self-signed certificate
    TLS-041  Hostname not in cert subject / SAN
    TLS-042  No SAN — relies on deprecated Common Name matching

Banca-safety:
  - PURE static. No TLS connections initiated by the analyzer; the
    operator's probe is the only thing touching the wire.
  - Same finding shape as F97 / F98 / F87 stack — F89.1 SARIF
    reporter publishes them unchanged.
  - Date checks use UTC consistently to avoid timezone-confusion
    false-flags around midnight.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


__all__ = [
    "TLSCertificate",
    "TLSProfile",
    "TLSFinding",
    "TLSAnalysis",
    "analyze_tls_profile",
    "ALL_TLS_RULES",
    "WEAK_CIPHER_PATTERNS",
    "MIN_RSA_KEY_BITS",
    "MIN_ECDSA_KEY_BITS",
]


# Stable rule IDs.
ALL_TLS_RULES: frozenset[str] = frozenset(
    {
        "TLS-001", "TLS-002", "TLS-003", "TLS-004",
        "TLS-010", "TLS-011", "TLS-012", "TLS-013", "TLS-014",
        "TLS-020", "TLS-021", "TLS-022", "TLS-023",
        "TLS-030", "TLS-031", "TLS-032",
        "TLS-040", "TLS-041", "TLS-042",
    }
)


# Cipher fingerprints — substring matched against UPPER-CASED
# cipher names. Patterns must be uppercase too (the matcher
# uppercases the cipher before comparison).
WEAK_CIPHER_PATTERNS: dict[str, tuple[str, ...]] = {
    "RC4": ("RC4_", "WITH_RC4", "-RC4-"),
    "DES_NON_3DES": ("DES-CBC", "WITH_DES_", "_DES_"),  # plain DES (not 3DES)
    "3DES": ("3DES_EDE", "DES-EDE3", "DES_CBC3"),
    "MD5": ("WITH_MD5", "_MD5"),
    "NULL": ("WITH_NULL", "NULL-", "NULL_SHA", "NULL_MD5"),
    "anon": ("DH_ANON", "DH-ANON", "ECDH_ANON", "AECDH"),  # uppercased for matching
    "EXPORT": ("EXPORT", "EXP-", "EXP1024", "EXP40", "EXP56"),
}

# Minimum acceptable key sizes per modern recommendations
# (NIST SP 800-131A Rev. 2, RFC 9325).
MIN_RSA_KEY_BITS = 2048
MIN_ECDSA_KEY_BITS = 256


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TLSCertificate:
    """One X.509 certificate from the chain. Typically the leaf;
    callers can pass intermediates as separate certificates if they
    want chain-level checks (out of scope for F100 v1)."""

    subject_common_name: str = ""
    issuer_common_name: str = ""
    not_before: str = ""  # ISO 8601 UTC, e.g. "2026-01-15T00:00:00Z"
    not_after: str = ""   # ISO 8601 UTC
    key_algorithm: str = ""  # "RSA" | "EC" | "Ed25519" | "DSA"
    key_size_bits: int = 0  # 2048 / 3072 / 4096 for RSA; 256/384 for EC
    signature_algorithm: str = ""  # "sha256WithRSAEncryption", "ecdsa-with-SHA256", ...
    san_dns_names: tuple[str, ...] = field(default_factory=tuple)
    is_self_signed: bool = False  # subject == issuer or known indicator
    serial_number: str = ""


@dataclass(frozen=True)
class TLSProfile:
    """A complete TLS profile snapshot of one endpoint."""

    hostname: str = ""
    port: int = 443
    # Protocols advertised by the server. Use uppercase consistent
    # naming: "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2",
    # "TLSv1.3". Negotiated value (if known) goes in
    # `negotiated_protocol`; the set of all enabled goes in
    # `supported_protocols`.
    negotiated_protocol: str = ""
    supported_protocols: tuple[str, ...] = field(default_factory=tuple)
    # The cipher the handshake settled on (e.g.
    # "TLS_AES_256_GCM_SHA384" or "ECDHE-RSA-AES256-GCM-SHA384").
    negotiated_cipher: str = ""
    # All cipher suites the server is willing to accept. Useful for
    # weak-cipher detection beyond the one that happened to win the
    # handshake. Empty means "caller didn't probe — only audit the
    # negotiated one".
    supported_ciphers: tuple[str, ...] = field(default_factory=tuple)
    # The leaf certificate. F100 v1 audits only the leaf; chain
    # validation lives in v2.
    certificate: TLSCertificate | None = None


@dataclass(frozen=True)
class TLSFinding:
    """One detected weakness. Same shape as F97/F98/F87 stack."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    remediation: str


@dataclass(frozen=True)
class TLSAnalysis:
    """Aggregated analysis."""

    hostname: str
    findings: tuple[TLSFinding, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_iso_datetime(raw: str) -> datetime | None:
    """Parse an ISO-8601 datetime string into a UTC datetime.
    Tolerates trailing Z, sub-second fractions, and timezone-less
    values (treats them as UTC)."""
    if not raw:
        return None
    cleaned = raw.strip().rstrip("Z").rstrip("z")
    cleaned = re.sub(r"\.\d+$", "", cleaned)
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _hostname_matches_dns_name(hostname: str, dns_name: str) -> bool:
    """RFC 6125 wildcard cert matching. `*.example.com` matches
    `foo.example.com` but NOT `foo.bar.example.com` (one-label only).
    Case-insensitive on both sides."""
    h = hostname.strip().lower().rstrip(".")
    d = dns_name.strip().lower().rstrip(".")
    if h == d:
        return True
    if not d.startswith("*."):
        return False
    suffix = d[2:]  # drop "*."
    if "." not in h:
        return False
    label, _, rest = h.partition(".")
    return rest == suffix and bool(label)


# ---------------------------------------------------------------------------
# Group A — Protocols
# ---------------------------------------------------------------------------


def _check_protocols(profile: TLSProfile) -> list[TLSFinding]:
    findings: list[TLSFinding] = []
    supported = {p.strip() for p in profile.supported_protocols}
    # Combine with negotiated for "what we know is enabled".
    if profile.negotiated_protocol:
        supported.add(profile.negotiated_protocol.strip())

    def _has(*needles: str) -> bool:
        normalized = {s.upper().replace(" ", "") for s in supported}
        return any(n.upper().replace(" ", "") in normalized for n in needles)

    if _has("SSLv2", "SSL2", "SSLv2.0"):
        findings.append(_proto_finding("TLS-003", "SSLv2", "CRITICAL"))
    if _has("SSLv3", "SSL3", "SSLv3.0"):
        findings.append(_proto_finding("TLS-003", "SSLv3", "CRITICAL"))
    if _has("TLSv1.0", "TLS1.0", "TLSv1"):
        findings.append(
            TLSFinding(
                rule_id="TLS-001",
                severity="HIGH",
                title="TLS 1.0 enabled on the endpoint",
                detail=(
                    "TLS 1.0 (RFC 2246, 1999) is deprecated. PCI-DSS 3.2.1 "
                    "deadline for disabling it passed June 2018. CBC-mode "
                    "ciphers are vulnerable to BEAST + Lucky 13 + POODLE-on-TLS."
                ),
                remediation=(
                    "Disable TLS 1.0 at the server / load balancer. Modern "
                    "browsers (Chrome 84+, Firefox 78+, Safari 13.1+) dropped "
                    "support; the only reason to keep TLS 1.0 enabled is "
                    "legacy non-browser clients — document them, set "
                    "deprecation deadline."
                ),
            )
        )
    if _has("TLSv1.1", "TLS1.1"):
        findings.append(
            TLSFinding(
                rule_id="TLS-002",
                severity="MEDIUM",
                title="TLS 1.1 enabled on the endpoint",
                detail=(
                    "TLS 1.1 (RFC 4346, 2006) was deprecated by RFC 8996 (2021). "
                    "No known practical breaks but no modern feature support "
                    "either; offers no benefit over TLS 1.2."
                ),
                remediation="Disable TLS 1.1; keep TLS 1.2 + 1.3 only.",
            )
        )

    # TLS-004: no TLS 1.3 support. Modern baseline; missing means
    # the server hasn't been touched since pre-2018. INFO not HIGH
    # because TLS 1.2 done right is still acceptable for banking.
    if supported and not _has("TLSv1.3", "TLS1.3"):
        findings.append(
            TLSFinding(
                rule_id="TLS-004",
                severity="INFO",
                title="No TLS 1.3 support announced",
                detail=(
                    "Server doesn't advertise TLS 1.3 (RFC 8446). Properly-"
                    "configured TLS 1.2 is still acceptable, but TLS 1.3 "
                    "drops 100+ deprecated cipher suites + adds 1-RTT/0-RTT "
                    "handshake — measurable perf + security gains."
                ),
                remediation=(
                    "Enable TLS 1.3 on the load balancer / server. Almost "
                    "every modern server software supports it (nginx ≥1.13, "
                    "Apache ≥2.4.37, IIS ≥10 on Windows Server 2022)."
                ),
            )
        )

    return findings


def _proto_finding(rule_id: str, proto: str, severity: str) -> TLSFinding:
    return TLSFinding(
        rule_id=rule_id,
        severity=severity,
        title=f"{proto} enabled on the endpoint",
        detail=(
            f"{proto} is broken — vulnerable to POODLE / DROWN / DNS-LOAD "
            "and other practical attacks. Any client negotiating this "
            "protocol is connecting INSECURELY."
        ),
        remediation=f"Disable {proto} immediately at the server / load balancer.",
    )


# ---------------------------------------------------------------------------
# Group B — Ciphers
# ---------------------------------------------------------------------------


def _check_ciphers(profile: TLSProfile) -> list[TLSFinding]:
    findings: list[TLSFinding] = []
    # Audit BOTH the negotiated cipher AND the full supported list
    # (when caller probed it). The negotiated one is what THIS client
    # got; supported_ciphers contains everything any client could
    # negotiate.
    cipher_pool: list[str] = []
    if profile.negotiated_cipher:
        cipher_pool.append(profile.negotiated_cipher)
    cipher_pool.extend(profile.supported_ciphers)
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique_ciphers = []
    for c in cipher_pool:
        key = c.upper()
        if key in seen:
            continue
        seen.add(key)
        unique_ciphers.append(c)

    # Detection: each weakness category fires at most once.
    fired: set[str] = set()
    for cipher in unique_ciphers:
        upper = cipher.upper()
        # NULL → TLS-011 CRITICAL (no encryption)
        if "NULL" not in fired and any(p in upper for p in WEAK_CIPHER_PATTERNS["NULL"]):
            findings.append(
                TLSFinding(
                    rule_id="TLS-011",
                    severity="CRITICAL",
                    title=f"NULL / no-encryption cipher offered: {cipher}",
                    detail=(
                        "Server advertises a NULL cipher suite. Connections "
                        "negotiating it transmit data in plaintext over the wire."
                    ),
                    remediation="Remove all NULL_* ciphers from the cipher list.",
                )
            )
            fired.add("NULL")
        # Anonymous → TLS-011 / TLS-012
        if "anon" not in fired and any(p in upper for p in WEAK_CIPHER_PATTERNS["anon"]):
            findings.append(
                TLSFinding(
                    rule_id="TLS-011",
                    severity="CRITICAL",
                    title=f"Anonymous (no-authentication) cipher offered: {cipher}",
                    detail=(
                        "Anonymous Diffie-Hellman ciphers (DH_anon, AECDH) "
                        "skip server authentication entirely — trivial MITM."
                    ),
                    remediation="Remove all anon ciphers; require authentication.",
                )
            )
            fired.add("anon")
        # Export grade → TLS-012
        if "EXPORT" not in fired and any(p in upper for p in WEAK_CIPHER_PATTERNS["EXPORT"]):
            findings.append(
                TLSFinding(
                    rule_id="TLS-012",
                    severity="CRITICAL",
                    title=f"Export-grade (40/56-bit) cipher offered: {cipher}",
                    detail=(
                        "Export ciphers (40-56 bit symmetric key) were a 1990s "
                        "regulatory artifact. FREAK + Logjam attacks exploit "
                        "them in 2025+."
                    ),
                    remediation="Remove all EXPORT_* ciphers.",
                )
            )
            fired.add("EXPORT")
        # RC4 → TLS-010 HIGH
        if "RC4" not in fired and any(p in upper for p in WEAK_CIPHER_PATTERNS["RC4"]):
            findings.append(
                _weak_cipher_finding("TLS-010", "HIGH", "RC4", cipher,
                                     "RC4 has known biases (Bar-Mizrachi 2013, RC4 NoMore 2015) — practical recovery of HTTPS cookies."))
            fired.add("RC4")
        # Plain DES → TLS-010 HIGH
        if "DES_NON_3DES" not in fired and any(
            p in upper for p in WEAK_CIPHER_PATTERNS["DES_NON_3DES"]
        ):
            # Skip if it's actually 3DES (DES-CBC3 / 3DES_EDE patterns)
            is_3des = any(p in upper for p in WEAK_CIPHER_PATTERNS["3DES"])
            if not is_3des:
                findings.append(
                    _weak_cipher_finding("TLS-010", "HIGH", "DES (56-bit)", cipher,
                                         "Single-DES is 56-bit symmetric — brute-forceable in <1 day on modern hardware."))
                fired.add("DES_NON_3DES")
        # 3DES → TLS-010 HIGH (Sweet32)
        if "3DES" not in fired and any(p in upper for p in WEAK_CIPHER_PATTERNS["3DES"]):
            findings.append(
                _weak_cipher_finding("TLS-010", "HIGH", "3DES", cipher,
                                     "3DES has a 64-bit block — Sweet32 birthday attack recovers plaintext on long-lived sessions."))
            fired.add("3DES")
        # MD5 MAC → TLS-014 MEDIUM
        if "MD5" not in fired and any(p in upper for p in WEAK_CIPHER_PATTERNS["MD5"]):
            findings.append(
                TLSFinding(
                    rule_id="TLS-014",
                    severity="MEDIUM",
                    title=f"MD5-based MAC in cipher suite: {cipher}",
                    detail=(
                        "MD5 is broken for collision resistance; HMAC-MD5 "
                        "remains acceptable today but signals an outdated "
                        "config — modern suites use SHA-256+."
                    ),
                    remediation="Migrate to SHA-256/384 HMAC suites.",
                )
            )
            fired.add("MD5")

    # TLS-013: no forward secrecy in the NEGOTIATED cipher. We only
    # check negotiated (not supported) because that's the cipher this
    # client actually got.
    if profile.negotiated_cipher:
        upper_neg = profile.negotiated_cipher.upper()
        # ECDHE / DHE keywords = forward secrecy. TLS 1.3 always has
        # forward secrecy by construction so we exempt TLS_AES_* etc.
        has_fs = (
            "ECDHE" in upper_neg
            or "DHE" in upper_neg
            or upper_neg.startswith("TLS_AES")  # TLS 1.3 builtins
            or upper_neg.startswith("TLS_CHACHA20")
        )
        if not has_fs:
            findings.append(
                TLSFinding(
                    rule_id="TLS-013",
                    severity="MEDIUM",
                    title=f"Negotiated cipher has no forward secrecy: {profile.negotiated_cipher}",
                    detail=(
                        "Cipher uses static RSA key exchange (no ECDHE/DHE). "
                        "If the server's private key is ever stolen, ALL "
                        "previously-recorded traffic can be decrypted."
                    ),
                    remediation=(
                        "Prefer ECDHE-based suites first in the cipher list. "
                        "Modern config: ECDHE-ECDSA-AES256-GCM-SHA384 / "
                        "ECDHE-RSA-AES256-GCM-SHA384."
                    ),
                )
            )
    return findings


def _weak_cipher_finding(rule_id: str, severity: str, cipher_name: str, full_cipher: str, detail: str) -> TLSFinding:
    return TLSFinding(
        rule_id=rule_id,
        severity=severity,
        title=f"Weak cipher offered ({cipher_name}): {full_cipher}",
        detail=detail,
        remediation=(
            f"Remove all {cipher_name} suites from the cipher list. "
            "Use Mozilla SSL Configuration Generator (Modern profile) as "
            "the baseline."
        ),
    )


# ---------------------------------------------------------------------------
# Group C — Key + Signature
# ---------------------------------------------------------------------------


def _check_key_and_signature(profile: TLSProfile) -> list[TLSFinding]:
    cert = profile.certificate
    if cert is None:
        return []
    findings: list[TLSFinding] = []

    algo = (cert.key_algorithm or "").upper()
    if algo == "RSA" and cert.key_size_bits and cert.key_size_bits < MIN_RSA_KEY_BITS:
        findings.append(
            TLSFinding(
                rule_id="TLS-020",
                severity="HIGH",
                title=f"RSA key too small: {cert.key_size_bits} bits",
                detail=(
                    f"RSA key is {cert.key_size_bits} bits. NIST SP 800-131A "
                    f"Rev. 2 minimum is {MIN_RSA_KEY_BITS}. Anything below "
                    "2048 is feasible to factor with a determined adversary."
                ),
                remediation="Rotate to a 2048-bit (or 3072-bit) RSA key.",
            )
        )
    if (
        algo in ("EC", "ECDSA", "ECDHE")
        and cert.key_size_bits
        and cert.key_size_bits < MIN_ECDSA_KEY_BITS
    ):
        findings.append(
            TLSFinding(
                rule_id="TLS-021",
                severity="HIGH",
                title=f"ECDSA key too small: {cert.key_size_bits} bits",
                detail=(
                    f"ECDSA key is {cert.key_size_bits} bits. NIST P-256 "
                    "(256-bit) is the practical minimum; smaller curves are "
                    "theoretical attacks territory."
                ),
                remediation="Rotate to P-256 / P-384.",
            )
        )

    sig_algo = (cert.signature_algorithm or "").upper()
    if "MD5" in sig_algo:
        findings.append(
            TLSFinding(
                rule_id="TLS-023",
                severity="CRITICAL",
                title="Certificate signed with MD5",
                detail=(
                    "MD5 collisions are practical (CMU 2008 → MD5-collision-"
                    "based rogue CA). Any cert signed with MD5 should be "
                    "treated as forgeable."
                ),
                remediation="Reissue with SHA-256+ signature.",
            )
        )
    elif "SHA1" in sig_algo or "SHA-1" in sig_algo:
        findings.append(
            TLSFinding(
                rule_id="TLS-022",
                severity="HIGH",
                title="Certificate signed with SHA-1",
                detail=(
                    "SHA-1 collisions demonstrated (Google + CWI 2017 SHAttered). "
                    "All major CAs ceased issuing SHA-1 certs by 2016; legacy "
                    "ones must be rotated."
                ),
                remediation="Reissue with SHA-256+ signature.",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Group D — Certificate validity
# ---------------------------------------------------------------------------


def _check_certificate(profile: TLSProfile) -> list[TLSFinding]:
    cert = profile.certificate
    if cert is None:
        return []
    findings: list[TLSFinding] = []
    now = datetime.now(timezone.utc)

    not_after = _parse_iso_datetime(cert.not_after)
    if not_after is not None:
        days = (not_after - now).total_seconds() / 86400
        if days < 0:
            findings.append(
                TLSFinding(
                    rule_id="TLS-030",
                    severity="CRITICAL",
                    title=f"Certificate EXPIRED {-int(days)} days ago",
                    detail=(
                        f"not_after={cert.not_after}. Modern browsers fail "
                        "the handshake; clients refuse to connect. Banking "
                        "site is effectively offline."
                    ),
                    remediation="Renew the certificate immediately. Automate via Let's Encrypt / ACM.",
                )
            )
        elif days < 7:
            findings.append(
                TLSFinding(
                    rule_id="TLS-031",
                    severity="CRITICAL",
                    title=f"Certificate expires in {int(days)} days",
                    detail=(
                        f"not_after={cert.not_after}. Less than a week of "
                        "validity remaining — renewal SLA must trigger now."
                    ),
                    remediation="Renew immediately. Verify automated renewal isn't blocked.",
                )
            )
        elif days < 30:
            findings.append(
                TLSFinding(
                    rule_id="TLS-032",
                    severity="HIGH",
                    title=f"Certificate expires in {int(days)} days",
                    detail=(
                        f"not_after={cert.not_after}. Renewal window starts "
                        "this month."
                    ),
                    remediation="Renew within the next two weeks; monitor automation.",
                )
            )

    if cert.is_self_signed:
        findings.append(
            TLSFinding(
                rule_id="TLS-040",
                severity="HIGH",
                title="Self-signed certificate",
                detail=(
                    "Certificate is self-signed (subject == issuer or marked "
                    "by the probe). No trusted CA in the chain. Browsers / "
                    "clients show certificate warnings, and any MITM with a "
                    "self-signed cert is indistinguishable."
                ),
                remediation=(
                    "Replace with a publicly-trusted cert (Let's Encrypt, "
                    "ACM, GlobalSign, ...). Self-signed acceptable ONLY for "
                    "internal management interfaces with cert pinning."
                ),
            )
        )

    # TLS-041 / TLS-042: hostname / SAN
    if profile.hostname and cert.san_dns_names:
        matched = any(
            _hostname_matches_dns_name(profile.hostname, san)
            for san in cert.san_dns_names
        )
        if not matched:
            findings.append(
                TLSFinding(
                    rule_id="TLS-041",
                    severity="HIGH",
                    title=f"Hostname {profile.hostname!r} not in cert SAN",
                    detail=(
                        f"Cert SAN list: {list(cert.san_dns_names)}. The "
                        f"hostname {profile.hostname!r} doesn't match any "
                        "SAN entry. Browsers fail the connection."
                    ),
                    remediation=(
                        "Reissue the cert with the correct SAN list, or "
                        "deploy this cert on the correct hostname."
                    ),
                )
            )
    elif profile.hostname and cert.subject_common_name and not cert.san_dns_names:
        findings.append(
            TLSFinding(
                rule_id="TLS-042",
                severity="MEDIUM",
                title="Certificate has no SAN — relies on deprecated CN matching",
                detail=(
                    f"Cert subject CN={cert.subject_common_name!r} but no "
                    "SAN entries. Modern browsers (Chrome 58+, Firefox 48+) "
                    "ignore CN for hostname verification — only SAN counts. "
                    "Connection may fail despite the right CN."
                ),
                remediation=(
                    "Reissue with subjectAltName extension listing the "
                    "hostname(s) explicitly."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def analyze_tls_profile(profile: TLSProfile) -> TLSAnalysis:
    """Run every check against the TLS profile.

    Returns a TLSAnalysis with findings sorted by severity
    (CRITICAL → INFO)."""
    findings: list[TLSFinding] = []
    findings.extend(_check_protocols(profile))
    findings.extend(_check_ciphers(profile))
    findings.extend(_check_key_and_signature(profile))
    findings.extend(_check_certificate(profile))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id))

    return TLSAnalysis(
        hostname=profile.hostname,
        findings=tuple(findings),
    )
