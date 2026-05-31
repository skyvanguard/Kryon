"""F95 — Webhook signature validator (Open Banking + ad-hoc schemes).

Webhooks are the primary push channel for Open Banking events
(Bancard, BCP, Banco Itaú in LATAM; Stripe / GitHub in the SaaS
world; Open Banking UK / BR for FAPI integrations). Their failure
modes are well-documented:
  - Missing signature header (anyone can POST events).
  - Weak HMAC algorithm (MD5/SHA1).
  - No replay protection (no timestamp / nonce, or unbounded skew).
  - Body canonicalization mismatch (verifier signs the wrong bytes).
  - Timing-leaky signature comparison.

This module performs:
  1. PURE static analysis on the request shape — identify the
     signature scheme by header pattern, flag missing replay
     protection, flag weak algorithms, surface the scheme name so
     the auditor knows what to verify against.
  2. OPTIONAL signature verification when the operator passes the
     shared secret / public key. Uses `hmac.compare_digest` for
     timing-safe comparison (HMAC schemes). Ed25519 verification
     requires the `cryptography` library; we degrade gracefully
     when it's unavailable.

Banca-safety:
  - Static analysis is the default. Verification is opt-in via
    the `secret` / `public_key` arguments.
  - Secret values are NEVER persisted in the analysis output.
    `WebhookAnalysis` carries finding metadata + scheme name +
    detected timestamp; it never echoes the raw secret.
  - No I/O. The caller supplies the request fields.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


__all__ = [
    "WebhookRequest",
    "WebhookFinding",
    "WebhookAnalysis",
    "detect_signature_scheme",
    "analyze_webhook",
    "ALL_SCHEMES",
]


# Recognized schemes. Stable identifiers so reports / dashboards
# group consistently.
ALL_SCHEMES: tuple[str, ...] = (
    "stripe",  # Stripe-Signature: t=...,v1=...
    "github_sha256",  # X-Hub-Signature-256: sha256=...
    "github_sha1",  # X-Hub-Signature: sha1=...  (legacy, weak)
    "discord_ed25519",  # X-Signature-Ed25519 + X-Signature-Timestamp
    "rfc9421",  # Signature: keyId=...,algorithm=...,signature=...
    "bancard",  # X-Bancard-Signature (LATAM banking)
    "bcp",  # X-BCP-Signature (LATAM banking)
    "open_banking_jws",  # x-jws-signature (Open Banking UK/BR)
    "custom_x_signature",  # generic X-Signature / X-Webhook-Signature
    "unknown",
)


# Algorithms considered cryptographically weak today. Detection of
# any of these in a signature header / scheme metadata fires a
# CRITICAL or HIGH finding.
_WEAK_ALGORITHMS = frozenset({"md5", "sha1", "hmac-md5", "hmac-sha1", "rsa-sha1"})

# Stripe-Signature value format: t=<unix_ts>,v1=<hex_sig>[,v0=<hex_sig>]
_STRIPE_SIGNATURE_RE = re.compile(r"t=(?P<ts>\d+),v1=(?P<sig>[A-Fa-f0-9]+)")

# GitHub HMAC signature value format: "sha256=<hex>" or "sha1=<hex>"
_GITHUB_SIGNATURE_RE = re.compile(
    r"^(?P<alg>sha\d+)=(?P<sig>[A-Fa-f0-9]+)\s*$",
    re.IGNORECASE,
)

# RFC 9421 Signature header (highly simplified parse — full RFC is
# complex but the common shape is parseable).
_RFC9421_KEYVAL_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


# Default replay window: 5 minutes. Operators tune per-integration.
DEFAULT_MAX_SKEW_SECONDS = 300


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WebhookRequest:
    """An inbound webhook request. The caller fills this from their
    HTTP framework (Flask request, FastAPI request, Lambda event,
    etc.) before passing to the analyzer."""

    method: str  # "POST" most commonly
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    # Optional pre-canonicalized body. Some schemes (Open Banking JWS)
    # sign a canonical JSON form; supply that here when distinct from
    # `body`. Empty means "use body as-is".
    canonical_body: bytes = b""


@dataclass(frozen=True)
class WebhookFinding:
    """One detected weakness. Mirror shape of JWTFinding / DKR
    findings."""

    finding_id: str  # WHK-NNN stable
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    remediation: str


@dataclass(frozen=True)
class WebhookAnalysis:
    """Aggregate analysis."""

    scheme_detected: str  # one of ALL_SCHEMES
    signature_present: bool
    timestamp_present: bool
    timestamp_value: int | None  # parsed unix timestamp when available
    nonce_present: bool
    findings: tuple[WebhookFinding, ...] = field(default_factory=tuple)
    verified: bool | None = None  # None when caller didn't ask, True/False otherwise


# ---------------------------------------------------------------------------
# Header lookup helpers
# ---------------------------------------------------------------------------


def _get_header(headers: dict[str, str], *names: str) -> str | None:
    """Case-insensitive header lookup. Returns the first non-empty
    match across the candidate names."""
    if not headers:
        return None
    lower_map = {k.lower(): v for k, v in headers.items()}
    for n in names:
        val = lower_map.get(n.lower())
        if val:
            return val
    return None


def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Lower-case header names to make subsequent lookups predictable."""
    return {k.lower(): v for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Scheme detection
# ---------------------------------------------------------------------------


def detect_signature_scheme(request: WebhookRequest) -> str:
    """Inspect the request headers and return the best-fit scheme
    identifier. Detection is by header presence + value shape — we
    don't attempt cryptographic verification here.

    Priority order resolves ambiguity: a vendor-specific header wins
    over the generic X-Signature fallback.
    """
    headers = _normalize_headers(request.headers)

    if "stripe-signature" in headers:
        # Stripe value format has the embedded t=...,v1=... shape.
        return "stripe"

    if "x-hub-signature-256" in headers:
        return "github_sha256"
    if "x-hub-signature" in headers:
        # Without -256: GitHub's legacy sha1 scheme. WEAK.
        return "github_sha1"

    if "x-signature-ed25519" in headers and "x-signature-timestamp" in headers:
        return "discord_ed25519"

    if "x-jws-signature" in headers:
        return "open_banking_jws"

    if "x-bancard-signature" in headers:
        return "bancard"
    if "x-bcp-signature" in headers:
        return "bcp"

    # RFC 9421 uses `Signature:` header. Avoid catching scheme-less
    # `Authorization: Signature ...` lines; we require the dedicated
    # header.
    if "signature" in headers and "=" in headers["signature"]:
        return "rfc9421"

    if "x-signature" in headers or "x-webhook-signature" in headers:
        return "custom_x_signature"

    return "unknown"


# ---------------------------------------------------------------------------
# Per-scheme parsing
# ---------------------------------------------------------------------------


def _parse_stripe(headers: dict[str, str]) -> tuple[int | None, str | None]:
    """Parse Stripe-Signature into (timestamp, hex_signature)."""
    raw = headers.get("stripe-signature", "")
    m = _STRIPE_SIGNATURE_RE.search(raw)
    if not m:
        return None, None
    try:
        ts = int(m.group("ts"))
    except (TypeError, ValueError):
        ts = None
    return ts, m.group("sig")


def _parse_github(headers: dict[str, str], *, sha256: bool) -> tuple[str | None, str | None]:
    """Parse GitHub HMAC signature. Returns (alg_name, hex_signature).
    When sha256=False, the value lives under the sha1 header."""
    key = "x-hub-signature-256" if sha256 else "x-hub-signature"
    raw = headers.get(key, "")
    m = _GITHUB_SIGNATURE_RE.match(raw)
    if not m:
        return None, None
    return m.group("alg").lower(), m.group("sig")


def _parse_rfc9421(headers: dict[str, str]) -> dict[str, str]:
    """Parse RFC 9421 `Signature:` key=value pairs."""
    raw = headers.get("signature", "")
    return {k.lower(): v for k, v in _RFC9421_KEYVAL_RE.findall(raw)}


# ---------------------------------------------------------------------------
# Timestamp parsing (Discord uses RFC 3339 / Stripe uses unix epoch)
# ---------------------------------------------------------------------------


def _parse_discord_timestamp(value: str) -> int | None:
    """Discord sends RFC 3339 (e.g. '2026-05-13T12:34:56Z'). Some
    libraries also send a Unix-epoch fallback. Try both."""
    if not value:
        return None
    # Try Unix epoch first (integer string).
    try:
        return int(value)
    except (ValueError, TypeError):
        pass
    # RFC 3339.
    from datetime import datetime

    cleaned = value.rstrip("Z").rstrip("z")
    cleaned = re.sub(r"\.\d+$", "", cleaned)
    try:
        dt = datetime.fromisoformat(cleaned)
        return int(dt.timestamp())
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------


def _check_signature_present(request: WebhookRequest, scheme: str) -> list[WebhookFinding]:
    if scheme != "unknown":
        return []
    return [
        WebhookFinding(
            finding_id="WHK-001",
            severity="CRITICAL",
            title="No recognized signature header",
            detail=(
                "Request carries no signature header that matches any "
                "documented scheme. Without authentication, anyone who "
                "can POST to this endpoint can inject fake events."
            ),
            remediation=(
                "Reject requests without a valid signature. Document the "
                "expected scheme (Stripe-style HMAC, RFC 9421, Open "
                "Banking JWS, etc.) for the partner."
            ),
        )
    ]


def _check_weak_algorithm(request: WebhookRequest, scheme: str) -> list[WebhookFinding]:
    findings: list[WebhookFinding] = []
    headers = _normalize_headers(request.headers)

    if scheme == "github_sha1":
        findings.append(
            WebhookFinding(
                finding_id="WHK-002",
                severity="HIGH",
                title="GitHub-style HMAC-SHA1 signature (deprecated)",
                detail=(
                    "X-Hub-Signature uses HMAC-SHA1. GitHub deprecated this "
                    "in favor of X-Hub-Signature-256. SHA1 collisions are "
                    "feasible; HMAC-SHA1 is still considered safe today but "
                    "moving target."
                ),
                remediation="Migrate to X-Hub-Signature-256 (HMAC-SHA256).",
            )
        )

    if scheme == "rfc9421":
        params = _parse_rfc9421(headers)
        alg = params.get("algorithm", "").lower()
        if alg in _WEAK_ALGORITHMS:
            findings.append(
                WebhookFinding(
                    finding_id="WHK-002",
                    severity="HIGH",
                    title=f"Weak signature algorithm: {alg}",
                    detail=(
                        f"RFC 9421 Signature header advertises algorithm={alg!r}. "
                        "Weak primitives erode the integrity guarantee."
                    ),
                    remediation="Configure the sender to use hmac-sha256 / ed25519 / rsa-pss.",
                )
            )

    return findings


def _check_replay_protection(
    request: WebhookRequest,
    scheme: str,
    *,
    max_skew_seconds: int,
) -> tuple[list[WebhookFinding], int | None]:
    """Return (findings, parsed_timestamp_if_any)."""
    findings: list[WebhookFinding] = []
    headers = _normalize_headers(request.headers)
    timestamp: int | None = None

    if scheme == "stripe":
        ts, _ = _parse_stripe(headers)
        timestamp = ts
        if ts is None:
            findings.append(
                WebhookFinding(
                    finding_id="WHK-003",
                    severity="HIGH",
                    title="Stripe signature missing timestamp",
                    detail=(
                        "Stripe-Signature value lacks `t=<unix>` segment. Without "
                        "a signed timestamp the verifier can't detect replay."
                    ),
                    remediation="Reject Stripe-Signature headers missing the `t=` component.",
                )
            )
    elif scheme == "discord_ed25519":
        ts_raw = headers.get("x-signature-timestamp", "")
        if not ts_raw:
            findings.append(
                WebhookFinding(
                    finding_id="WHK-003",
                    severity="HIGH",
                    title="Discord-style scheme missing X-Signature-Timestamp",
                    detail=(
                        "Ed25519 verification requires the timestamp header; "
                        "absence breaks both signature verify AND replay window."
                    ),
                    remediation="Reject requests without X-Signature-Timestamp.",
                )
            )
        else:
            timestamp = _parse_discord_timestamp(ts_raw)
    elif scheme in ("github_sha256", "github_sha1"):
        # GitHub doesn't sign a timestamp by default; replay is on
        # the operator. Surface as HIGH so they know.
        findings.append(
            WebhookFinding(
                finding_id="WHK-003",
                severity="HIGH",
                title="GitHub-style scheme has no signed timestamp",
                detail=(
                    "X-Hub-Signature-256 covers the body only. Without an "
                    "out-of-band timestamp the receiver can't detect replay."
                ),
                remediation=(
                    "Either require a signed `X-GitHub-Delivery` ID in a sliding "
                    "dedupe window, OR move to a scheme that signs a timestamp."
                ),
            )
        )
    elif scheme == "rfc9421":
        params = _parse_rfc9421(headers)
        if "created" not in params:
            findings.append(
                WebhookFinding(
                    finding_id="WHK-003",
                    severity="HIGH",
                    title="RFC 9421 signature missing `created` parameter",
                    detail=(
                        "Per RFC 9421 §2.3, `created` SHOULD be present so the verifier can enforce a freshness window."
                    ),
                    remediation="Require senders to include `created=` in the Signature header.",
                )
            )
        else:
            try:
                timestamp = int(params["created"])
            except (ValueError, TypeError):
                timestamp = None

    # Window enforcement when we have a timestamp.
    if timestamp is not None:
        now = int(time.time())
        skew = abs(now - timestamp)
        if skew > max_skew_seconds:
            findings.append(
                WebhookFinding(
                    finding_id="WHK-004",
                    severity="HIGH",
                    title=f"Timestamp outside acceptable window ({skew}s skew)",
                    detail=(
                        f"Signed timestamp differs from receiver clock by {skew}s "
                        f"(window: {max_skew_seconds}s). Either a replay attempt "
                        "or major clock drift."
                    ),
                    remediation=(
                        f"Reject when skew > {max_skew_seconds}s; widen window only if both sides are NTP-attested."
                    ),
                )
            )

    return findings, timestamp


def _check_unknown_scheme(scheme: str) -> list[WebhookFinding]:
    """An unrecognized custom scheme isn't necessarily insecure, but
    the auditor should know. INFO so the auditor adds manual coverage."""
    if scheme not in ("custom_x_signature", "unknown"):
        return []
    if scheme == "unknown":
        return []  # already covered by WHK-001
    return [
        WebhookFinding(
            finding_id="WHK-010",
            severity="INFO",
            title="Custom signature scheme (manual review needed)",
            detail=(
                "Generic X-Signature / X-Webhook-Signature header present. "
                "Kryon has no built-in profile for this scheme — the auditor "
                "must confirm the sender uses HMAC-SHA256+, signs a timestamp, "
                "and verifies with constant-time comparison."
            ),
            remediation="Document the scheme's profile and add a specific check for it.",
        )
    ]


def _check_body_integrity(request: WebhookRequest) -> list[WebhookFinding]:
    """Compare Content-Length to body length when both are available.
    Mismatch suggests the framework consumed / re-encoded the body
    before the verifier saw it — common bug that breaks signature
    verification silently."""
    headers = _normalize_headers(request.headers)
    cl = headers.get("content-length")
    if not cl or not request.body:
        return []
    try:
        declared = int(cl)
    except ValueError:
        return []
    actual = len(request.body)
    if declared == actual:
        return []
    return [
        WebhookFinding(
            finding_id="WHK-030",
            severity="MEDIUM",
            title=f"Content-Length ({declared}) mismatches body length ({actual})",
            detail=(
                "The HTTP body Kryon sees differs in length from the declared "
                "Content-Length. Either a framework re-encoded the body or "
                "transport-level mutation. Signature verification on a "
                "transformed body will fail silently."
            ),
            remediation=(
                "Read the raw request body BEFORE any JSON parsing; verify signature against those exact bytes."
            ),
        )
    ]


# ---------------------------------------------------------------------------
# Optional signature verification (gated by operator providing secret)
# ---------------------------------------------------------------------------


def _verify_stripe(request: WebhookRequest, secret: bytes, ts: int, signature_hex: str) -> bool:
    """Verify a Stripe-style signature: HMAC-SHA256 over `<ts>.<body>`."""
    body = request.canonical_body or request.body
    signed_payload = f"{ts}.".encode() + body
    digest = hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest.lower(), signature_hex.lower())


def _verify_github(
    request: WebhookRequest,
    secret: bytes,
    signature_hex: str,
    *,
    sha256: bool,
) -> bool:
    """Verify GitHub-style HMAC over the raw body."""
    algo = hashlib.sha256 if sha256 else hashlib.sha1
    body = request.canonical_body or request.body
    digest = hmac.new(secret, body, algo).hexdigest()
    return hmac.compare_digest(digest.lower(), signature_hex.lower())


def _attempt_verify(
    request: WebhookRequest,
    scheme: str,
    *,
    secret: bytes | None,
    public_key: bytes | None,
) -> tuple[bool | None, list[WebhookFinding]]:
    """Attempt cryptographic verification when caller provided the
    material. Returns (verified, findings)."""
    headers = _normalize_headers(request.headers)
    findings: list[WebhookFinding] = []

    if scheme == "stripe" and secret:
        ts, sig = _parse_stripe(headers)
        if ts is None or sig is None:
            return False, [
                WebhookFinding(
                    finding_id="WHK-020",
                    severity="CRITICAL",
                    title="Stripe signature parse failed during verification",
                    detail="Could not extract t=/v1= from Stripe-Signature.",
                    remediation="Check the header value shape.",
                )
            ]
        ok = _verify_stripe(request, secret, ts, sig)
        return ok, ([_failed_verify_finding()] if not ok else [_ok_finding()])

    if scheme == "github_sha256" and secret:
        _, sig = _parse_github(headers, sha256=True)
        if not sig:
            return False, [_failed_verify_finding()]
        ok = _verify_github(request, secret, sig, sha256=True)
        return ok, ([_failed_verify_finding()] if not ok else [_ok_finding()])

    if scheme == "github_sha1" and secret:
        _, sig = _parse_github(headers, sha256=False)
        if not sig:
            return False, [_failed_verify_finding()]
        ok = _verify_github(request, secret, sig, sha256=False)
        return ok, ([_failed_verify_finding()] if not ok else [_ok_finding()])

    if scheme == "discord_ed25519" and public_key:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError:
            return None, []  # degrade gracefully; static-only result
        sig_hex = headers.get("x-signature-ed25519", "")
        ts_raw = headers.get("x-signature-timestamp", "")
        body = request.canonical_body or request.body
        message = ts_raw.encode("utf-8") + body
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(sig_bytes, message)
            return True, [_ok_finding()]
        except (ValueError, InvalidSignature):
            return False, [_failed_verify_finding()]
        except Exception:  # noqa: BLE001
            return False, [_failed_verify_finding()]

    return None, findings


def _failed_verify_finding() -> WebhookFinding:
    return WebhookFinding(
        finding_id="WHK-020",
        severity="CRITICAL",
        title="Signature verification failed",
        detail=(
            "Computed signature does not match the value in the header. "
            "Either the request is forged, the secret rotated without "
            "coordination, or the body was modified in transit."
        ),
        remediation="Reject the request; investigate source IP + recent secret rotation.",
    )


def _ok_finding() -> WebhookFinding:
    return WebhookFinding(
        finding_id="WHK-021",
        severity="INFO",
        title="Signature verified against caller-provided secret",
        detail="HMAC / Ed25519 verification succeeded with the operator's secret.",
        remediation="Nothing to do — informational.",
    )


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def analyze_webhook(
    request: WebhookRequest,
    *,
    expected_scheme: str | None = None,
    secret: bytes | None = None,
    public_key: bytes | None = None,
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
) -> WebhookAnalysis:
    """Run static analysis (+ optional verify) on a webhook request.

    Args:
        request: WebhookRequest with method/url/headers/body.
        expected_scheme: when set, fires WHK-011 if detected scheme
            doesn't match. Optional.
        secret: when provided, attempt HMAC verification for the
            detected scheme (stripe / github). Bytes; the analyzer
            never logs / surfaces it.
        public_key: 32-byte Ed25519 public key for discord_ed25519
            scheme verification. Optional.
        max_skew_seconds: replay window in seconds. Default 300 (5 min).

    Returns:
        WebhookAnalysis with the scheme, findings, and (when caller
        provided material) the verification verdict.
    """
    scheme = detect_signature_scheme(request)
    findings: list[WebhookFinding] = []
    findings.extend(_check_signature_present(request, scheme))
    findings.extend(_check_weak_algorithm(request, scheme))
    replay_findings, timestamp = _check_replay_protection(request, scheme, max_skew_seconds=max_skew_seconds)
    findings.extend(replay_findings)
    findings.extend(_check_unknown_scheme(scheme))
    findings.extend(_check_body_integrity(request))

    if expected_scheme and scheme != expected_scheme:
        findings.append(
            WebhookFinding(
                finding_id="WHK-011",
                severity="HIGH",
                title=f"Detected scheme {scheme!r} does not match expected {expected_scheme!r}",
                detail=(
                    "The operator pinned the expected scheme. The incoming "
                    "request advertises a different scheme — either a "
                    "misconfiguration on the sender side, or a downgrade attempt."
                ),
                remediation=f"Reject; require scheme {expected_scheme!r}.",
            )
        )

    verified: bool | None = None
    verify_findings: list[WebhookFinding] = []
    if secret or public_key:
        verified, verify_findings = _attempt_verify(request, scheme, secret=secret, public_key=public_key)
        findings.extend(verify_findings)

    # Header presence flags surfaced for the report.
    headers = _normalize_headers(request.headers)
    signature_present = scheme != "unknown"
    nonce_header = _get_header(
        request.headers,
        "X-Nonce",
        "X-Webhook-Nonce",
        "X-Request-Id",
        "X-Idempotency-Key",
    )

    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW, INFO.
    from kryon.util.severity import SEVERITY_RANK as severity_order
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    return WebhookAnalysis(
        scheme_detected=scheme,
        signature_present=signature_present,
        timestamp_present=timestamp is not None,
        timestamp_value=timestamp,
        nonce_present=nonce_header is not None,
        findings=tuple(findings),
        verified=verified,
    )
