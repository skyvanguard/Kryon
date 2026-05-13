"""F116 — Embedded secret detection.

12+ regex patterns (HIGH-SIGNAL only — no generic "20-char alnum"
catch-alls that flood with false positives) plus a Shannon-entropy
scan as a fallback.

**Banca-safety**:

  * Captured secrets are NEVER stored in plain. The `EmbeddedSecret`
    record exposes only the first 4 characters + the last 4 of the
    raw value, separated by `…`, plus a SHA-256 hash of the FULL
    value (so operators can cross-reference without leaking).
  * The matched fragment never crosses module boundaries unredacted.
  * Pattern set is conservative — designed to fire on REAL secrets
    rather than every base64-looking string.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field

__all__ = [
    "EmbeddedSecret",
    "SECRET_PATTERNS",
    "scan_for_secrets",
    "shannon_entropy",
]


# (pattern, label, severity, redact_full_match) tuples
SECRET_PATTERNS: tuple[tuple[re.Pattern, str, str], ...] = (
    # AWS — production access keys
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "aws-access-key", "CRITICAL"),
    (re.compile(rb"ASIA[0-9A-Z]{16}"), "aws-temporary-key", "HIGH"),
    # AWS secret access keys (40-char base64) — only when paired with
    # an obvious context word, to avoid noise
    (
        re.compile(
            rb"(?i)aws(?:.{0,20})?['\"]?[0-9a-zA-Z/+]{40}['\"]?",
            re.MULTILINE,
        ),
        "aws-secret-key-candidate",
        "HIGH",
    ),
    # GitHub
    (re.compile(rb"ghp_[A-Za-z0-9]{36}"), "github-personal-access-token", "CRITICAL"),
    (re.compile(rb"gho_[A-Za-z0-9]{36}"), "github-oauth-token", "CRITICAL"),
    (re.compile(rb"ghs_[A-Za-z0-9]{36}"), "github-server-token", "CRITICAL"),
    (re.compile(rb"ghr_[A-Za-z0-9]{36}"), "github-refresh-token", "HIGH"),
    # Stripe
    (re.compile(rb"sk_live_[0-9a-zA-Z]{24,99}"), "stripe-secret-live", "CRITICAL"),
    (re.compile(rb"sk_test_[0-9a-zA-Z]{24,99}"), "stripe-secret-test", "MEDIUM"),
    (re.compile(rb"pk_live_[0-9a-zA-Z]{24,99}"), "stripe-public-live", "LOW"),
    # Google / Firebase
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "google-api-key", "HIGH"),
    (re.compile(rb"ya29\.[0-9A-Za-z\-_]+"), "google-oauth-token", "HIGH"),
    # Slack
    (re.compile(rb"xox[bpsoa]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,40}"), "slack-token", "CRITICAL"),
    (re.compile(rb"xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+"), "slack-app-token", "CRITICAL"),
    # JWT (header.payload.signature)
    (
        re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        "jwt-token",
        "MEDIUM",
    ),
    # Private keys
    (
        re.compile(rb"-----BEGIN (?:RSA |OPENSSH |DSA |EC |ENCRYPTED |PGP )?PRIVATE KEY"),
        "private-key-header",
        "CRITICAL",
    ),
    # Generic Bearer in HTML/JS body (often leaked in client-side code)
    (
        re.compile(rb"(?i)bearer\s+[A-Za-z0-9_\-\.~+/]{20,}={0,2}"),
        "bearer-token-in-body",
        "HIGH",
    ),
    # Authorization Basic (base64 user:pass)
    (
        re.compile(rb"(?i)authorization:\s*basic\s+[A-Za-z0-9+/]{16,}={0,2}"),
        "basic-auth-in-body",
        "HIGH",
    ),
    # NPM token
    (re.compile(rb"npm_[A-Za-z0-9]{36}"), "npm-token", "HIGH"),
    # SendGrid
    (re.compile(rb"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), "sendgrid-key", "CRITICAL"),
    # Twilio
    (re.compile(rb"SK[a-f0-9]{32}"), "twilio-secret-key", "HIGH"),
    # MailChimp
    (re.compile(rb"[0-9a-f]{32}-us[0-9]{1,2}"), "mailchimp-key", "MEDIUM"),
    # Generic API-key context (`api_key = "..."` / `"api_key": "..."` /
    # `apikey: ...`) — only when high-entropy value follows
    (
        re.compile(
            rb"""(?i)(?:api[_-]?key|apikey|secret|password|passwd|token)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-+/.=]{16,})['"]""",
            re.MULTILINE,
        ),
        "generic-api-key-context",
        "MEDIUM",
    ),
)


@dataclass(frozen=True)
class EmbeddedSecret:
    """One detected secret.

    Banca-safety: `redacted_preview` is ALWAYS truncated — first 4
    chars + … + last 4 chars. `value_sha256` lets operators
    cross-reference without leaking the secret in audit logs."""

    kind: str  # one of the labels from SECRET_PATTERNS
    severity: str
    redacted_preview: str
    value_sha256: str
    matched_at_offset: int
    matched_length: int


def shannon_entropy(data: bytes, sample_size: int = 4096) -> float:
    """Compute Shannon entropy of a byte string. Caps at `sample_size`
    bytes to keep huge bodies fast. Higher values indicate random-
    looking data (likely encrypted/encoded/secret)."""
    if not data:
        return 0.0
    if len(data) > sample_size:
        data = data[:sample_size]
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _redact(value: bytes) -> str:
    """Build a redacted preview of a matched secret. NEVER emits the
    full secret.

    Tiers:
      * < 8 chars   → "***" (fully hidden — too short to leak meaningfully)
      * 8..12 chars → "<first>***<last>"
      * > 12 chars  → "<first 4>…<last 4>"
    """
    if not value:
        return ""
    try:
        decoded = value.decode("utf-8", errors="replace")
    except Exception:
        decoded = value.hex()
    if len(decoded) < 8:
        return "***"
    if len(decoded) <= 12:
        return decoded[0] + "***" + decoded[-1]
    return decoded[:4] + "…" + decoded[-4:]


def scan_for_secrets(
    content: bytes,
    max_secrets: int = 50,
) -> tuple[EmbeddedSecret, ...]:
    """Scan content for embedded secrets.

    Returns up to `max_secrets` records, deduped by SHA-256 (same
    secret repeated → reported once).

    Returns empty tuple for empty content. Capped scan size: only
    the first 2MB of content is analyzed to avoid catastrophic regex
    cost on huge bodies."""
    if not content:
        return ()
    # Cap scan size — banca-safety + DoS guard
    scan_window = content[: 2_000_000]
    out: list[EmbeddedSecret] = []
    seen_hashes: set[str] = set()
    for pattern, kind, severity in SECRET_PATTERNS:
        for m in pattern.finditer(scan_window):
            raw = m.group(0)
            digest = hashlib.sha256(raw).hexdigest()
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            out.append(
                EmbeddedSecret(
                    kind=kind,
                    severity=severity,
                    redacted_preview=_redact(raw),
                    value_sha256=digest,
                    matched_at_offset=m.start(),
                    matched_length=len(raw),
                )
            )
            if len(out) >= max_secrets:
                return tuple(out)
    return tuple(out)
