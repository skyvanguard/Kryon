"""F87.5 — JWT static validator (claim + algorithm analysis).

JWTs are the authorization currency of every Open Banking deployment
in LATAM, and their failure modes are well-documented: alg=none,
RS256→HS256 key confusion, missing aud/iss, kid path traversal,
unrestricted jku/x5u headers. This module performs pure-static
analysis on a JWT — parse the header + payload, inspect the claims,
flag every common weakness — without ever attempting cryptographic
verification (that needs the issuer's public key the operator
provides through a separate channel).

Static analysis scope:
  - Parse JWT structure (header.payload.signature, base64url decode).
  - Algorithm checks:
      alg=none                   → CRITICAL (CVE-2015-9235 family)
      alg=HS256 + provided pubkey → CRITICAL (key confusion)
      alg=HS384/HS512 + pubkey   → CRITICAL (same confusion)
  - Claim checks:
      exp missing                → HIGH (no expiration)
      exp expired                → MEDIUM (informational; replay window)
      iat in the future          → HIGH (clock skew or forgery)
      nbf in the future          → MEDIUM (not-yet-valid)
      aud missing / mismatched   → HIGH (audience confusion)
      iss missing / mismatched   → HIGH (issuer spoofing)
      sub missing                → MEDIUM
  - Header smell tests:
      kid with path-traversal    → CRITICAL (./. ../ %2f patterns)
      jku / x5u to untrusted host→ HIGH (key-fetch injection)
      typ ≠ JWT (when present)   → MEDIUM (smuggling)

Banca-safety:
  - PURE static analysis. No signing, no verification, no
    cryptographic operations. The validator never produces a token.
  - The token string is treated as opaque metadata. Even sensitive
    claims (sub, email, jti) stay inside the analyzed token object —
    they are NOT re-emitted in the JWTAnalysis output. The analysis
    surfaces only weakness names, severities, and short reasons.
  - No I/O. The caller supplies expected aud/iss as parameters.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "JWTToken",
    "JWTFinding",
    "JWTAnalysis",
    "parse_jwt",
    "analyze_jwt",
    "JWTParseError",
    "KNOWN_SIGNATURE_ALGS",
]


# Algorithms that legitimate signing operations use. `none` and any
# unrecognized algorithm trip the analyzer.
KNOWN_SIGNATURE_ALGS = frozenset(
    {
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES256K",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    }
)


class JWTParseError(ValueError):
    """Raised when the input doesn't look like a JWT at all."""


@dataclass(frozen=True)
class JWTToken:
    """Parsed JWT structure. Header + payload are dicts; signature
    is the raw base64url segment (we don't decode it because the
    analyzer doesn't verify it)."""

    header: dict[str, Any]
    payload: dict[str, Any]
    signature_b64: str
    raw_header_b64: str
    raw_payload_b64: str

    @property
    def alg(self) -> str:
        """Algorithm advertised in the header. Returns empty string
        when missing — the analyzer flags that as a CRITICAL."""
        a = self.header.get("alg")
        return str(a) if isinstance(a, str) else ""

    @property
    def kid(self) -> str | None:
        k = self.header.get("kid")
        return str(k) if isinstance(k, str) else None

    @property
    def jku(self) -> str | None:
        j = self.header.get("jku")
        return str(j) if isinstance(j, str) else None

    @property
    def x5u(self) -> str | None:
        x = self.header.get("x5u")
        return str(x) if isinstance(x, str) else None


@dataclass(frozen=True)
class JWTFinding:
    """One detected weakness."""

    finding_id: str  # JWT-001 through JWT-NNN (stable codes)
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    remediation: str


@dataclass(frozen=True)
class JWTAnalysis:
    """Aggregated analysis result."""

    parsed: bool
    findings: tuple[JWTFinding, ...] = field(default_factory=tuple)
    alg_observed: str = ""
    claims_present: tuple[str, ...] = field(default_factory=tuple)
    # The original token is NOT surfaced — banca-safety: callers
    # should pass the original token reference separately if they
    # need it.


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _base64url_decode(segment: str) -> bytes:
    """RFC 7515 §2: base64url, no padding. We add the padding back
    before decoding."""
    if not segment:
        raise JWTParseError("empty segment")
    pad = 4 - len(segment) % 4
    if pad and pad < 4:
        segment = segment + ("=" * pad)
    try:
        return base64.urlsafe_b64decode(segment)
    except (ValueError, base64.binascii.Error) as e:
        raise JWTParseError(f"base64url decode failed: {e}") from e


def parse_jwt(token: str) -> JWTToken:
    """Parse a JWT string into a JWTToken.

    Strict on structure (must have exactly three dot-separated
    segments) and on the JSON shape of header + payload (must
    decode to dicts). Defensive everywhere else.
    """
    token = (token or "").strip()
    if not token:
        raise JWTParseError("empty token")
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTParseError(f"JWT must have 3 dot-separated segments; got {len(parts)}")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header_bytes = _base64url_decode(header_b64)
        payload_bytes = _base64url_decode(payload_b64)
    except JWTParseError:
        raise

    try:
        header = json.loads(header_bytes)
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise JWTParseError(f"header/payload JSON invalid: {e}") from e

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JWTParseError("header and payload must be JSON objects")

    return JWTToken(
        header=header,
        payload=payload,
        signature_b64=signature_b64,
        raw_header_b64=header_b64,
        raw_payload_b64=payload_b64,
    )


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------


# Path-traversal indicators in `kid` values. Attackers use these to
# pivot key lookup to arbitrary paths under the verifier's
# filesystem-backed key store.
# All lower-case — the analyzer matches against kid.lower() so
# Windows paths like "C:\Windows\..." must be normalised to "c:\".
_KID_TRAVERSAL_PATTERNS = (
    "../",
    "..\\",
    "%2e%2e",
    "%2f",
    "%5c",
    "/etc/",
    "c:\\",
    "../../",
)


def _check_alg(token: JWTToken, allow_hmac_with_pubkey: bool) -> list[JWTFinding]:
    findings: list[JWTFinding] = []
    alg = token.alg

    if not alg:
        findings.append(
            JWTFinding(
                finding_id="JWT-001",
                severity="CRITICAL",
                title="Missing alg header",
                detail="JWT header has no 'alg' field; verifiers may default-accept unsigned tokens.",
                remediation="Reject tokens without an explicit alg claim; pin alg to a server-chosen value.",
            )
        )
        return findings

    if alg.lower() == "none":
        findings.append(
            JWTFinding(
                finding_id="JWT-002",
                severity="CRITICAL",
                title="Algorithm 'none' accepted",
                detail=(
                    "Token advertises alg=none. Verifiers that honor the header "
                    "algorithm skip signature verification entirely (CVE-2015-9235)."
                ),
                remediation=(
                    "Hard-code the expected algorithm at the verifier; never trust the alg field from the token header."
                ),
            )
        )

    if alg not in KNOWN_SIGNATURE_ALGS and alg.lower() != "none":
        findings.append(
            JWTFinding(
                finding_id="JWT-003",
                severity="HIGH",
                title="Unknown signing algorithm",
                detail=(
                    f"Algorithm {alg!r} is not in the known signature set. "
                    "Custom algorithms are rarely well-vetted; verifiers may "
                    "accept arbitrary input."
                ),
                remediation="Pin alg to a standard value (RS256/ES256/PS256 recommended).",
            )
        )

    if allow_hmac_with_pubkey and alg.upper() in ("HS256", "HS384", "HS512"):
        findings.append(
            JWTFinding(
                finding_id="JWT-004",
                severity="CRITICAL",
                title="Symmetric algorithm + public key in scope",
                detail=(
                    f"Token uses {alg}, the operator indicated the verifier holds the "
                    "issuer's public key. Attackers re-sign tokens with the public key "
                    "as the HMAC secret (key confusion). Verifiers that don't pin alg "
                    "treat the forgery as valid."
                ),
                remediation=(
                    "Hard-code alg to the expected asymmetric value at the verifier; "
                    "never derive the HMAC key from a key the attacker can read."
                ),
            )
        )

    return findings


def _claim_present(claim: Any) -> bool:
    """A claim is 'present' when it's non-null and non-empty."""
    if claim is None:
        return False
    if isinstance(claim, str) and not claim.strip():
        return False
    return True


def _check_temporal_claims(token: JWTToken, leeway_seconds: int = 60) -> list[JWTFinding]:
    findings: list[JWTFinding] = []
    payload = token.payload
    now = datetime.now(timezone.utc).timestamp()

    exp = payload.get("exp")
    if not _claim_present(exp):
        findings.append(
            JWTFinding(
                finding_id="JWT-010",
                severity="HIGH",
                title="Missing exp claim",
                detail="Token has no expiration; once stolen it stays valid forever.",
                remediation="Always include exp; typical lifetime 5-15 minutes for access tokens.",
            )
        )
    elif isinstance(exp, (int, float)):
        if exp + leeway_seconds < now:
            findings.append(
                JWTFinding(
                    finding_id="JWT-011",
                    severity="MEDIUM",
                    title="Token expired",
                    detail=(
                        f"exp claim {datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()} "
                        "is in the past. Informational: verifiers should already be rejecting."
                    ),
                    remediation="Confirm the verifier checks exp; nothing to fix on the token itself.",
                )
            )

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and iat > now + leeway_seconds:
        findings.append(
            JWTFinding(
                finding_id="JWT-012",
                severity="HIGH",
                title="iat claim in the future",
                detail=(
                    "Token's issued-at timestamp is in the future. Either clock "
                    "skew between issuer and verifier, or a forgery attempt."
                ),
                remediation="Reject tokens with iat > now + leeway; widen leeway only if NTP-attested.",
            )
        )

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > now + leeway_seconds:
        findings.append(
            JWTFinding(
                finding_id="JWT-013",
                severity="MEDIUM",
                title="Token not yet valid",
                detail=(f"nbf={datetime.fromtimestamp(nbf, tz=timezone.utc).isoformat()} is in the future."),
                remediation="Check verifier honors nbf; otherwise tokens are valid before their issuer intended.",
            )
        )

    return findings


def _check_identity_claims(
    token: JWTToken,
    *,
    expected_audience: str | None,
    expected_issuer: str | None,
) -> list[JWTFinding]:
    findings: list[JWTFinding] = []
    payload = token.payload

    aud = payload.get("aud")
    if not _claim_present(aud):
        findings.append(
            JWTFinding(
                finding_id="JWT-020",
                severity="HIGH",
                title="Missing aud claim",
                detail=(
                    "Token has no audience binding. Tokens issued for one service "
                    "can be replayed against another in the same trust domain."
                ),
                remediation="Require aud at the verifier; pin to the expected service identifier.",
            )
        )
    elif expected_audience:
        # aud may be a string or a list of strings (RFC 7519 §4.1.3).
        aud_set: set[str] = set()
        if isinstance(aud, str):
            aud_set = {aud}
        elif isinstance(aud, list):
            aud_set = {str(a) for a in aud}
        if expected_audience not in aud_set:
            findings.append(
                JWTFinding(
                    finding_id="JWT-021",
                    severity="HIGH",
                    title="aud claim does not match expected value",
                    detail=(
                        f"Token aud={sorted(aud_set)} does not include "
                        f"{expected_audience!r}. Audience confusion in scope."
                    ),
                    remediation="Reject; verify the issuer is binding tokens to the correct audience.",
                )
            )

    iss = payload.get("iss")
    if not _claim_present(iss):
        findings.append(
            JWTFinding(
                finding_id="JWT-022",
                severity="HIGH",
                title="Missing iss claim",
                detail="No issuer claim — can't tell which IdP minted this token.",
                remediation="Require iss; pin to a whitelist of trusted issuers.",
            )
        )
    elif expected_issuer and str(iss) != expected_issuer:
        findings.append(
            JWTFinding(
                finding_id="JWT-023",
                severity="HIGH",
                title="iss claim does not match expected value",
                detail=f"Token iss={iss!r}, expected {expected_issuer!r}.",
                remediation="Reject; investigate whether a rogue IdP minted the token.",
            )
        )

    sub = payload.get("sub")
    if not _claim_present(sub):
        findings.append(
            JWTFinding(
                finding_id="JWT-024",
                severity="MEDIUM",
                title="Missing sub claim",
                detail="No subject — token isn't bound to a user identity.",
                remediation="Require sub for any user-context token.",
            )
        )

    return findings


def _check_kid_traversal(token: JWTToken) -> list[JWTFinding]:
    """`kid` is operator-controlled metadata that some verifiers use
    as a filename. Attackers point it at /dev/null + a known
    signature, or at an asset bundled in the verifier that gives a
    predictable HMAC key."""
    kid = token.kid
    if not kid:
        return []
    findings: list[JWTFinding] = []
    lower = kid.lower()
    if any(pattern in lower for pattern in _KID_TRAVERSAL_PATTERNS):
        findings.append(
            JWTFinding(
                finding_id="JWT-030",
                severity="CRITICAL",
                title="kid header carries path-traversal pattern",
                detail=(
                    f"kid={kid!r}. Verifiers using kid as a filesystem path can be "
                    "tricked into loading attacker-chosen keys (kid injection)."
                ),
                remediation=(
                    "Treat kid as opaque; look it up in a hash map keyed on "
                    "well-known identifiers. Never concatenate kid into a path."
                ),
            )
        )
    return findings


def _check_url_headers(
    token: JWTToken,
    *,
    trusted_hosts: tuple[str, ...] = (),
) -> list[JWTFinding]:
    """jku + x5u are URLs the verifier may fetch to resolve the
    signing key. Unconstrained, an attacker hosts their own key set
    and the verifier signs off on attacker-controlled tokens."""
    findings: list[JWTFinding] = []
    trusted = {h.lower() for h in trusted_hosts}
    for header_name, attr in (("jku", token.jku), ("x5u", token.x5u)):
        if not attr:
            continue
        try:
            from urllib.parse import urlparse

            parsed = urlparse(attr)
            host = (parsed.hostname or "").lower()
        except Exception:  # noqa: BLE001
            host = ""
        if not trusted_hosts:
            findings.append(
                JWTFinding(
                    finding_id="JWT-040",
                    severity="HIGH",
                    title=f"{header_name} header present without trusted-host whitelist",
                    detail=(
                        f"{header_name}={attr!r}. Verifier may fetch keys from "
                        "this URL; with no host whitelist, attackers point at their "
                        "own JWKS endpoint."
                    ),
                    remediation=(
                        f"Pin allowed {header_name} hosts to the issuer's published JWKS URL; reject everything else."
                    ),
                )
            )
        elif host not in trusted:
            findings.append(
                JWTFinding(
                    finding_id="JWT-041",
                    severity="HIGH",
                    title=f"{header_name} host not in trusted list",
                    detail=(f"{header_name} points at {host!r} which is not in trusted_hosts={sorted(trusted)}."),
                    remediation=f"Reject tokens whose {header_name} resolves outside the whitelist.",
                )
            )
    return findings


def _check_typ(token: JWTToken) -> list[JWTFinding]:
    """RFC 7519 says typ SHOULD be 'JWT' (case-insensitive). When
    present and non-JWT, the token may be a smuggling vehicle (e.g.
    a JOSE-style nested JWE)."""
    typ = token.header.get("typ")
    if not isinstance(typ, str):
        return []
    if typ.strip().upper() not in ("JWT", "JOSE", "AT+JWT"):
        return [
            JWTFinding(
                finding_id="JWT-050",
                severity="MEDIUM",
                title="Unusual typ header",
                detail=(
                    f"typ={typ!r}; non-JWT typ values can signal nested tokens or smuggling. Confirm intended use."
                ),
                remediation="Pin acceptable typ values at the verifier.",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def analyze_jwt(
    token_string: str,
    *,
    expected_audience: str | None = None,
    expected_issuer: str | None = None,
    expected_alg: str | None = None,
    allow_hmac_with_pubkey: bool = False,
    trusted_jku_hosts: tuple[str, ...] = (),
    leeway_seconds: int = 60,
) -> JWTAnalysis:
    """Run static analysis against `token_string`.

    Args:
        token_string: the raw JWT (header.payload.signature).
        expected_audience: the verifier's identifier — JWT-021 fires
            when the token's aud doesn't include it.
        expected_issuer: trusted issuer — JWT-023 fires on mismatch.
        expected_alg: pin the expected algorithm. JWT-005 fires when
            the token's alg doesn't match (separate from JWT-002
            alg=none). Optional.
        allow_hmac_with_pubkey: when True, signals to the alg checker
            that the verifier holds the issuer's public key — this
            turns HS256/384/512 tokens into JWT-004 (key confusion).
        trusted_jku_hosts: whitelist of hosts the jku/x5u headers may
            point at. Empty = warn on any jku/x5u presence.
        leeway_seconds: clock-skew tolerance for exp/iat/nbf checks.

    Returns:
        JWTAnalysis. parsed=False when the token didn't parse at all
        (single CRITICAL finding describes why).
    """
    try:
        token = parse_jwt(token_string)
    except JWTParseError as e:
        return JWTAnalysis(
            parsed=False,
            findings=(
                JWTFinding(
                    finding_id="JWT-000",
                    severity="CRITICAL",
                    title="JWT failed to parse",
                    detail=str(e),
                    remediation="Confirm the input is a valid JWT (header.payload.signature base64url).",
                ),
            ),
        )

    findings: list[JWTFinding] = []
    findings.extend(_check_alg(token, allow_hmac_with_pubkey=allow_hmac_with_pubkey))
    if expected_alg and token.alg and token.alg != expected_alg:
        findings.append(
            JWTFinding(
                finding_id="JWT-005",
                severity="HIGH",
                title="Algorithm does not match expected value",
                detail=f"Token alg={token.alg!r}, verifier expected {expected_alg!r}.",
                remediation="Reject; pin alg at the verifier to defeat algorithm-substitution attacks.",
            )
        )
    findings.extend(_check_temporal_claims(token, leeway_seconds=leeway_seconds))
    findings.extend(
        _check_identity_claims(
            token,
            expected_audience=expected_audience,
            expected_issuer=expected_issuer,
        )
    )
    findings.extend(_check_kid_traversal(token))
    findings.extend(_check_url_headers(token, trusted_hosts=trusted_jku_hosts))
    findings.extend(_check_typ(token))

    claims_present = tuple(sorted(k for k, v in token.payload.items() if _claim_present(v)))

    return JWTAnalysis(
        parsed=True,
        findings=tuple(findings),
        alg_observed=token.alg,
        claims_present=claims_present,
    )
