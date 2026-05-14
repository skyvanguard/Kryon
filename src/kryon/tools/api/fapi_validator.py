"""F87.4 — FAPI 1.0 Advanced compliance validator.

Validates an OpenID Connect / OAuth 2.0 authorization server against
the **FAPI 1.0 Advanced** profile (openid.net/specs/
openid-financial-api-part-2-1_0.html). FAPI Advanced is the baseline
Open Banking requires in LATAM (Banco Central do Brasil OBB, BCP
Paraguay), Europe (PSD2 RTS), UK (Open Banking Implementation
Entity), and Australia (Consumer Data Right).

The validator runs over the server's **OpenID Connect Discovery
document** — the JSON returned by `<issuer>/.well-known/
openid-configuration`. Every check here is a static read on that
document; no live OAuth dance, no client registration, no
cryptographic operations. That keeps the validator banca-safe and
trivially reproducible (the discovery doc is the same byte sequence
every operator sees; the same input always produces the same report).

Checks (numbered to match the report):

  FAPI-1   PAR endpoint declared (`pushed_authorization_request_endpoint`).
           FAPI Advanced §5.2.2.1: request parameters MUST be pushed
           to the AS via PAR (RFC 9126). Without PAR, the AS can't
           bind the request to the client and a CSRF-on-redirect
           attack reopens.
  FAPI-2   Request object signing algorithm: PS256 OR ES256 declared.
           §5.2.2: `request_object_signing_alg_values_supported` MUST
           include at least one PS256 / ES256. RS256 alone is
           insufficient (deprecated by FAPI Advanced).
  FAPI-3   ID token signing algorithm: PS256 OR ES256 declared.
           `id_token_signing_alg_values_supported` — same rule as F2,
           applied to the ID token instead of the request object.
  FAPI-4   Strong client auth: `private_key_jwt` OR `tls_client_auth`.
           §5.2.2: `token_endpoint_auth_methods_supported` MUST
           include at least one. `client_secret_*` methods are FAPI-
           non-compliant for the Advanced profile.
  FAPI-5   Sender-constrained tokens: mTLS-bound OR DPoP.
           Either `tls_client_certificate_bound_access_tokens=true`
           OR `dpop_signing_alg_values_supported` declared. FAPI
           Advanced requires sender-constrained tokens to prevent
           token replay (RFC 8705 mTLS-bound, RFC 9449 DPoP).
  FAPI-6   PKCE S256: `code_challenge_methods_supported` MUST
           include `S256`. `plain` alone is non-compliant.
  FAPI-7   Implicit flow disabled: `response_types_supported` MUST
           NOT include `id_token` or `token` types without `code`.
           Implicit and hybrid flows are FAPI-banned (§5.2.2.6).
  FAPI-8   JWT-protected response modes:
           `response_modes_supported` should include at least one of
           `jwt`, `query.jwt`, `fragment.jwt`, `form_post.jwt` (JARM,
           OpenID Financial-grade API: JWT Secured Authorization
           Response Mode).
  FAPI-9   Open Banking scopes present: scopes_supported includes
           `payments`, `accounts`, `openid`, etc. INFO-only — scope
           naming is profile-specific; flagged so the auditor
           verifies the bank's chosen scope vocabulary.
  FAPI-10  Phishing-resistant ACR/AMR: `acr_values_supported` or
           `amr_values_supported` includes `urn:openbanking:psd2:sca`
           OR `hwk`, `phr`, `phrh`. PSD2 SCA mandates the AS
           announces these to clients.

Each check returns a `FAPICheckResult` with:
  - check_id   ("FAPI-1" … "FAPI-10")
  - severity   (CRITICAL / HIGH / MEDIUM / INFO)
  - status     ("pass" / "fail" / "warning" / "inapplicable")
  - expected   ("PS256 or ES256")
  - actual     (e.g. "['RS256']")
  - remediation (one-line guidance)
  - rationale  (1-2 sentence FAPI clause reference)

The aggregate `FAPIComplianceReport.compliant` is True only when
every CRITICAL + HIGH check is pass — same gate Open Banking
Conformance suites use.

Banca-safety:
  - All checks are pure reads on a dict — no I/O, no cryptography.
  - The optional `fetch_discovery_document(issuer_url, fire=...)`
    helper uses stdlib urllib with the same double-gate as
    F87.2 / F87.3 (`KRYON_FAPI_FIRE=true` env + arg).
  - Discovery JSON is bounded at 1 MB; specs say "small JSON document"
    and a runaway response is suspicious.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

__all__ = [
    "FAPIDiscovery",
    "FAPICheckResult",
    "FAPIComplianceReport",
    "parse_discovery",
    "validate_fapi_advanced",
    "fetch_discovery_document",
    "ALL_FAPI_CHECKS",
    "DISCOVERY_RESPONSE_CAP_BYTES",
]


# Spec says discovery doc is "small JSON". 1 MB is a generous cap.
DISCOVERY_RESPONSE_CAP_BYTES = 1 * 1024 * 1024

# FAPI Advanced requires asymmetric, post-RSA signing.
_FAPI_ADV_SIGNING_ALGS = {"PS256", "ES256", "PS384", "ES384", "PS512", "ES512"}

# FAPI-compliant token endpoint auth methods.
_FAPI_ADV_CLIENT_AUTH_METHODS = {"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}

# JARM response modes acceptable per FAPI Advanced §5.2.2.
_FAPI_ADV_JWT_RESPONSE_MODES = {"jwt", "query.jwt", "fragment.jwt", "form_post.jwt"}

# AMR claim values that satisfy "phishing-resistant" per FAPI + PSD2
# SCA + RFC 8176. urn:openbanking:psd2:sca is a recognized ACR string.
_PHISHING_RESISTANT_AMR = {"hwk", "phr", "phrh"}
_PHISHING_RESISTANT_ACR = {"urn:openbanking:psd2:sca"}


@dataclass(frozen=True)
class FAPIDiscovery:
    """Compact view of an OpenID Connect Discovery document.

    Only the fields FAPI Advanced touches are surfaced — the original
    JSON is preserved as `raw` for downstream consumers that need
    something exotic. Tuples instead of lists so the dataclass is
    hashable + comparable across runs.
    """

    issuer: str
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    par_endpoint: str | None = None
    jwks_uri: str | None = None
    response_types_supported: tuple[str, ...] = field(default_factory=tuple)
    response_modes_supported: tuple[str, ...] = field(default_factory=tuple)
    grant_types_supported: tuple[str, ...] = field(default_factory=tuple)
    request_object_signing_alg_values: tuple[str, ...] = field(default_factory=tuple)
    id_token_signing_alg_values: tuple[str, ...] = field(default_factory=tuple)
    token_endpoint_auth_methods: tuple[str, ...] = field(default_factory=tuple)
    code_challenge_methods_supported: tuple[str, ...] = field(default_factory=tuple)
    scopes_supported: tuple[str, ...] = field(default_factory=tuple)
    acr_values_supported: tuple[str, ...] = field(default_factory=tuple)
    amr_values_supported: tuple[str, ...] = field(default_factory=tuple)
    tls_client_certificate_bound_access_tokens: bool = False
    dpop_signing_alg_values_supported: tuple[str, ...] = field(default_factory=tuple)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FAPICheckResult:
    """One check outcome."""

    check_id: str
    title: str
    severity: str  # CRITICAL / HIGH / MEDIUM / INFO
    status: str  # pass / fail / warning / inapplicable
    expected: str
    actual: str
    remediation: str
    rationale: str


@dataclass(frozen=True)
class FAPIComplianceReport:
    """Aggregated outcome of validating one discovery document."""

    issuer: str
    profile: str  # "fapi_1_advanced"
    results: tuple[FAPICheckResult, ...]
    compliant: bool  # True iff every CRITICAL + HIGH check is "pass"
    summary: dict[str, int] = field(default_factory=dict)  # status -> count


# ---------------------------------------------------------------------------
# Discovery doc parser
# ---------------------------------------------------------------------------


def _str_tuple(node: Any) -> tuple[str, ...]:
    """Coerce a JSON value into a tuple of strings, dedupe-preserving
    order. Non-list / non-str inputs collapse to empty."""
    if not isinstance(node, list):
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for item in node:
        if not isinstance(item, str):
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return tuple(out)


def parse_discovery(doc: dict[str, Any]) -> FAPIDiscovery:
    """Build a FAPIDiscovery from a parsed discovery JSON dict.

    Defensive: missing/wrong-shape keys collapse to defaults. The
    full doc is preserved in `raw` so a curator can inspect anything
    we don't surface."""
    if not isinstance(doc, dict):
        return FAPIDiscovery(issuer="")

    issuer = str(doc.get("issuer") or "")
    return FAPIDiscovery(
        issuer=issuer,
        authorization_endpoint=str(doc["authorization_endpoint"])
        if isinstance(doc.get("authorization_endpoint"), str)
        else None,
        token_endpoint=str(doc["token_endpoint"]) if isinstance(doc.get("token_endpoint"), str) else None,
        par_endpoint=str(doc["pushed_authorization_request_endpoint"])
        if isinstance(doc.get("pushed_authorization_request_endpoint"), str)
        else None,
        jwks_uri=str(doc["jwks_uri"]) if isinstance(doc.get("jwks_uri"), str) else None,
        response_types_supported=_str_tuple(doc.get("response_types_supported")),
        response_modes_supported=_str_tuple(doc.get("response_modes_supported")),
        grant_types_supported=_str_tuple(doc.get("grant_types_supported")),
        request_object_signing_alg_values=_str_tuple(doc.get("request_object_signing_alg_values_supported")),
        id_token_signing_alg_values=_str_tuple(doc.get("id_token_signing_alg_values_supported")),
        token_endpoint_auth_methods=_str_tuple(doc.get("token_endpoint_auth_methods_supported")),
        code_challenge_methods_supported=_str_tuple(doc.get("code_challenge_methods_supported")),
        scopes_supported=_str_tuple(doc.get("scopes_supported")),
        acr_values_supported=_str_tuple(doc.get("acr_values_supported")),
        amr_values_supported=_str_tuple(doc.get("amr_values_supported")),
        tls_client_certificate_bound_access_tokens=bool(doc.get("tls_client_certificate_bound_access_tokens", False)),
        dpop_signing_alg_values_supported=_str_tuple(doc.get("dpop_signing_alg_values_supported")),
        raw=doc,
    )


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_par(d: FAPIDiscovery) -> FAPICheckResult:
    status = "pass" if d.par_endpoint else "fail"
    return FAPICheckResult(
        check_id="FAPI-1",
        title="Pushed Authorization Request endpoint declared",
        severity="CRITICAL",
        status=status,
        expected="pushed_authorization_request_endpoint key present",
        actual=d.par_endpoint or "(missing)",
        remediation="Add a PAR endpoint (RFC 9126) and advertise it in discovery.",
        rationale="FAPI Advanced §5.2.2.1: clients MUST use PAR to bind authorization parameters to the request.",
    )


def _check_request_object_signing(d: FAPIDiscovery) -> FAPICheckResult:
    allowed = _FAPI_ADV_SIGNING_ALGS & set(d.request_object_signing_alg_values)
    status = "pass" if allowed else "fail"
    return FAPICheckResult(
        check_id="FAPI-2",
        title="Request object signing — PS256/ES256",
        severity="CRITICAL",
        status=status,
        expected=f"at least one of {sorted(_FAPI_ADV_SIGNING_ALGS)}",
        actual=str(list(d.request_object_signing_alg_values)) or "(missing)",
        remediation="Add PS256 or ES256 to request_object_signing_alg_values_supported.",
        rationale="FAPI Advanced §5.2.2.7: request objects must be signed with PS256 / ES256; RS256 alone is non-compliant.",
    )


def _check_id_token_signing(d: FAPIDiscovery) -> FAPICheckResult:
    allowed = _FAPI_ADV_SIGNING_ALGS & set(d.id_token_signing_alg_values)
    status = "pass" if allowed else "fail"
    return FAPICheckResult(
        check_id="FAPI-3",
        title="ID token signing — PS256/ES256",
        severity="CRITICAL",
        status=status,
        expected=f"at least one of {sorted(_FAPI_ADV_SIGNING_ALGS)}",
        actual=str(list(d.id_token_signing_alg_values)) or "(missing)",
        remediation="Add PS256 or ES256 to id_token_signing_alg_values_supported.",
        rationale="FAPI Advanced §5.2.2.7: ID tokens must use PS256 / ES256; RS256 was deprecated.",
    )


def _check_client_auth(d: FAPIDiscovery) -> FAPICheckResult:
    matched = _FAPI_ADV_CLIENT_AUTH_METHODS & set(d.token_endpoint_auth_methods)
    status = "pass" if matched else "fail"
    return FAPICheckResult(
        check_id="FAPI-4",
        title="Strong client authentication (private_key_jwt or tls_client_auth)",
        severity="CRITICAL",
        status=status,
        expected=f"at least one of {sorted(_FAPI_ADV_CLIENT_AUTH_METHODS)}",
        actual=str(list(d.token_endpoint_auth_methods)) or "(missing)",
        remediation="Add private_key_jwt or tls_client_auth to token_endpoint_auth_methods_supported; drop client_secret_basic/post for the FAPI profile.",
        rationale="FAPI Advanced §5.2.2: client_secret_* methods are weak; FAPI requires asymmetric or mTLS client auth.",
    )


def _check_sender_constrained_tokens(d: FAPIDiscovery) -> FAPICheckResult:
    if d.tls_client_certificate_bound_access_tokens:
        status = "pass"
        actual = "tls_client_certificate_bound_access_tokens=true"
    elif d.dpop_signing_alg_values_supported:
        status = "pass"
        actual = f"DPoP algs declared: {list(d.dpop_signing_alg_values_supported)}"
    else:
        status = "fail"
        actual = "neither mTLS-bound nor DPoP declared"
    return FAPICheckResult(
        check_id="FAPI-5",
        title="Sender-constrained access tokens (mTLS-bound or DPoP)",
        severity="CRITICAL",
        status=status,
        expected="tls_client_certificate_bound_access_tokens=true OR dpop_signing_alg_values_supported",
        actual=actual,
        remediation="Enable mTLS-bound tokens (RFC 8705) or DPoP (RFC 9449) on the AS.",
        rationale="FAPI Advanced requires sender-constrained tokens to prevent replay.",
    )


def _check_pkce_s256(d: FAPIDiscovery) -> FAPICheckResult:
    methods = set(d.code_challenge_methods_supported)
    status = "pass" if "S256" in methods else "fail"
    return FAPICheckResult(
        check_id="FAPI-6",
        title="PKCE with S256 supported",
        severity="HIGH",
        status=status,
        expected="S256 in code_challenge_methods_supported",
        actual=str(list(d.code_challenge_methods_supported)) or "(missing)",
        remediation="Add 'S256' to code_challenge_methods_supported; drop 'plain'.",
        rationale="FAPI Advanced §5.2.2.6: PKCE with S256 is mandatory; 'plain' is non-compliant.",
    )


def _check_no_implicit_flow(d: FAPIDiscovery) -> FAPICheckResult:
    """Implicit (`token`, `id_token`) and hybrid (`code id_token`,
    `code token`) flows are banned. The `code` response type may
    appear; everything else must include `code` as well — and never
    just `token` or `id_token` alone."""
    response_types = list(d.response_types_supported)
    bad: list[str] = []
    for rt in response_types:
        parts = set(rt.split())
        if "code" not in parts:
            bad.append(rt)
    status = "fail" if bad else "pass"
    return FAPICheckResult(
        check_id="FAPI-7",
        title="Implicit flow disabled — every response type includes code",
        severity="CRITICAL",
        status=status,
        expected="only response types that include 'code'",
        actual=f"non-code response_types: {bad}" if bad else "all response types include code",
        remediation="Remove 'token', 'id_token', 'id_token token' from response_types_supported.",
        rationale="FAPI Advanced §5.2.2.6: implicit and hybrid (token-returning) flows are banned.",
    )


def _check_jarm(d: FAPIDiscovery) -> FAPICheckResult:
    modes = set(d.response_modes_supported)
    jwt_modes = _FAPI_ADV_JWT_RESPONSE_MODES & modes
    if jwt_modes:
        status = "pass"
        actual = f"JARM modes declared: {sorted(jwt_modes)}"
    else:
        status = "warning"  # JARM is recommended, not strict-required
        actual = f"no JARM mode declared. response_modes_supported = {sorted(modes)}"
    return FAPICheckResult(
        check_id="FAPI-8",
        title="JARM JWT-protected response mode declared",
        severity="MEDIUM",
        status=status,
        expected=f"at least one of {sorted(_FAPI_ADV_JWT_RESPONSE_MODES)}",
        actual=actual,
        remediation="Add jwt / query.jwt / fragment.jwt / form_post.jwt to response_modes_supported.",
        rationale="OpenID JARM gives signed authorization responses; FAPI Advanced strongly recommends it for tamper protection.",
    )


def _check_open_banking_scopes(d: FAPIDiscovery) -> FAPICheckResult:
    """INFO-only: scope vocabulary is profile-specific
    (Open Banking UK uses 'payments accounts fundsconfirmations';
    Brazil OBB uses 'accounts:read', etc.). We surface what's
    declared so the curator can verify against the bank's profile."""
    scopes = list(d.scopes_supported)
    common_ob = {"payments", "accounts", "openid"}
    matched = common_ob & set(scopes)
    if matched:
        status = "pass"
        actual = f"OB-shaped scopes: {sorted(matched)}"
    else:
        status = "warning"
        actual = f"scopes_supported = {scopes!r}"
    return FAPICheckResult(
        check_id="FAPI-9",
        title="Open Banking scope vocabulary declared",
        severity="INFO",
        status=status,
        expected="at least one of {payments, accounts, openid}",
        actual=actual,
        remediation="Declare the Open Banking scope vocabulary your profile uses in scopes_supported.",
        rationale="Profile-specific. INFO check — auditor verifies against the bank's scope spec.",
    )


def _check_phishing_resistant_acr(d: FAPIDiscovery) -> FAPICheckResult:
    acr_match = _PHISHING_RESISTANT_ACR & set(d.acr_values_supported)
    amr_match = _PHISHING_RESISTANT_AMR & set(d.amr_values_supported)
    if acr_match or amr_match:
        status = "pass"
        actual = f"acr matches: {sorted(acr_match)}; amr matches: {sorted(amr_match)}"
    else:
        status = "fail"
        actual = (
            f"acr_values_supported={list(d.acr_values_supported)}, amr_values_supported={list(d.amr_values_supported)}"
        )
    return FAPICheckResult(
        check_id="FAPI-10",
        title="Phishing-resistant ACR/AMR claims declared",
        severity="HIGH",
        status=status,
        expected="acr=urn:openbanking:psd2:sca OR amr in {hwk, phr, phrh}",
        actual=actual,
        remediation="Add urn:openbanking:psd2:sca to acr_values_supported and hwk/phr/phrh to amr_values_supported.",
        rationale="PSD2 SCA + FAPI: the AS must announce the strong-authentication classes available so clients can request them.",
    )


ALL_FAPI_CHECKS = (
    _check_par,
    _check_request_object_signing,
    _check_id_token_signing,
    _check_client_auth,
    _check_sender_constrained_tokens,
    _check_pkce_s256,
    _check_no_implicit_flow,
    _check_jarm,
    _check_open_banking_scopes,
    _check_phishing_resistant_acr,
)


def validate_fapi_advanced(discovery: FAPIDiscovery) -> FAPIComplianceReport:
    """Run every FAPI 1.0 Advanced check on the discovery document.

    Compliance gate: report is `compliant=True` iff every CRITICAL +
    HIGH check is "pass". MEDIUM warnings and INFO entries don't
    block compliance — operator decides based on the bank's profile.
    """
    results = tuple(check(discovery) for check in ALL_FAPI_CHECKS)
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    compliant = all(r.status == "pass" for r in results if r.severity in ("CRITICAL", "HIGH"))
    return FAPIComplianceReport(
        issuer=discovery.issuer,
        profile="fapi_1_advanced",
        results=results,
        compliant=compliant,
        summary=counts,
    )


# ---------------------------------------------------------------------------
# Live discovery fetch (gated)
# ---------------------------------------------------------------------------


def _fire_enabled(fire: bool) -> bool:
    if not fire:
        return False
    return os.environ.get("KRYON_FAPI_FIRE", "").strip().lower() in ("1", "true", "yes")


def _well_known_url(issuer: str) -> str:
    """Spec: append `/.well-known/openid-configuration` to the issuer.
    Some banks publish OAuth-only metadata at
    `/.well-known/oauth-authorization-server` — caller can pass that
    directly as a full URL if needed."""
    if issuer.endswith("/.well-known/openid-configuration") or issuer.endswith(
        "/.well-known/oauth-authorization-server"
    ):
        return issuer
    return issuer.rstrip("/") + "/.well-known/openid-configuration"


def fetch_discovery_document(
    issuer_url: str,
    *,
    fire: bool = False,
    timeout: int = 20,
    cap_bytes: int = DISCOVERY_RESPONSE_CAP_BYTES,
) -> dict[str, Any] | None:
    """Pull the OpenID Connect Discovery document for an issuer.

    DRY-RUN by default — returns None without network traffic. Live
    fetch requires KRYON_FAPI_FIRE=true env AND fire=True arg.

    Returns the parsed JSON dict on success, None on dry-run, raises
    on parse errors. HTTP errors come back as None with a debug log.
    """
    if not _fire_enabled(fire):
        return None

    url = _well_known_url(issuer_url)
    req = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(cap_bytes)
    except (HTTPError, URLError, TimeoutError, OSError) as e:
        logger.debug("FAPI discovery fetch failed for %s: %s", url, e)
        return None
    except Exception as e:  # noqa: BLE001
        logger.debug("FAPI discovery unexpected error: %s", e)
        return None

    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None
