"""F87.3 — GraphQL introspection detector.

GraphQL introspection (`__schema`) is the standard way clients
discover the schema of an API. Production deployments routinely leave
it enabled — the official `apollo-server` and `graphql-yoga` defaults
keep it on, and many backends just never flip the switch. For an
attacker this is a free recon win: types, queries, mutations,
parameters, all dumped without authentication on a surprising number
of internal banking APIs (T24 Direct Banking, BCP digital channels
where the GraphQL gateway was internal-only "by network").

This module implements:

  1. `is_graphql_endpoint(url, ...)` — minimal probe. POSTs the
     trivial `{__typename}` query. A GraphQL endpoint returns either
     `{"data":{"__typename":"..."}}` or `{"errors":[...]}` — both
     positive. Anything else (HTML, 404, non-JSON body) is negative.
     One round-trip, ≤5 KB response.

  2. `probe_introspection(url, ...)` — issues the standard
     IntrospectionQuery. Returns an `IntrospectionResult` carrying
     verdict (`enabled` | `disabled` | `auth_required` | `error`)
     plus the parsed schema view when enabled.

  3. `parse_schema(response_json)` — extracts type names, field
     names, query/mutation names from the introspection payload.

  4. `classify_risk(schema)` — sensitive-naming heuristic. Names
     containing `user`, `account`, `transaction`, `password`,
     `secret`, `private*` raise the impact tier; pure CRUD on
     non-sensitive entities stays medium/low.

Banca-safety contract:
  - Only POST with a read-only query is ever sent. The
    IntrospectionQuery is by definition non-mutating.
  - Live execution requires KRYON_GRAPHQL_FIRE=true env AND fire=True
    arg — same double-gate as F87.2 BOLA. Default DRY-RUN.
  - Response body cap: 2 MB. Larger payloads truncate with a warning;
    `__schema` rarely exceeds 200 KB in practice but a misconfigured
    gateway can return runaway recursion.
  - Stdlib urllib only.
  - Mutation discovery does NOT execute mutations — we only LIST
    them from the introspection result so the auditor knows what's
    exposed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

__all__ = [
    "GraphQLEndpoint",
    "ParsedSchema",
    "IntrospectionResult",
    "RiskAssessment",
    "is_graphql_endpoint",
    "probe_introspection",
    "parse_schema",
    "classify_risk",
    "INTROSPECTION_QUERY",
    "DEFAULT_RESPONSE_CAP_BYTES",
]


DEFAULT_RESPONSE_CAP_BYTES = 2 * 1024 * 1024  # 2 MB

# Sensitive-name patterns. No \b word boundaries so camelCase tokens
# like "changePassword" or "userAccount" still match. We accept the
# tradeoff that "accountant" would also match "account" — in the
# banking domain that's not a real risk class (and a curator can
# dismiss the rare false positive). The naming heuristic deliberately
# does NOT include very short fragments like "id" or "cc" — those
# would over-match.
_SENSITIVE_HIGH = re.compile(
    r"("
    r"user|account|customer|client|"
    r"password|secret|credential|token|"
    r"creditcard|cardholder|pan|cvv|"
    r"ssn|cedula|ruc|"
    r"private"
    r")",
    re.IGNORECASE,
)
_SENSITIVE_MEDIUM = re.compile(
    r"("
    r"transaction|payment|transfer|balance|"
    r"invoice|"
    r"address|phone|email"
    r")",
    re.IGNORECASE,
)


# Standard IntrospectionQuery from the GraphQL spec, slimmed to the
# fields the auditor cares about (no `description` walks — those
# inflate the response by 5-10x for no security signal).
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        type { name kind ofType { name kind } }
        isDeprecated
      }
    }
  }
}
""".strip()


# A trivial 1-token probe — every conformant GraphQL server answers
# this whether or not introspection is enabled, because __typename
# isn't part of introspection.
_TYPENAME_PROBE = "{__typename}"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphQLEndpoint:
    """One endpoint that responded with GraphQL semantics on the
    typename probe."""

    url: str
    http_status: int
    accepts_post_json: bool
    accepts_get_query: bool = False  # GET with ?query= — also detection-positive
    body_fingerprint: str = ""
    body_sha256: str | None = None


@dataclass(frozen=True)
class ParsedSchema:
    """Compact view of an introspection response. Field/type tuples are
    deduplicated + sorted so the same schema produces the same view
    across runs."""

    query_type: str | None
    mutation_type: str | None
    subscription_type: str | None
    type_names: tuple[str, ...] = field(default_factory=tuple)
    query_fields: tuple[str, ...] = field(default_factory=tuple)
    mutation_fields: tuple[str, ...] = field(default_factory=tuple)
    subscription_fields: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RiskAssessment:
    """Sensitive-name classification on the parsed schema."""

    risk: str  # "high" | "medium" | "low" | "info"
    matched_sensitive_terms: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""


@dataclass(frozen=True)
class IntrospectionResult:
    """One probe outcome."""

    url: str
    verdict: str  # "enabled" | "disabled" | "auth_required" | "dry_run" | "error" | "not_graphql"
    http_status: int | None = None
    schema: ParsedSchema | None = None
    risk: RiskAssessment | None = None
    body_sha256: str | None = None
    error: str | None = None
    notes: str = ""


# ---------------------------------------------------------------------------
# Fire gate
# ---------------------------------------------------------------------------


def _fire_enabled(fire: bool) -> bool:
    """Live HTTP requires BOTH env and arg. Same contract as F87.2."""
    if not fire:
        return False
    env = os.environ.get("KRYON_GRAPHQL_FIRE", "").strip().lower()
    return env in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _post_graphql(
    url: str,
    query: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    cap_bytes: int = DEFAULT_RESPONSE_CAP_BYTES,
) -> tuple[int, bytes]:
    """One POST. Returns (status, body) — body capped at cap_bytes.
    Raises only on network errors; HTTP error responses come back as
    (status, body) so the caller can classify."""
    payload = json.dumps({"query": query}).encode("utf-8")
    req = Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **(headers or {}),
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(cap_bytes)
    except HTTPError as e:
        try:
            body = e.read(cap_bytes)
        except Exception:  # noqa: BLE001
            body = b""
        return e.code, body


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _looks_like_graphql_response(body: bytes) -> bool:
    """A response is GraphQL-shaped when its JSON has a top-level
    `data` OR `errors` key. We don't require both — older servers
    return only `errors` on a parse failure."""
    if not body:
        return False
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(doc, dict):
        return False
    return "data" in doc or "errors" in doc


def is_graphql_endpoint(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    fire: bool = False,
    timeout: int = 20,
) -> GraphQLEndpoint | None:
    """Probe `url` with the `__typename` query. Returns a GraphQLEndpoint
    when the response is GraphQL-shaped, None otherwise.

    DRY-RUN (default) → returns None without touching the network.
    Use fire=True + KRYON_GRAPHQL_FIRE=true env to enable.
    """
    if not _fire_enabled(fire):
        return None

    try:
        status, body = _post_graphql(url, _TYPENAME_PROBE, headers=headers, timeout=timeout)
    except (URLError, TimeoutError, OSError):
        return None
    except Exception as e:  # noqa: BLE001
        logger.debug("graphql probe network error: %s", e)
        return None

    if not _looks_like_graphql_response(body):
        return None

    fingerprint = body[:200].decode("utf-8", errors="replace")
    return GraphQLEndpoint(
        url=url,
        http_status=status,
        accepts_post_json=True,
        body_fingerprint=fingerprint,
        body_sha256=hashlib.sha256(body).hexdigest(),
    )


# ---------------------------------------------------------------------------
# Introspection probe
# ---------------------------------------------------------------------------


def _verdict_from_response(status: int, body: bytes) -> tuple[str, dict[str, Any] | None]:
    """Classify the introspection response. Returns (verdict, parsed_json).

    Verdicts:
      enabled       — body has data.__schema → introspection is on
      disabled      — body has errors mentioning introspection-related text
      auth_required — 401 / 403
      not_graphql   — non-JSON body or no data/errors key
      error         — 5xx or unparseable
    """
    if status in (401, 403):
        return "auth_required", None
    if status >= 500:
        return "error", None

    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "not_graphql", None
    if not isinstance(doc, dict):
        return "not_graphql", None

    data = doc.get("data") if isinstance(doc.get("data"), dict) else None
    if data and isinstance(data.get("__schema"), dict):
        return "enabled", doc

    errors = doc.get("errors")
    if isinstance(errors, list):
        for err in errors:
            if not isinstance(err, dict):
                continue
            msg = str(err.get("message") or "").lower()
            if "introspection" in msg or "__schema" in msg or "is not allowed" in msg:
                return "disabled", doc
        # Generic error (syntax, etc) but server is GraphQL-shaped.
        return "disabled", doc
    return "not_graphql", None


def probe_introspection(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    fire: bool = False,
    timeout: int = 30,
    cap_bytes: int = DEFAULT_RESPONSE_CAP_BYTES,
) -> IntrospectionResult:
    """Run the standard IntrospectionQuery against `url`.

    DRY-RUN (default) → returns IntrospectionResult(verdict="dry_run")
    without HTTP traffic. Operator must export
    KRYON_GRAPHQL_FIRE=true AND pass fire=True for live execution.
    """
    if not _fire_enabled(fire):
        return IntrospectionResult(
            url=url,
            verdict="dry_run",
            notes=f"would POST IntrospectionQuery to {url}",
        )

    try:
        status, body = _post_graphql(
            url,
            INTROSPECTION_QUERY,
            headers=headers,
            timeout=timeout,
            cap_bytes=cap_bytes,
        )
    except (URLError, TimeoutError, OSError) as e:
        return IntrospectionResult(
            url=url,
            verdict="error",
            error=f"{type(e).__name__}: {e}",
        )
    except Exception as e:  # noqa: BLE001
        return IntrospectionResult(
            url=url,
            verdict="error",
            error=f"{type(e).__name__}: {e}",
        )

    verdict, doc = _verdict_from_response(status, body)
    body_sha = hashlib.sha256(body).hexdigest() if body else None

    if verdict == "enabled" and doc is not None:
        schema = parse_schema(doc)
        risk = classify_risk(schema)
        return IntrospectionResult(
            url=url,
            verdict="enabled",
            http_status=status,
            schema=schema,
            risk=risk,
            body_sha256=body_sha,
        )

    return IntrospectionResult(
        url=url,
        verdict=verdict,
        http_status=status,
        body_sha256=body_sha,
    )


# ---------------------------------------------------------------------------
# Schema parsing
# ---------------------------------------------------------------------------


def _fields_of_root(doc: dict[str, Any], root_name: str | None) -> tuple[str, ...]:
    """Return the field names defined on a root type (Query / Mutation /
    Subscription). Empty tuple when the root isn't present."""
    if not root_name:
        return ()
    schema = doc.get("data", {}).get("__schema", {})
    types = schema.get("types") or []
    for t in types:
        if not isinstance(t, dict):
            continue
        if t.get("name") != root_name:
            continue
        fields = t.get("fields") or []
        names = [str(f["name"]) for f in fields if isinstance(f, dict) and isinstance(f.get("name"), str)]
        return tuple(sorted(set(names)))
    return ()


def parse_schema(response_json: dict[str, Any]) -> ParsedSchema:
    """Extract the compact view from a full introspection response.

    Defensive: any missing key → empty tuple / None. Even an
    obviously-broken response yields a well-formed ParsedSchema so
    downstream consumers don't crash.
    """
    # Defensive: a malformed doc may have `data` as a string, list, or
    # null. Coerce non-dict to empty dict before further descent.
    data_node = response_json.get("data")
    if not isinstance(data_node, dict):
        return ParsedSchema(query_type=None, mutation_type=None, subscription_type=None)
    schema_obj = data_node.get("__schema", {})
    if not isinstance(schema_obj, dict):
        return ParsedSchema(query_type=None, mutation_type=None, subscription_type=None)

    def _root_name(key: str) -> str | None:
        node = schema_obj.get(key)
        if isinstance(node, dict):
            n = node.get("name")
            return n if isinstance(n, str) else None
        return None

    query_root = _root_name("queryType")
    mutation_root = _root_name("mutationType")
    sub_root = _root_name("subscriptionType")

    types = schema_obj.get("types") or []
    type_names = tuple(
        sorted(
            {
                str(t["name"])
                for t in types
                if isinstance(t, dict)
                and isinstance(t.get("name"), str)
                # Skip GraphQL-internal __Type / __Field etc.
                and not t["name"].startswith("__")
            }
        )
    )

    return ParsedSchema(
        query_type=query_root,
        mutation_type=mutation_root,
        subscription_type=sub_root,
        type_names=type_names,
        query_fields=_fields_of_root(response_json, query_root),
        mutation_fields=_fields_of_root(response_json, mutation_root),
        subscription_fields=_fields_of_root(response_json, sub_root),
    )


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------


def classify_risk(schema: ParsedSchema) -> RiskAssessment:
    """Sensitive-naming heuristic over the parsed schema.

    Tier:
      high   — at least one HIGH match (user/account/password/cvv/...)
      medium — at least one MEDIUM match (transaction/balance/address/...)
      low    — neither, but schema is non-empty (worth flagging that
               introspection is open even if surface looks innocuous)
      info   — empty schema (server returned __schema but no types?
               typically a stub gateway)

    The set of matched sensitive terms is surfaced so the auditor
    sees which names triggered the tier — not just "high".
    """
    targets = list(schema.type_names) + list(schema.query_fields) + list(schema.mutation_fields)
    if not targets:
        return RiskAssessment(risk="info", reason="introspection enabled but schema empty")

    matched_high = sorted({m.group(0).lower() for tgt in targets for m in [_SENSITIVE_HIGH.search(tgt)] if m})
    matched_medium = sorted({m.group(0).lower() for tgt in targets for m in [_SENSITIVE_MEDIUM.search(tgt)] if m})

    if matched_high:
        return RiskAssessment(
            risk="high",
            matched_sensitive_terms=tuple(matched_high),
            reason="introspection exposes high-sensitivity entity names",
        )
    if matched_medium:
        return RiskAssessment(
            risk="medium",
            matched_sensitive_terms=tuple(matched_medium),
            reason="introspection exposes medium-sensitivity entity names",
        )
    return RiskAssessment(
        risk="low",
        reason="introspection enabled but no sensitive entity names detected",
    )
