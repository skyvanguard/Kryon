"""F87.3 — agent-facing tool wrapper for GraphQL introspection recon.

Composes the detector + introspection probe into a single JSON-returning
callable the agent can use. Two operation modes:

  * Detection only: call with `mode="detect"`. Runs the typename
    probe across one or more candidate URLs and returns which ones
    look like GraphQL endpoints. Useful when the operator just wants
    to fingerprint a target before deciding whether to escalate.

  * Full recon: `mode="introspect"`. For each detected endpoint,
    issues the IntrospectionQuery and surfaces the parsed schema +
    risk tier. This is the typical engagement flow.

Both modes obey the F87.3 banca-safety contract (env + arg gates,
read-only queries, 2 MB cap).
"""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.graphql_recon import (
    IntrospectionResult,
    is_graphql_endpoint,
    probe_introspection,
)

__all__ = ["graphql_recon"]


_DEFAULT_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/api/v1/graphql")


def _candidate_urls(target: str) -> list[str]:
    """Build candidate URLs to probe. When `target` already includes
    a path, return it verbatim. Otherwise enumerate the common
    GraphQL paths."""
    target = target.rstrip("/")
    # Naive path detection: anything past the host is treated as a
    # complete URL.
    if "://" in target:
        host_and_path = target.split("://", 1)[1]
        if "/" in host_and_path:
            return [target]
        return [target + p for p in _DEFAULT_PATHS]
    return [target + p for p in _DEFAULT_PATHS]


def _result_to_dict(result: IntrospectionResult) -> dict[str, Any]:
    schema = (
        {
            "query_type": result.schema.query_type,
            "mutation_type": result.schema.mutation_type,
            "subscription_type": result.schema.subscription_type,
            "type_count": len(result.schema.type_names),
            "query_count": len(result.schema.query_fields),
            "mutation_count": len(result.schema.mutation_fields),
            "subscription_count": len(result.schema.subscription_fields),
            # Cap the surfaced names so a 1000-type schema doesn't
            # blow up the agent's context window. Operator who needs
            # the full list reads body_sha256 + inspects manually.
            "type_names": list(result.schema.type_names)[:50],
            "query_fields": list(result.schema.query_fields)[:50],
            "mutation_fields": list(result.schema.mutation_fields)[:50],
        }
        if result.schema is not None
        else None
    )
    risk = (
        {
            "risk": result.risk.risk,
            "matched_sensitive_terms": list(result.risk.matched_sensitive_terms),
            "reason": result.risk.reason,
        }
        if result.risk is not None
        else None
    )
    return {
        "url": result.url,
        "verdict": result.verdict,
        "http_status": result.http_status,
        "schema": schema,
        "risk": risk,
        "body_sha256": result.body_sha256,
        "error": result.error,
        "notes": result.notes,
    }


@function_tool
def graphql_recon(
    target: str,
    mode: str = "introspect",
    fire: bool = False,
    bearer_token: str = "",
    timeout: int = 30,
) -> str:
    """Detect GraphQL endpoints and (optionally) dump their schema via
    introspection.

    Args:
        target: Either a fully-qualified URL ("https://api.example.com
            /graphql") or a base ("https://api.example.com" — common
            paths /graphql, /api/graphql, /v1/graphql, /api/v1/graphql
            are tried).
        mode: "detect" runs only the typename probe per candidate URL.
            "introspect" runs the IntrospectionQuery and surfaces the
            parsed schema + risk tier (default).
        fire: when True AND KRYON_GRAPHQL_FIRE=true env is set, issues
            live HTTP. Default False (dry-run).
        bearer_token: optional Authorization header value (without the
            "Bearer " prefix). Useful when introspection is gated
            behind auth but the operator has a token.
        timeout: per-request timeout in seconds.

    Returns:
        JSON string with one entry per probed URL.
    """
    if not target.strip():
        return json.dumps({"error": "empty target"})
    if mode not in ("detect", "introspect"):
        return json.dumps({"error": f"unknown mode {mode!r}; use 'detect' or 'introspect'"})

    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else None
    urls = _candidate_urls(target.strip())

    if mode == "detect":
        results: list[dict[str, Any]] = []
        for url in urls:
            endpoint = is_graphql_endpoint(url, headers=headers, fire=fire, timeout=timeout)
            results.append(
                {
                    "url": url,
                    "is_graphql": endpoint is not None,
                    "http_status": endpoint.http_status if endpoint else None,
                    "body_fingerprint": endpoint.body_fingerprint if endpoint else "",
                }
            )
        return json.dumps({"mode": "detect", "results": results}, ensure_ascii=False)

    # introspect
    out: list[dict[str, Any]] = []
    for url in urls:
        result = probe_introspection(url, headers=headers, fire=fire, timeout=timeout)
        out.append(_result_to_dict(result))
    return json.dumps({"mode": "introspect", "results": out}, ensure_ascii=False)
