"""F87.5 — agent-facing tool wrapper for the JWT validator."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.jwt_validator import (
    JWTAnalysis,
    analyze_jwt,
)

__all__ = ["validate_jwt"]


def _analysis_to_dict(analysis: JWTAnalysis) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in analysis.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "parsed": analysis.parsed,
        "alg_observed": analysis.alg_observed,
        "claims_present": list(analysis.claims_present),
        "finding_count": len(analysis.findings),
        "by_severity": by_severity,
        "findings": [
            {
                "id": f.finding_id,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "remediation": f.remediation,
            }
            for f in analysis.findings
        ],
    }


@function_tool
def validate_jwt(
    token: str,
    expected_audience: str = "",
    expected_issuer: str = "",
    expected_alg: str = "",
    allow_hmac_with_pubkey: bool = False,
    trusted_jku_hosts_csv: str = "",
    leeway_seconds: int = 60,
) -> str:
    """Static JWT analysis.

    Args:
        token: the JWT to analyze (header.payload.signature).
        expected_audience: pin the verifier's identifier; analyzer
            fires JWT-021 when the token's aud doesn't include it.
        expected_issuer: trusted issuer; mismatch → JWT-023.
        expected_alg: pin the algorithm; mismatch → JWT-005.
        allow_hmac_with_pubkey: set True when the operator's verifier
            already has the issuer's public key — turns HS* tokens
            into the JWT-004 key-confusion finding.
        trusted_jku_hosts_csv: comma-separated whitelist for jku/x5u
            hosts. Empty = warn on any jku/x5u presence.
        leeway_seconds: clock-skew tolerance for exp/iat/nbf.

    Returns:
        JSON string with the analysis. Always includes a `findings`
        list (possibly empty); when the JWT failed to parse,
        `parsed: false` plus a single JWT-000 finding.
    """
    if not token.strip():
        return json.dumps({"error": "empty token"})

    trusted_hosts = tuple(h.strip().lower() for h in trusted_jku_hosts_csv.split(",") if h.strip())

    analysis = analyze_jwt(
        token,
        expected_audience=expected_audience or None,
        expected_issuer=expected_issuer or None,
        expected_alg=expected_alg or None,
        allow_hmac_with_pubkey=allow_hmac_with_pubkey,
        trusted_jku_hosts=trusted_hosts,
        leeway_seconds=leeway_seconds,
    )
    return json.dumps(_analysis_to_dict(analysis), ensure_ascii=False)
