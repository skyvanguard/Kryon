"""F87.4 — agent-facing tool wrapper for the FAPI 1.0 Advanced validator.

Two modes:
  - `from_url`: fetches `<issuer>/.well-known/openid-configuration`
    (under the double-gate) and validates.
  - `from_json`: validates an inline / pre-fetched discovery doc
    (banca-safe air-gap path — operator pastes the doc).
"""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.fapi_validator import (
    FAPIComplianceReport,
    fetch_discovery_document,
    parse_discovery,
    validate_fapi_advanced,
)

__all__ = ["validate_fapi"]


def _report_to_dict(report: FAPIComplianceReport) -> dict[str, Any]:
    return {
        "issuer": report.issuer,
        "profile": report.profile,
        "compliant": report.compliant,
        "summary": dict(report.summary),
        "checks": [
            {
                "check_id": r.check_id,
                "title": r.title,
                "severity": r.severity,
                "status": r.status,
                "expected": r.expected,
                "actual": r.actual,
                "remediation": r.remediation,
                "rationale": r.rationale,
            }
            for r in report.results
        ],
    }


@function_tool
def validate_fapi(
    target: str,
    mode: str = "from_url",
    fire: bool = False,
) -> str:
    """Validate an OpenID Connect issuer against FAPI 1.0 Advanced.

    Args:
        target: Either:
          - mode="from_url": the issuer URL ("https://auth.bank.com")
            or full discovery URL.
          - mode="from_json": the discovery document as a JSON string.
        mode: "from_url" (default) fetches discovery over HTTP under
            the double-gate; "from_json" parses the inline body
            without any network traffic.
        fire: required for live HTTP. Ignored in from_json mode.

    Returns:
        JSON string with the FAPIComplianceReport.
    """
    if mode not in ("from_url", "from_json"):
        return json.dumps({"error": f"unknown mode {mode!r}; use from_url or from_json"})

    target = target.strip()
    if not target:
        return json.dumps({"error": "empty target"})

    if mode == "from_json":
        try:
            doc = json.loads(target)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"invalid JSON: {e}"})
        if not isinstance(doc, dict):
            return json.dumps({"error": "discovery document must be a JSON object"})
        discovery = parse_discovery(doc)
        report = validate_fapi_advanced(discovery)
        return json.dumps(_report_to_dict(report), ensure_ascii=False)

    # from_url
    doc = fetch_discovery_document(target, fire=fire)
    if doc is None:
        return json.dumps(
            {
                "error": "no discovery document fetched",
                "note": (
                    "live fetch requires KRYON_FAPI_FIRE=true env AND fire=True "
                    "arg; otherwise pass the discovery JSON with mode='from_json'"
                ),
            }
        )
    discovery = parse_discovery(doc)
    report = validate_fapi_advanced(discovery)
    return json.dumps(_report_to_dict(report), ensure_ascii=False)
