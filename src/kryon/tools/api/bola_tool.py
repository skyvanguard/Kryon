"""F87.2 — agent-facing tool wrapper for the BOLA detector.

Composes parse_openapi → plan_probes → execute_probe across an
operator-provided ID pair set, with per-endpoint cap + rate limiting.

The tool returns a JSON string with the BOLASummary and the per-probe
findings so the agent can reason about the result and the curator can
audit deterministically.

Default mode is DRY-RUN. The agent's playbook (F87 surface) must
explicitly set fire=True AND the operator must export
KRYON_BOLA_FIRE=true before any HTTP traffic flows.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.bola_detector import (
    DEFAULT_MAX_IDS_PER_ENDPOINT,
    DEFAULT_RATE_LIMIT_PER_SECOND,
    BOLAFinding,
    _TokenBucket,
    correlate_findings,
    execute_probe,
    plan_probes,
)
from kryon.tools.api.openapi_importer import InvalidOpenAPIError, parse_openapi

logger = logging.getLogger(__name__)


def _summarize(findings: list[BOLAFinding]) -> dict[str, Any]:
    summary = correlate_findings(findings)
    return {
        "summary": {
            "total_probes": summary.total_probes,
            "by_verdict": summary.by_verdict,
            "by_risk": summary.by_risk,
            "confirmed_leak_count": len(summary.confirmed_leaks),
        },
        "findings": [
            {
                "endpoint": f.candidate.endpoint_path,
                "method": f.candidate.method.upper(),
                "path_parameter": f.candidate.path_parameter,
                "risk": f.candidate.risk,
                "id_tested": f.id_tested,
                "verdict": f.verdict,
                "http_status": f.http_status,
                "body_fingerprint": f.body_fingerprint,
                "body_sha256": f.body_sha256,
                "error": f.error,
                "notes": f.notes,
            }
            for f in findings
        ],
    }


@function_tool
def detect_bola(
    spec_source: str,
    base_url: str,
    token: str,
    foreign_ids_csv: str,
    fire: bool = False,
    max_ids_per_endpoint: int = DEFAULT_MAX_IDS_PER_ENDPOINT,
    rate_limit_per_second: int = DEFAULT_RATE_LIMIT_PER_SECOND,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer ",
) -> str:
    """Plan + (optionally) execute BOLA probes for an OpenAPI spec.

    Args:
        spec_source: URL / path / inline text of an OpenAPI spec —
            same shape `import_openapi_spec` accepts.
        base_url: API base. The spec's `servers` are not used in v1
            because operators frequently override (staging vs prod).
        token: Bearer / api-key token. Used as token A (the
            "authenticated user" whose owned ids we DON'T have a
            handle on; the foreign_ids are what we probe with).
        foreign_ids_csv: comma-separated list of IDs the token does
            NOT own. The probe asks: can token A read these?
        fire: when True AND KRYON_BOLA_FIRE=true env is set, issues
            live GET requests. Default False (dry-run plan only).
        max_ids_per_endpoint: cap on probes per endpoint. Hard-capped
            at 50 server-side regardless of caller.
        rate_limit_per_second: target traffic rate. Coarse — sleeps
            between probes to stay below the limit.
        auth_header / auth_prefix: customize for APIs that use
            "X-API-Key" + "" instead of "Authorization" + "Bearer ".

    Returns:
        JSON string with the BOLASummary + per-probe findings.
    """
    try:
        spec = parse_openapi(spec_source)
    except InvalidOpenAPIError as e:
        return json.dumps({"error": f"invalid OpenAPI spec: {e}"})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"{type(e).__name__}: {e}"})

    candidates = plan_probes(spec, max_ids_per_endpoint=max_ids_per_endpoint)
    if not candidates:
        return json.dumps(
            {
                "summary": {"total_probes": 0, "by_verdict": {}, "by_risk": {}, "confirmed_leak_count": 0},
                "findings": [],
                "note": "no object-leveled GET endpoints found",
            }
        )

    # Dedup: a repeated id would fire the same live BOLA probe twice (wasted
    # budget, skewed counts) under fire mode.
    ids = list(dict.fromkeys(s.strip() for s in foreign_ids_csv.split(",") if s.strip()))
    if not ids:
        return json.dumps({"error": "no foreign_ids supplied"})
    ids = ids[:max_ids_per_endpoint]

    bucket = _TokenBucket(rate_limit_per_second)
    findings: list[BOLAFinding] = []
    for candidate in candidates:
        for id_value in ids:
            bucket.wait()
            findings.append(
                execute_probe(
                    candidate,
                    base_url=base_url,
                    token=token,
                    id_to_test=id_value,
                    auth_header=auth_header,
                    auth_prefix=auth_prefix,
                    fire=fire,
                )
            )

    return json.dumps(_summarize(findings), ensure_ascii=False)
