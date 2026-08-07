"""F114 — agent-facing tool wrappers."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.active_probes.open_redirect_active import (
    ActiveProbeAttempt,
    OpenRedirectActiveConfig,
    probe_open_redirect_active,
)
from kryon.tools.active_probes.ssrf_active import (
    SsrfActiveConfig,
    SsrfProbeAttempt,
    probe_ssrf_active,
)

__all__ = ["probe_open_redirect", "probe_ssrf"]


def _attempt_to_dict(a: ActiveProbeAttempt) -> dict[str, Any]:
    return {
        "payload": a.payload,
        "request_url": a.request_url,
        "http_status": a.http_status,
        "response_location": a.response_location,
        "response_body_snippet": a.response_body_snippet[:200],
        "elapsed_seconds": round(a.elapsed_seconds, 3),
        "error": a.error,
    }


def _ssrf_attempt_to_dict(a: SsrfProbeAttempt) -> dict[str, Any]:
    return {
        "payload": a.payload,
        "request_url": a.request_url,
        "http_status": a.http_status,
        "response_body_snippet": a.response_body_snippet[:200],
        "elapsed_seconds": round(a.elapsed_seconds, 3),
        "detected_signature": a.detected_signature,
        "error": a.error,
    }


@function_tool
def probe_open_redirect(config_json: str) -> str:
    """Active probe for open redirect.

    DOUBLE-GATED — sends live HTTP only when:
      1. `fire: true` in config_json
      2. KRYON_OPENREDIRECT_FIRE=true env var set
    Without both, returns the constructed payloads (dry-run) without
    sending traffic.

    Args:
        config_json: {
          endpoint_url: required, the URL with the param to test,
          parameter_name: required, e.g. "next"/"redirect_uri"/...,
          canary_host: default "kryon-canary.invalid",
          fire: default false,
          timeout_seconds, rate_limit_per_second, follow_redirects,
          extra_headers, extra_cookies
        }
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})

    endpoint_url = doc.get("endpoint_url")
    parameter_name = doc.get("parameter_name")
    if not endpoint_url or not parameter_name:
        return json.dumps({"error": "endpoint_url + parameter_name are required"})

    cfg = OpenRedirectActiveConfig(
        endpoint_url=str(endpoint_url),
        parameter_name=str(parameter_name),
        canary_host=str(doc.get("canary_host") or "kryon-canary.invalid"),
        fire=bool(doc.get("fire", False)),
        timeout_seconds=float(doc.get("timeout_seconds") or 5.0),
        rate_limit_per_second=float(doc.get("rate_limit_per_second") or 5.0),
        follow_redirects=bool(doc.get("follow_redirects", False)),
        extra_headers=tuple(
            (str(h.get("name") or ""), str(h.get("value") or ""))
            for h in (doc.get("extra_headers") or [])
            if isinstance(h, dict) and h.get("name")
        ),
        extra_cookies=tuple(
            (str(c.get("name") or ""), str(c.get("value") or ""))
            for c in (doc.get("extra_cookies") or [])
            if isinstance(c, dict) and c.get("name")
        ),
    )
    result = probe_open_redirect_active(cfg)
    return json.dumps(
        {
            "fired": result.fired,
            "fire_gate_state": result.fire_gate_state,
            "elapsed_seconds": round(result.elapsed_seconds, 3),
            "payloads_built": list(result.payloads_built),
            "attempt_count": len(result.attempts),
            "finding_count": len(result.findings),
            "attempts": [_attempt_to_dict(a) for a in result.attempts],
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "remediation": f.remediation,
                    "url": f.url,
                    "parameter_name": f.parameter_name,
                }
                for f in result.findings
            ],
        },
        ensure_ascii=False,
    )


@function_tool
def probe_ssrf(config_json: str) -> str:
    """Active (semi-blind) probe for SSRF.

    DOUBLE-GATED — sends live HTTP only when:
      1. `fire: true` in config_json
      2. KRYON_SSRF_FIRE=true env var set
    Without both, returns the constructed payloads (dry-run).

    Args:
        config_json: {
          endpoint_url: required,
          parameter_name: required,
          canary_url: optional operator-supplied OOB callback,
          fire: default false,
          ...
        }
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})

    endpoint_url = doc.get("endpoint_url")
    parameter_name = doc.get("parameter_name")
    if not endpoint_url or not parameter_name:
        return json.dumps({"error": "endpoint_url + parameter_name are required"})

    cfg = SsrfActiveConfig(
        endpoint_url=str(endpoint_url),
        parameter_name=str(parameter_name),
        canary_url=str(doc.get("canary_url") or ""),
        fire=bool(doc.get("fire", False)),
        timeout_seconds=float(doc.get("timeout_seconds") or 5.0),
        rate_limit_per_second=float(doc.get("rate_limit_per_second") or 3.0),
        extra_headers=tuple(
            (str(h.get("name") or ""), str(h.get("value") or ""))
            for h in (doc.get("extra_headers") or [])
            if isinstance(h, dict) and h.get("name")
        ),
        extra_cookies=tuple(
            (str(c.get("name") or ""), str(c.get("value") or ""))
            for c in (doc.get("extra_cookies") or [])
            if isinstance(c, dict) and c.get("name")
        ),
    )
    result = probe_ssrf_active(cfg)
    return json.dumps(
        {
            "fired": result.fired,
            "fire_gate_state": result.fire_gate_state,
            "canary_url_supplied": result.canary_url_supplied,
            "elapsed_seconds": round(result.elapsed_seconds, 3),
            "payloads_built": list(result.payloads_built),
            "attempt_count": len(result.attempts),
            "finding_count": len(result.findings),
            "attempts": [_ssrf_attempt_to_dict(a) for a in result.attempts],
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "remediation": f.remediation,
                    "location": f.location,
                }
                for f in result.findings
            ],
        },
        ensure_ascii=False,
    )
