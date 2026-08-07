"""F95 — agent-facing tool wrapper for the webhook validator.

The wrapper accepts headers + body as JSON / b64 string inputs (since
@function_tool args don't carry binary cleanly), runs the analyzer,
and returns a JSON summary. The secret / public_key inputs are
deliberately separate kwargs so they remain inspectable in the agent
prompt — never echoed back in the output.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.webhook_validator import (
    DEFAULT_MAX_SKEW_SECONDS,
    WebhookAnalysis,
    WebhookFinding,
    WebhookRequest,
    analyze_webhook,
)

__all__ = ["validate_webhook"]


def _finding_to_dict(f: WebhookFinding) -> dict[str, Any]:
    return {
        "id": f.finding_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
    }


def _analysis_to_dict(analysis: WebhookAnalysis) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in analysis.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "scheme_detected": analysis.scheme_detected,
        "signature_present": analysis.signature_present,
        "timestamp_present": analysis.timestamp_present,
        "timestamp_value": analysis.timestamp_value,
        "nonce_present": analysis.nonce_present,
        "verified": analysis.verified,
        "finding_count": len(analysis.findings),
        "by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in analysis.findings],
    }


@function_tool
def validate_webhook(
    headers_json: str,
    body_b64: str = "",
    method: str = "POST",
    url: str = "",
    expected_scheme: str = "",
    secret_b64: str = "",
    public_key_b64: str = "",
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
) -> str:
    """Analyze a webhook request for signature-scheme + replay-
    protection weaknesses, optionally verifying the signature.

    Args:
        headers_json: JSON object of HTTP headers (`{"Stripe-Signature":
            "t=...,v1=...", ...}`).
        body_b64: base64-encoded raw request body. Empty when
            analyzing headers only.
        method, url: optional request metadata.
        expected_scheme: when set, fires WHK-011 on scheme mismatch.
        secret_b64: base64-encoded HMAC secret. When provided, the
            analyzer attempts cryptographic verification.
        public_key_b64: base64-encoded Ed25519 public key (32 bytes
            raw). For discord_ed25519 scheme verification.
        max_skew_seconds: replay window in seconds. Default 300.

    Returns:
        JSON summary including scheme detected, replay-protection
        flags, findings list, and `verified` (when verification was
        attempted). The raw secret/public_key are NEVER echoed.
    """
    try:
        headers = json.loads(headers_json) if headers_json else {}
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid headers JSON: {e}"})
    if not isinstance(headers, dict):
        return json.dumps({"error": "headers must be a JSON object"})

    body: bytes = b""
    if body_b64:
        try:
            body = base64.b64decode(body_b64)
        except Exception as e:  # noqa: BLE001
            return json.dumps({"error": f"invalid body base64: {e}"})

    secret: bytes | None = None
    if secret_b64:
        try:
            secret = base64.b64decode(secret_b64)
        except Exception as e:  # noqa: BLE001
            return json.dumps({"error": f"invalid secret base64: {e}"})

    public_key: bytes | None = None
    if public_key_b64:
        try:
            public_key = base64.b64decode(public_key_b64)
        except Exception as e:  # noqa: BLE001
            return json.dumps({"error": f"invalid public_key base64: {e}"})

    request = WebhookRequest(
        method=method,
        url=url,
        headers={str(k): str(v) for k, v in headers.items()},
        body=body,
    )

    analysis = analyze_webhook(
        request,
        expected_scheme=expected_scheme or None,
        secret=secret,
        public_key=public_key,
        max_skew_seconds=max_skew_seconds,
    )
    return json.dumps(_analysis_to_dict(analysis), ensure_ascii=False)
