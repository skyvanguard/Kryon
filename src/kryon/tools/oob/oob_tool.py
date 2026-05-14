"""F115 — agent-facing tool wrappers for OOB."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.oob.interactsh import (
    InteractshConfig,
    is_interactsh_available,
    run_interactsh_batch,
)
from kryon.tools.oob.payloads import (
    OOB_PAYLOAD_KINDS,
    OobPayload,
    generate_oob_payloads,
)

__all__ = [
    "list_oob_payload_kinds",
    "generate_oob_probe_payloads",
    "interactsh_check_available",
    "interactsh_batch_session",
]


def _payload_to_dict(p: OobPayload) -> dict[str, Any]:
    return {
        "kind": p.kind,
        "correlation_id": p.correlation_id,
        "payload": p.payload,
        "callback_subdomain": p.callback_subdomain,
    }


@function_tool
def list_oob_payload_kinds() -> str:
    """List every OOB payload kind the generator can produce."""
    return json.dumps({"kinds": list(OOB_PAYLOAD_KINDS)})


@function_tool
def generate_oob_probe_payloads(config_json: str) -> str:
    """Generate OOB probe payloads for a callback domain.

    Args:
        config_json: {
          callback_domain (required): e.g. "abc123.my-interactsh.lab",
          kinds (optional list of strings): defaults to ALL kinds,
          correlation_id_prefix (optional, default "k")
        }

    Returns:
        JSON list of payloads. Each has a unique correlation_id
        embedded in the callback subdomain so observed callbacks can
        be mapped back to the triggering payload.
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})
    domain = doc.get("callback_domain")
    if not domain:
        return json.dumps({"error": "callback_domain is required"})
    kinds = doc.get("kinds")
    if isinstance(kinds, list) and kinds:
        kinds_tuple = tuple(str(k) for k in kinds)
    else:
        kinds_tuple = OOB_PAYLOAD_KINDS
    prefix = str(doc.get("correlation_id_prefix") or "k")
    payloads = generate_oob_payloads(callback_domain=str(domain), kinds=kinds_tuple, correlation_id_prefix=prefix)
    return json.dumps(
        {
            "callback_domain": str(domain),
            "payload_count": len(payloads),
            "payloads": [_payload_to_dict(p) for p in payloads],
        },
        ensure_ascii=False,
    )


@function_tool
def interactsh_check_available() -> str:
    """Return whether `interactsh-client` is installed on PATH."""
    return json.dumps({"available": is_interactsh_available()})


@function_tool
def interactsh_batch_session(config_json: str) -> str:
    """Start a batch interactsh session: wait for the assigned
    domain, sleep `collect_seconds` while probes fire externally,
    return all observed interactions.

    BANCA-SAFETY: refuses public oast.* servers unless
    `allow_public_server=true` is explicitly set.

    Args:
        config_json: {
          server_url (required for banca): self-hosted interactsh URL,
          allow_public_server (default false),
          collect_seconds (default 30),
          startup_timeout_seconds (default 10),
          auth_token (optional)
        }

    Returns:
        JSON with the assigned callback_domain + list of interactions
        that arrived during the collection window. `binary_missing`
        / `public_server_blocked` flags signal failure modes.
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})

    cfg = InteractshConfig(
        interactsh_binary=str(doc.get("interactsh_binary") or "interactsh-client"),
        server_url=str(doc.get("server_url") or ""),
        allow_public_server=bool(doc.get("allow_public_server", False)),
        collect_seconds=int(doc.get("collect_seconds") or 30),
        startup_timeout_seconds=float(doc.get("startup_timeout_seconds") or 10.0),
        auth_token=str(doc.get("auth_token") or ""),
        extra_args=tuple(str(a) for a in (doc.get("extra_args") or ())),
    )
    result = run_interactsh_batch(cfg)
    return json.dumps(
        {
            "callback_domain": result.callback_domain,
            "binary_missing": result.binary_missing,
            "public_server_blocked": result.public_server_blocked,
            "elapsed_seconds": round(result.elapsed_seconds, 3),
            "exit_code": result.exit_code,
            "error": result.error,
            "interaction_count": len(result.interactions),
            "interactions": [
                {
                    "unique_id": i.unique_id,
                    "protocol": i.protocol,
                    "remote_address": i.remote_address,
                    "timestamp": i.timestamp,
                }
                for i in result.interactions
            ],
        },
        ensure_ascii=False,
    )
