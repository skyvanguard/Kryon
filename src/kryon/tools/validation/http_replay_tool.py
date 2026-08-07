"""Fase 2 — agent-facing wrappers for the deterministic replay validators.

Thin ``@function_tool`` shells over the pure ``http_replay`` core. They exist so
the LLM can confirm an XSS / SSRF / IDOR finding with a single crafted GET
instead of shelling out to dalfox/commix. Same double-gate as the core
(KRYON_REPLAY_FIRE env + fire=True); default dry-run sends no traffic.
"""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.validation.http_replay import (
    ReplayResult,
    replay_idor as _replay_idor,
    replay_reflected_ssrf as _replay_ssrf,
    replay_reflected_xss as _replay_xss,
)

__all__ = ["replay_xss", "replay_ssrf", "replay_idor"]


def _to_json(r: ReplayResult) -> str:
    payload: dict[str, Any] = {
        "verdict": r.verdict,
        "cwe": r.cwe,
        "method": r.method,
        "evidence": r.evidence,
        "payload": r.payload,
    }
    return json.dumps(payload, ensure_ascii=False)


def _parse_headers(headers_json: str) -> dict[str, str] | None:
    if not headers_json.strip():
        return None
    try:
        obj = json.loads(headers_json)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    return {str(k): str(v) for k, v in obj.items()}


@function_tool(strict_mode=False)
def replay_xss(url: str, parameter: str, fire: bool = False, headers_json: str = "", timeout: int = 20) -> str:
    """Confirm reflected XSS deterministically by injecting a unique breakout
    canary and checking whether it comes back UNESCAPED (proof) or entity-encoded
    (safe). No dalfox, no browser — a single GET.

    Args:
        url: the endpoint the finding hit (query string preserved).
        parameter: the query parameter suspected of reflecting into HTML.
        fire: opt-in for live HTTP; combined with KRYON_REPLAY_FIRE env.
        headers_json: optional JSON object of extra request headers.
        timeout: per-request timeout in seconds.

    Returns:
        JSON: verdict (confirmed|not-reproduced|inconclusive|dry_run), cwe,
        method, evidence excerpt, payload.
    """
    return _to_json(_replay_xss(url, parameter, fire=fire, timeout=timeout, headers=_parse_headers(headers_json)))


@function_tool(strict_mode=False)
def replay_ssrf(
    url: str,
    parameter: str,
    marker_url: str,
    expected_token: str,
    fire: bool = False,
    headers_json: str = "",
    timeout: int = 20,
) -> str:
    """Confirm in-band SSRF by asking the server to fetch a URL you control and
    checking whether its distinctive content is echoed back.

    Args:
        url: the endpoint whose parameter takes a URL/host.
        parameter: the parameter to poison with ``marker_url``.
        marker_url: a resource whose response you know (your canary endpoint or
            an internal service such as the cloud metadata IP).
        expected_token: a string that appears ONLY if that URL was fetched.
        fire: opt-in for live HTTP; combined with KRYON_REPLAY_FIRE env.
        headers_json: optional JSON object of extra request headers.
        timeout: per-request timeout in seconds.

    Returns:
        JSON verdict. Blind SSRF (no echo) needs an OAST listener — out of scope
        here; a non-echo returns not-reproduced, not confirmed.
    """
    return _to_json(
        _replay_ssrf(
            url,
            parameter,
            marker_url,
            expected_token,
            fire=fire,
            timeout=timeout,
            headers=_parse_headers(headers_json),
        )
    )


@function_tool(strict_mode=False)
def replay_idor(
    url: str,
    id_parameter: str,
    own_id: str,
    other_id: str,
    fire: bool = False,
    session_headers_json: str = "",
    timeout: int = 20,
) -> str:
    """Confirm IDOR by requesting a neighbour's object with YOUR session and
    checking whether the server serves their data.

    Args:
        url: the object endpoint (e.g. ``https://t/api/account``).
        id_parameter: the object-id query parameter (e.g. ``id``).
        own_id: an object id you're authorized for (the control).
        other_id: a neighbour's object id (the test).
        fire: opt-in for live HTTP; combined with KRYON_REPLAY_FIRE env.
        session_headers_json: JSON object with YOUR session auth headers
            (e.g. {"Cookie": "session=..."} or {"Authorization": "Bearer ..."}).
        timeout: per-request timeout in seconds.

    Returns:
        JSON verdict. confirmed = sibling returned 200 with distinct data;
        not-reproduced = 401/403/404 or identical/empty body.
    """
    return _to_json(
        _replay_idor(
            url,
            id_parameter,
            own_id,
            other_id,
            fire=fire,
            timeout=timeout,
            session_headers=_parse_headers(session_headers_json),
        )
    )
