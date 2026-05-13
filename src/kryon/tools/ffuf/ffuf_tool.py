"""F112 — agent-facing tool wrapper for ffuf."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.ffuf.runner import (
    FfufConfig,
    FfufHit,
    FfufResult,
    is_ffuf_available,
    run_ffuf,
)

__all__ = ["ffuf_scan", "ffuf_check_available"]


def _hit_to_dict(h: FfufHit) -> dict[str, Any]:
    return {
        "url": h.url,
        "input": h.input,
        "http_status": h.http_status,
        "content_length": h.content_length,
        "content_words": h.content_words,
        "content_lines": h.content_lines,
        "content_type": h.content_type,
        "response_time_ms": h.response_time_ms,
    }


def _result_to_dict(r: FfufResult) -> dict[str, Any]:
    return {
        "elapsed_seconds": round(r.elapsed_seconds, 3),
        "ffuf_missing": r.ffuf_missing,
        "exit_code": r.exit_code,
        "hit_count": len(r.hits),
        "hits": [_hit_to_dict(h) for h in r.hits],
        "stderr_excerpt": r.stderr_excerpt,
        "command": r.command,
        "wordlist_used": r.wordlist_used,
    }


@function_tool
def ffuf_check_available() -> str:
    """Return whether ffuf is installed on PATH."""
    return json.dumps({"available": is_ffuf_available()})


@function_tool
def ffuf_scan(config_json: str) -> str:
    """Run an ffuf content-discovery scan with banca-safe defaults.

    Args:
        config_json: JSON object with:
          - base_url (required): URL with FUZZ placeholder
          - wordlist_path (optional): defaults to embedded 200-entry list
          - threads, rate_limit_per_second, timeout_seconds
          - methods, match_status, filter_status, filter_size
          - cookies, headers (for authenticated scans)
          - follow_redirects (default false)

    Returns:
        JSON summary with hit list. `ffuf_missing: true` if binary absent.
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})
    base_url = doc.get("base_url")
    if not base_url:
        return json.dumps({"error": "base_url is required (must contain FUZZ)"})

    cookies = tuple(
        (str(c.get("name") or ""), str(c.get("value") or ""))
        for c in (doc.get("cookies") or [])
        if isinstance(c, dict) and c.get("name")
    )
    headers = tuple(
        (str(h.get("name") or ""), str(h.get("value") or ""))
        for h in (doc.get("headers") or [])
        if isinstance(h, dict) and h.get("name")
    )

    cfg = FfufConfig(
        base_url=str(base_url),
        wordlist_path=str(doc.get("wordlist_path") or ""),
        ffuf_binary=str(doc.get("ffuf_binary") or "ffuf"),
        threads=int(doc.get("threads") or 10),
        rate_limit_per_second=int(doc.get("rate_limit_per_second") or 10),
        timeout_seconds=int(doc.get("timeout_seconds") or 8),
        overall_timeout_seconds=int(doc.get("overall_timeout_seconds") or 180),
        methods=tuple(str(m) for m in (doc.get("methods") or ["GET"])),
        match_status=tuple(int(s) for s in (doc.get("match_status") or (200, 204, 301, 302, 401, 403))),
        filter_status=tuple(int(s) for s in (doc.get("filter_status") or (404,))),
        filter_size=tuple(int(s) for s in (doc.get("filter_size") or ())),
        follow_redirects=bool(doc.get("follow_redirects", False)),
        user_agent=str(doc.get("user_agent") or "Kryon-Ffuf/1.0 (banca-safe)"),
        cookies=cookies,
        headers=headers,
        extra_args=tuple(str(a) for a in (doc.get("extra_args") or ())),
    )
    result = run_ffuf(cfg)
    return json.dumps(_result_to_dict(result), ensure_ascii=False)
