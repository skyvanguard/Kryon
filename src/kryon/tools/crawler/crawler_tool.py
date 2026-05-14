"""F108 — agent-facing tool wrapper for the crawler."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.crawler.crawler import (
    Crawler,
    CrawlerConfig,
    CrawlResult,
)

__all__ = ["crawl_target"]


def _result_to_dict(r: CrawlResult) -> dict[str, Any]:
    return {
        "pages": [
            {
                "url": p.url,
                "http_status": p.http_status,
                "content_type": p.content_type,
                "depth": p.depth,
                "body_length": p.body_length,
                # body_snippet intentionally excluded by default to keep
                # the JSON small. Operator can re-fetch if needed.
            }
            for p in r.pages
        ],
        "endpoints": [
            {
                "url": e.url,
                "source": e.source,
                "source_page": e.source_page,
                "method": e.method,
                "parameters": list(e.parameters),
            }
            for e in r.endpoints
        ],
        "forms": [
            {
                "action": f.action,
                "method": f.method,
                "fields": [{"name": n, "type": t} for n, t in f.fields],
                "source_page": f.source_page,
            }
            for f in r.forms
        ],
        "script_urls": list(r.script_urls),
        "meta_tags": [
            {
                "page_url": page_url,
                "metas": {k: v for k, v in pairs},
            }
            for page_url, pairs in r.meta_tags
        ],
        "errors": [{"url": e.url, "reason": e.reason, "detail": e.detail} for e in r.errors],
        "stats": {
            "pages_count": len(r.pages),
            "endpoint_count": len(r.endpoints),
            "form_count": len(r.forms),
            "script_count": len(r.script_urls),
            "error_count": len(r.errors),
            "elapsed_seconds": round(r.elapsed_seconds, 3),
        },
    }


@function_tool
def crawl_target(config_json: str) -> str:
    """Crawl a target same-origin, extract endpoints + forms + JS URLs.

    Banca-safe: GET/HEAD only, internal-IP blocked by default,
    rate-limited (default 5 req/s), bounded (default 200 pages /
    depth 5).

    Args:
        config_json: JSON object with at minimum `seeds: [str]`.
            Optional fields:
              user_agent, max_pages, max_depth, max_concurrency,
              max_body_bytes, per_request_timeout_seconds,
              rate_limit_per_second, respect_robots, same_origin_only,
              allowed_extra_hosts, block_internal_ips,
              fetch_external_js,
              auth_cookies: [{"name": ..., "value": ...}],
              auth_headers: [{"name": ..., "value": ...}]

    Returns:
        JSON summary with discovered pages / endpoints / forms /
        scripts / errors.
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})

    seeds = doc.get("seeds")
    if not seeds or not isinstance(seeds, list):
        return json.dumps({"error": "seeds: list[str] is required"})

    # Convert optional auth lists.
    auth_cookies = tuple(
        (str(c.get("name") or ""), str(c.get("value") or ""))
        for c in (doc.get("auth_cookies") or [])
        if isinstance(c, dict)
    )
    auth_headers = tuple(
        (str(h.get("name") or ""), str(h.get("value") or ""))
        for h in (doc.get("auth_headers") or [])
        if isinstance(h, dict)
    )
    allowed_extra_hosts = tuple(str(x) for x in (doc.get("allowed_extra_hosts") or []))

    try:
        cfg = CrawlerConfig(
            seeds=tuple(str(s) for s in seeds),
            user_agent=str(doc.get("user_agent") or "Kryon-Crawler/1.0 (banca-safe; +read-only)"),
            max_pages=int(doc.get("max_pages") or 200),
            max_depth=int(doc.get("max_depth") or 5),
            max_concurrency=int(doc.get("max_concurrency") or 4),
            max_body_bytes=int(doc.get("max_body_bytes") or 100_000),
            per_request_timeout_seconds=float(doc.get("per_request_timeout_seconds") or 8.0),
            rate_limit_per_second=float(doc.get("rate_limit_per_second") or 5.0),
            respect_robots=bool(doc.get("respect_robots", True)),
            same_origin_only=bool(doc.get("same_origin_only", True)),
            allowed_extra_hosts=allowed_extra_hosts,
            block_internal_ips=bool(doc.get("block_internal_ips", True)),
            fetch_external_js=bool(doc.get("fetch_external_js", True)),
            auth_cookies=auth_cookies,
            auth_headers=auth_headers,
        )
    except ValueError as e:
        return json.dumps({"error": f"invalid config: {e}"})

    try:
        result = Crawler(cfg).crawl()
    except Exception as e:
        return json.dumps({"error": f"crawl failed: {type(e).__name__}: {e}"})

    return json.dumps(_result_to_dict(result), ensure_ascii=False)
