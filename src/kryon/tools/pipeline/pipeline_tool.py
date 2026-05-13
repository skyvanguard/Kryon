"""F109 — agent-facing tool wrapper for the unified pipeline."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.crawler.crawler import CrawlerConfig
from kryon.tools.pipeline.pipeline import (
    Pipeline,
    PipelineConfig,
    PipelineResult,
    UnifiedFinding,
)

__all__ = ["run_web_audit_pipeline"]


def _finding_to_dict(f: UnifiedFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "source_module": f.source_module,
        "target": f.target,
        "extra": {k: v for k, v in f.extra},
    }


def _result_to_dict(r: PipelineResult) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_module: dict[str, int] = {}
    for f in r.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_module[f.source_module] = by_module.get(f.source_module, 0) + 1
    return {
        "elapsed_seconds": round(r.elapsed_seconds, 3),
        "stages_run": list(r.stages_run),
        "stages_skipped": list(r.stages_skipped),
        "crawl_summary": {
            "pages_count": len(r.crawl.pages),
            "endpoint_count": len(r.crawl.endpoints),
            "form_count": len(r.crawl.forms),
            "script_count": len(r.crawl.script_urls),
            "error_count": len(r.crawl.errors),
        },
        "finding_count": len(r.findings),
        "by_severity": by_severity,
        "by_module": by_module,
        "findings": [_finding_to_dict(f) for f in r.findings],
    }


@function_tool
def run_web_audit_pipeline(config_json: str) -> str:
    """Run the unified F109 pipeline: crawl + F97/F98/F102/F104/F107
    deterministic analyzers + optional F100 TLS + F101 disclosure.

    Args:
        config_json: JSON object with at minimum `seeds: [str]`. All
            other fields optional:
              run_headers, run_cookies, run_cms, run_js_libs,
              run_dom_xss (default True);
              run_disclosure, run_disclosure_full, run_tls
              (default False — banca opt-in);
              crawler: nested CrawlerConfig fields.

    Returns:
        JSON summary with stage breakdown + unified finding list
        (sorted by severity).
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

    # Optional nested crawler config
    crawler_cfg: CrawlerConfig | None = None
    crawler_dict = doc.get("crawler")
    if isinstance(crawler_dict, dict):
        try:
            crawler_cfg = CrawlerConfig(
                seeds=tuple(str(s) for s in seeds),
                max_pages=int(crawler_dict.get("max_pages") or 200),
                max_depth=int(crawler_dict.get("max_depth") or 5),
                max_concurrency=int(crawler_dict.get("max_concurrency") or 4),
                max_body_bytes=int(crawler_dict.get("max_body_bytes") or 100_000),
                per_request_timeout_seconds=float(crawler_dict.get("per_request_timeout_seconds") or 8.0),
                rate_limit_per_second=float(crawler_dict.get("rate_limit_per_second") or 5.0),
                respect_robots=bool(crawler_dict.get("respect_robots", True)),
                same_origin_only=bool(crawler_dict.get("same_origin_only", True)),
                block_internal_ips=bool(crawler_dict.get("block_internal_ips", True)),
                fetch_external_js=bool(crawler_dict.get("fetch_external_js", True)),
            )
        except ValueError as e:
            return json.dumps({"error": f"invalid crawler config: {e}"})

    try:
        cfg = PipelineConfig(
            seeds=tuple(str(s) for s in seeds),
            crawler=crawler_cfg,
            run_headers=bool(doc.get("run_headers", True)),
            run_cookies=bool(doc.get("run_cookies", True)),
            run_cms=bool(doc.get("run_cms", True)),
            run_js_libs=bool(doc.get("run_js_libs", True)),
            run_dom_xss=bool(doc.get("run_dom_xss", True)),
            run_disclosure=bool(doc.get("run_disclosure", False)),
            run_disclosure_full=bool(doc.get("run_disclosure_full", False)),
            run_tls=bool(doc.get("run_tls", False)),
            tls_timeout=float(doc.get("tls_timeout") or 5.0),
        )
    except ValueError as e:
        return json.dumps({"error": f"invalid pipeline config: {e}"})

    try:
        result = Pipeline(cfg).run()
    except Exception as e:
        return json.dumps({"error": f"pipeline failed: {type(e).__name__}: {e}"})

    return json.dumps(_result_to_dict(result), ensure_ascii=False)
