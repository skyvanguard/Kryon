"""@function_tool wrapper exposing the F66 unified web pipeline.

The pipeline (authenticated-aware crawl + security headers + cookie flags + CMS
detection + JS-library CVEs + DOM-XSS sinks, optionally TLS / info-disclosure /
nuclei / ffuf) was fully built but had ZERO call-sites — neither the LLM nor a
deterministic phase could reach it. This wires it as an LLM-callable tool.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from kryon.sdk.agents import function_tool


@function_tool
def web_pipeline_scan(
    url: str,
    run_tls: bool = False,
    run_disclosure: bool = False,
    run_nuclei: bool = False,
) -> str:
    """Run the unified web analysis pipeline against a URL in one pass.

    Static analyzers are ON (security headers, cookie flags, CMS detection, JS
    library CVEs, DOM-XSS sinks via a crawl). Network-heavier stages are opt-in:
    TLS profiling (run_tls), info-disclosure probes (run_disclosure), nuclei
    templates (run_nuclei). Returns JSON with the normalized findings.

    Use this instead of stitching the individual web checks together by hand when
    auditing a web app end-to-end.
    """
    try:
        from kryon.tools.pipeline.pipeline import PipelineConfig, run_pipeline
    except ImportError as e:  # pragma: no cover
        return json.dumps({"error": f"pipeline unavailable: {e}"})
    try:
        cfg = PipelineConfig(
            seeds=(url,),
            run_tls=run_tls,
            run_disclosure=run_disclosure,
            run_nuclei=run_nuclei,
        )
        result = run_pipeline(cfg)
        findings = [asdict(f) for f in result.findings]
        return json.dumps({"url": url, "count": len(findings), "findings": findings}, default=str)
    except Exception as e:  # noqa: BLE001 — Playwright/browser may be absent at runtime
        return json.dumps({"error": f"pipeline run failed: {e}"})
