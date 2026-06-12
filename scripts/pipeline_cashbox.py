"""F109 — run the full unified pipeline against cashbox.britimp.com.py
(authorized target). Read-only, banca-safe; F100 + F101 opted in for
demonstration."""

from __future__ import annotations

import sys
from datetime import datetime, timezone

sys.path.insert(0, "src")

from kryon.tools.crawler.crawler import CrawlerConfig
from kryon.tools.pipeline.pipeline import PipelineConfig, run_pipeline

TARGET = "https://cashbox.britimp.com.py/"


def main() -> int:
    print("=" * 72)
    print(f"F109 PIPELINE RUN — {TARGET}")
    print(f"timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    crawler_cfg = CrawlerConfig(
        seeds=(TARGET,),
        max_pages=30,
        max_depth=2,
        max_concurrency=2,
        rate_limit_per_second=4.0,
        per_request_timeout_seconds=8.0,
        respect_robots=True,
        same_origin_only=True,
        block_internal_ips=False,
    )
    cfg = PipelineConfig(
        seeds=(TARGET,),
        crawler=crawler_cfg,
        run_headers=True,
        run_cookies=True,
        run_cms=True,
        run_js_libs=True,
        run_dom_xss=True,
        run_disclosure=True,
        run_disclosure_full=False,  # minimal banca-safe set
        run_tls=True,
    )
    print("stages requested:")
    for k, v in (
        ("F97-headers", cfg.run_headers),
        ("F98-cookies", cfg.run_cookies),
        ("F104-cms", cfg.run_cms),
        ("F102-js-libs", cfg.run_js_libs),
        ("F107-dom-xss", cfg.run_dom_xss),
        ("F101-disclosure (opt-in)", cfg.run_disclosure),
        ("F100-tls (opt-in)", cfg.run_tls),
    ):
        print(f"  {'[X]' if v else '[ ]'} {k}")

    result = run_pipeline(cfg)

    print(f"\nelapsed: {result.elapsed_seconds:.2f}s")
    print(f"crawl: {len(result.crawl.pages)} pages, {len(result.crawl.endpoints)} endpoints, "
          f"{len(result.crawl.script_urls)} scripts, {len(result.crawl.errors)} errors")
    print(f"stages run: {', '.join(result.stages_run)}")
    if result.stages_skipped:
        print(f"stages skipped: {', '.join(result.stages_skipped)}")

    by_severity: dict[str, int] = {}
    by_module: dict[str, int] = {}
    for f in result.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_module[f.source_module] = by_module.get(f.source_module, 0) + 1

    print(f"\n--- finding count: {len(result.findings)} ---")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in by_severity:
            print(f"  {sev:8s}: {by_severity[sev]}")
    print("\n--- by source module ---")
    for mod in sorted(by_module.keys()):
        print(f"  {mod}: {by_module[mod]}")

    print("\n--- top findings ---")
    for f in result.findings[:25]:
        print(f"  [{f.severity:8s}] {f.source_module} {f.rule_id}  {f.title}")
        print(f"            target: {f.target}")
    if len(result.findings) > 25:
        print(f"  ... ({len(result.findings) - 25} more)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
