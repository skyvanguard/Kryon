"""F108 — crawl cashbox.britimp.com.py (authorized target) and
report what the crawler surfaces. Read-only, banca-safe."""

from __future__ import annotations

import sys

sys.path.insert(0, "src")

from kryon.tools.crawler.crawler import Crawler, CrawlerConfig

TARGET = "https://cashbox.britimp.com.py/"


def main() -> int:
    cfg = CrawlerConfig(
        seeds=(TARGET,),
        max_pages=50,
        max_depth=3,
        max_concurrency=2,
        rate_limit_per_second=4.0,
        respect_robots=True,
        same_origin_only=True,
        block_internal_ips=False,  # public target
    )
    print(f"crawling {TARGET}")
    print(f"  max_pages={cfg.max_pages} max_depth={cfg.max_depth} rate={cfg.rate_limit_per_second}/s")
    result = Crawler(cfg).crawl()

    print(f"\nelapsed: {result.elapsed_seconds:.2f}s")
    print(f"pages fetched: {len(result.pages)}")
    print(f"endpoints discovered: {len(result.endpoints)}")
    print(f"forms discovered: {len(result.forms)}")
    print(f"external script URLs: {len(result.script_urls)}")
    print(f"errors: {len(result.errors)}")

    print("\n--- pages (top 10 by depth) ---")
    for p in sorted(result.pages, key=lambda x: (x.depth, x.url))[:10]:
        print(f"  d{p.depth} [{p.http_status}] {p.url}")

    print("\n--- endpoints by source ---")
    by_source: dict[str, list[str]] = {}
    for ep in result.endpoints:
        by_source.setdefault(ep.source, []).append(ep.url)
    for source, urls in sorted(by_source.items()):
        print(f"  {source}: {len(urls)}")
        for u in sorted(set(urls))[:5]:
            print(f"    - {u}")
        if len(set(urls)) > 5:
            print(f"    ... ({len(set(urls)) - 5} more)")

    print("\n--- forms ---")
    for f in result.forms[:5]:
        fields = ", ".join(name for name, _ in f.fields)
        print(f"  [{f.method}] {f.action}  fields: {fields}")

    print("\n--- script URLs (sample) ---")
    for s in result.script_urls[:8]:
        print(f"  {s}")
    if len(result.script_urls) > 8:
        print(f"  ... ({len(result.script_urls) - 8} more)")

    print("\n--- errors ---")
    for e in result.errors[:8]:
        print(f"  [{e.reason}] {e.url}  {e.detail}")
    if len(result.errors) > 8:
        print(f"  ... ({len(result.errors) - 8} more)")

    # ---- secondary: feed surfaces back into F102 + F104 + F107 ----
    print("\n" + "=" * 60)
    print("CHAINED ANALYSIS (crawler output → F102/F104/F107)")
    print("=" * 60)

    from kryon.tools.api.vuln_js_libs import (
        ScriptObservation,
        analyze_scripts,
    )
    from kryon.tools.api.cms_fingerprint import (
        FingerprintObservation,
        analyze_fingerprint,
    )

    # F102 against all discovered script URLs
    js_obs = [ScriptObservation(src=src) for src in result.script_urls]
    js_an = analyze_scripts(js_obs)
    print(f"\nF102 (vuln JS libs): {len(js_an.findings)} findings across {len(js_obs)} scripts")
    for f in js_an.findings:
        print(f"  [{f.severity:8s}] {f.rule_id}: {f.title}")

    # F104 against root page if we have it
    root_pages = [p for p in result.pages if p.url == TARGET or p.url == TARGET.rstrip("/")]
    if root_pages:
        rp = root_pages[0]
        # collect meta-tag pairs for root
        root_metas: list[tuple[str, str]] = []
        for page_url, pairs in result.meta_tags:
            if page_url == rp.url:
                root_metas = list(pairs)
                break
        fp_obs = FingerprintObservation(
            url=rp.url,
            headers=rp.headers,
            body_snippet=rp.body_snippet,
            cookie_names=(),
        )
        fp_an = analyze_fingerprint(fp_obs)
        print(f"\nF104 (CMS fingerprint on root): {len(fp_an.findings)} findings")
        for f in fp_an.findings:
            tech = f.detected_tech + (f" {f.detected_version}" if f.detected_version else "")
            print(f"  [{f.severity:8s}] {f.rule_id}: {f.title}  [{tech}]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
