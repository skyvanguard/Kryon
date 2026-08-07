"""
Reproducible ingestion of the CVE corpus.

Runs the full F4 pipeline end-to-end against the real github/advisory-database:
  1. GitHubAdvisoryScraper.scrape() with memory-safety CWE filter
  2. cve_diff_enricher.enrich_batch() — cloning target repos as needed
  3. cve_corpus.ingest_jsonl() — into ChromaDB with Ollama embeddings

Safe to interrupt: each stage writes intermediate JSONL so re-running
skips work already done.

Environment:
  KRYON_ADVISORY_DB_PATH   where advisory-database is cloned (default /workspace/sources/_advisory_database)
  KRYON_SOURCES_ROOT       where target repos are cloned (default /workspace/sources)
  KRYON_CVE_CORPUS_DIR     where ChromaDB persists (default /workspace/.kryon_cve_corpus)
  KRYON_EMBEDDING_BASE_URL Ollama endpoint
  KRYON_EMBEDDING_MODEL    embedding model name
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def stage1_scrape(out_path: Path, limit: int, cwes: list[str], ecosystems: list[str] | None) -> int:
    from kryon.knowledge.scrapers.github_advisory_scraper import (
        GitHubAdvisoryScraper,
        write_jsonl,
    )
    print(f"[1/3] scraping advisory-database  limit={limit}  cwes={cwes}")
    t0 = time.time()
    s = GitHubAdvisoryScraper()
    advisories = s.scrape(
        limit=limit,
        require_fix_commit=True,
        cwe_filter=cwes,
        ecosystems=ecosystems,
    )
    n = write_jsonl(advisories, str(out_path))
    print(f"      wrote {n} advisories -> {out_path}  ({time.time()-t0:.1f}s)")
    return n


def _advisories_iter(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def stage2_enrich(
    in_path: Path, out_path: Path, max_advisories: int, max_commits: int
) -> dict:
    from kryon.knowledge.scrapers.cve_diff_enricher import enrich_batch
    print(f"[2/3] enriching with real diffs  max_advisories={max_advisories}")
    # Subsample
    advisories = list(_advisories_iter(in_path))[:max_advisories]
    t0 = time.time()
    stats = enrich_batch(
        advisories,
        out_path=str(out_path),
        max_commits=max_commits,
        progress_every=5,
    )
    print(
        f"      {stats['advisories_processed']} advisories, "
        f"{stats['entries_written']} entries written, "
        f"{stats['failures']} failures, "
        f"{stats['duration_s']}s -> {out_path}"
    )
    return stats


def stage3_ingest(enriched_path: Path) -> dict:
    from kryon.knowledge import cve_corpus
    print("[3/3] ingesting into ChromaDB")
    t0 = time.time()
    n = cve_corpus.ingest_jsonl(str(enriched_path))
    stats = cve_corpus.corpus_stats()
    stats["ingest_count"] = n
    stats["duration_s"] = round(time.time() - t0, 1)
    print(
        f"      ingested {n} entries, total in corpus: {stats.get('count', '?')}, "
        f"persist: {stats.get('persist_dir')}  ({stats['duration_s']}s)"
    )
    return stats


def smoke_test():
    """Quick recall sanity check on the newly ingested corpus."""
    print("\n[smoke] recall_similar_code_pattern on classic memcpy snippet:")
    from kryon.knowledge import cve_corpus
    snippet = (
        "int copy_chunk(char *dst, const char *src, size_t n) {\n"
        "    memcpy(dst, src, n);\n"
        "    return 0;\n"
        "}\n"
    )
    matches = cve_corpus._query_similar(snippet, top_k=5)
    for m in matches:
        print(f"  sim={m['similarity']:.3f}  "
              f"{m.get('cve_id', '?'):<15} {m.get('cwe_ids', ''):<20} "
              f"{m.get('repo', ''):<30} "
              f"{m.get('pattern_excerpt', '')[:60]}...")
    return matches


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out-dir", default="/workspace/hunts/corpus_build")
    p.add_argument("--scrape-limit", type=int, default=200,
                   help="max advisories from scraper")
    p.add_argument("--enrich-limit", type=int, default=40,
                   help="max advisories to enrich (clone repo + diff)")
    p.add_argument("--max-commits-per-advisory", type=int, default=1)
    p.add_argument(
        "--cwes", default="CWE-787,CWE-416,CWE-190,CWE-125,CWE-476,CWE-121,CWE-415",
        help="comma-separated CWE filter (memory-safety by default)",
    )
    p.add_argument("--ecosystems", default="",
                   help="comma-separated ecosystem filter (empty = all)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--skip-scrape", action="store_true",
                   help="reuse existing scraped JSONL")
    p.add_argument("--skip-enrich", action="store_true",
                   help="reuse existing enriched JSONL")
    args = p.parse_args()

    _configure_logging(args.verbose)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    scraped_path = out_dir / "advisories.jsonl"
    enriched_path = out_dir / "enriched.jsonl"

    cwes = [c.strip() for c in args.cwes.split(",") if c.strip()]
    ecosystems = [e.strip() for e in args.ecosystems.split(",") if e.strip()] or None

    t_total = time.time()

    # Stage 1
    if args.skip_scrape and scraped_path.is_file():
        n = sum(1 for _ in _advisories_iter(scraped_path))
        print(f"[1/3] skip scrape — using existing {scraped_path} ({n} advisories)")
    else:
        n = stage1_scrape(scraped_path, args.scrape_limit, cwes, ecosystems)
        if n == 0:
            print("ERROR: scraper returned 0 advisories — cannot proceed")
            return 1

    # Stage 2
    if args.skip_enrich and enriched_path.is_file():
        n2 = sum(1 for _ in _advisories_iter(enriched_path))
        print(f"[2/3] skip enrich — using existing {enriched_path} ({n2} entries)")
    else:
        stage2_enrich(scraped_path, enriched_path, args.enrich_limit, args.max_commits_per_advisory)

    # Stage 3
    stage3_ingest(enriched_path)

    smoke_test()

    print(f"\nTotal wall time: {time.time()-t_total:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
