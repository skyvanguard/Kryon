"""
F4.3 embedding comparison — does mxbai-embed-large beat nomic-embed-text
on CVE/code pattern retrieval?

Metric: for each labeled query (snippet with known target CWE), count
how often the correct CVE entry ranks in top-k (k=1,3,5). Higher is
better — correct CVE at lower rank means semantic retrieval is
discriminating the right bug class.

Both embedders are accessed via the SAME Ollama /api/embeddings endpoint
— only KRYON_EMBEDDING_MODEL changes per run, so the comparison is
like-for-like.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

FIXTURES = [
    (
        "CVE-A001", "CWE-787",
        (
            "heap overflow in parse_header due to missing length check\n"
            "CWE: CWE-787\n"
            "FIX: Fix heap overflow in parse_header\n"
            "---\n"
            "FILE: parser.c\n"
            "-    memcpy(buf, src, len);\n"
            "+    if (len > sizeof(buf)) return -1;\n"
            "+    memcpy(buf, src, len);\n"
        ),
        (
            "int copy_payload(uint8_t *dst, const uint8_t *src, size_t n) {\n"
            "    memcpy(dst, src, n);\n"
            "    return 0;\n"
            "}\n"
        ),
    ),
    (
        "CVE-A002", "CWE-416",
        (
            "use-after-free in release_handler — callback freed buffer\n"
            "CWE: CWE-416\n"
            "FIX: Fix use-after-free in release_handler\n"
            "---\n"
            "FILE: handler.c\n"
            "     free(h->buf);\n"
            "-    h->state = IDLE;\n"
            "+    h->buf = NULL;\n"
            "+    h->state = IDLE;\n"
        ),
        (
            "void cleanup(struct ctx *c) {\n"
            "    free(c->data);\n"
            "    if (c->next) process(c);\n"
            "}\n"
        ),
    ),
    (
        "CVE-A003", "CWE-190",
        (
            "integer overflow in compute_size leads to small allocation\n"
            "CWE: CWE-190\n"
            "FIX: Guard multiplication against overflow\n"
            "---\n"
            "FILE: alloc.c\n"
            "-    return malloc(a * b);\n"
            "+    if (a && SIZE_MAX / a < b) return NULL;\n"
            "+    return malloc(a * b);\n"
        ),
        (
            "void *make_buf(size_t count, size_t elem) {\n"
            "    size_t total = count * elem;\n"
            "    return malloc(total);\n"
            "}\n"
        ),
    ),
    (
        "CVE-A004", "CWE-125",
        (
            "out-of-bounds read in decode_token past end of buffer\n"
            "CWE: CWE-125\n"
            "FIX: Check index before read\n"
            "---\n"
            "FILE: decoder.c\n"
            "-    return buf[pos + offset];\n"
            "+    if (pos + offset >= len) return 0;\n"
            "+    return buf[pos + offset];\n"
        ),
        (
            "uint8_t peek(const uint8_t *buf, size_t pos, size_t len) {\n"
            "    int off = get_offset();\n"
            "    return buf[pos + off];\n"
            "}\n"
        ),
    ),
    (
        "CVE-A005", "CWE-476",
        (
            "null pointer dereference when lookup fails\n"
            "CWE: CWE-476\n"
            "FIX: Guard against NULL return\n"
            "---\n"
            "FILE: lookup.c\n"
            "     entry = find_entry(key);\n"
            "+    if (!entry) return -ENOENT;\n"
            "     return entry->value;\n"
        ),
        (
            "int get_val(const char *k) {\n"
            "    struct obj *o = hash_get(k);\n"
            "    return o->value;\n"
            "}\n"
        ),
    ),
    (
        "CVE-A006", "CWE-787-stack",
        (
            "stack buffer overflow in handle_input via strcpy\n"
            "CWE: CWE-787\n"
            "FIX: Use strncpy with explicit size\n"
            "---\n"
            "FILE: input.c\n"
            "     char buf[64];\n"
            "-    strcpy(buf, user_input);\n"
            "+    strncpy(buf, user_input, sizeof(buf)-1);\n"
            "+    buf[sizeof(buf)-1] = 0;\n"
        ),
        (
            "void serve(const char *req) {\n"
            "    char local[128];\n"
            "    strcpy(local, req);\n"
            "    process(local);\n"
            "}\n"
        ),
    ),
]


def run_benchmark(embed_model: str, ollama_url: str = "http://kryon-ollama:11434") -> dict:
    os.environ["KRYON_EMBEDDING_BASE_URL"] = ollama_url
    os.environ["KRYON_EMBEDDING_MODEL"] = embed_model
    os.environ["KRYON_CVE_CORPUS_DIR"] = f"/tmp/kryon_cve_corpus_{embed_model.replace(':', '_').replace('/', '_')}"

    # Force re-import so embedder re-binds
    for m in [k for k in list(sys.modules) if k.startswith("kryon.knowledge.cve_corpus")]:
        sys.modules.pop(m)

    from kryon.knowledge import cve_corpus
    cve_corpus.reset_corpus()

    entries = [
        {
            "ghsa_id": f"GHSA-{cve}",
            "cve_id": cve,
            "cwe_ids": [cwe],
            "summary": pattern.splitlines()[0] if pattern else "",
            "severity": "HIGH",
            "ecosystem": "test",
            "package": "bench",
            "commit_sha": "deadbeef",
            "repo": "bench/bench",
            "subject": "benchmark",
            "files": [],
            "pattern": pattern,
        }
        for cve, cwe, pattern, _ in FIXTURES
    ]
    n = cve_corpus.ingest_entries(entries)
    assert n == len(FIXTURES), f"ingest mismatch: {n} vs {len(FIXTURES)}"

    hits_at = {1: 0, 3: 0, 5: 0}
    ranks: list[int] = []
    per_query: list[dict] = []
    t0 = time.time()

    for cve, cwe, _, query in FIXTURES:
        matches = cve_corpus._query_similar(query, top_k=6)
        rank = 999
        for i, m in enumerate(matches, 1):
            if m["cve_id"] == cve:
                rank = i
                break
        ranks.append(rank)
        for k in (1, 3, 5):
            if rank <= k:
                hits_at[k] += 1
        per_query.append({
            "cve": cve,
            "cwe": cwe,
            "correct_rank": rank,
            "top3": [m["cve_id"] for m in matches[:3]],
        })

    elapsed = time.time() - t0
    n_q = len(FIXTURES)
    return {
        "embed_model": embed_model,
        "n_queries": n_q,
        "recall@1": hits_at[1] / n_q,
        "recall@3": hits_at[3] / n_q,
        "recall@5": hits_at[5] / n_q,
        "mean_rank": round(sum(ranks) / len(ranks), 2),
        "total_time_s": round(elapsed, 2),
        "per_query": per_query,
    }


def main():
    models = ["nomic-embed-text", "mxbai-embed-large"]
    print("=" * 70)
    print("F4.3 embedding benchmark — CVE pattern retrieval quality")
    print("=" * 70)
    print(f"Fixtures: {len(FIXTURES)} labeled CVE<->query pairs")
    print()

    results = []
    for model in models:
        print(f"--> {model}")
        try:
            r = run_benchmark(model)
            results.append(r)
            print(
                f"    recall@1={r['recall@1']:.0%}  "
                f"recall@3={r['recall@3']:.0%}  "
                f"recall@5={r['recall@5']:.0%}  "
                f"mean_rank={r['mean_rank']}  "
                f"{r['total_time_s']}s"
            )
        except Exception as e:
            print(f"    FAILED: {e}")
            import traceback; traceback.print_exc()

    if len(results) == 2:
        a, b = results
        print()
        print("Per-query ranks:")
        print(f"  {'CVE':<10} {'CWE':<14} {a['embed_model']:>22} {b['embed_model']:>22}")
        for qa, qb in zip(a["per_query"], b["per_query"]):
            marker = "  " if qa["correct_rank"] == qb["correct_rank"] else (
                " +" if qb["correct_rank"] < qa["correct_rank"] else " -"
            )
            print(f"{marker}{qa['cve']:<10} {qa['cwe']:<14}"
                  f"  rank={qa['correct_rank']:>4} "
                  f"top3={qa['top3']!s:<30} "
                  f"  rank={qb['correct_rank']:>4} "
                  f"top3={qb['top3']}")

        print()
        gap1 = b["recall@1"] - a["recall@1"]
        gap3 = b["recall@3"] - a["recall@3"]
        winner = b["embed_model"] if (gap1 + gap3) > 0 else a["embed_model"]
        print(f"VERDICT: {winner} wins overall "
              f"(@1 gap={gap1*100:+.0f}pp, @3 gap={gap3*100:+.0f}pp)")

    out = Path("/tmp/bench_f43_embeddings.json")
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults: {out}")


if __name__ == "__main__":
    main()
