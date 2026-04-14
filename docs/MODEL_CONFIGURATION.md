# Model configuration — Kryon on 12 GB VRAM

Reference for the model lineup, context windows, and embedding choices
that run locally on the laptop (RTX 5070 Ti Laptop, 12 GB VRAM, 32 GB RAM).

## Language model variants (Ollama)

| Name                | Size | Ctx   | VRAM load (peak) | CPU spill | Speed target     | When to use |
|---------------------|------|-------|------------------|-----------|------------------|-------------|
| `gemma4:26b`        | 17 GB| 8192  | ~7-8 GB          | no        | ~25 tok/s        | quick tests |
| `gemma4:26b-32k`    | 17 GB| 32 768| ~9-10 GB         | minimal   | ~18-22 tok/s     | **default** |
| `gemma4:26b-64k`    | 17 GB| 65 536| ~11 GB (border)  | ~46% CPU  | ~13-15 tok/s     | long engagements / big repos |

The 32k variant is the baseline: it reliably stays GPU-resident during
autonomous hunts (30+ turns with tool outputs), and inference stays fast
enough for interactive use. The 64k variant is opt-in for times when the
hunter needs to hold a big source file + prior findings + compacted
history simultaneously.

### Switching to 64k

```bash
# In docker/.env.docker:
KRYON_MODEL=gemma4:26b-64k

# Then:
docker compose restart kryon
```

If inference feels too slow, drop back to 32k — the compaction services
(session_memory dedup, compact_hunter_session) already buy back a lot
of effective context.

### Pushing beyond 64k with KV cache quantization

Ollama supports KV cache quantization via env var on the **ollama**
container (not kryon):

```yaml
# docker/docker-compose.override.yml, under the ollama service:
environment:
  - OLLAMA_KV_CACHE_TYPE=q8_0     # halves KV cache; minor quality loss
  # - OLLAMA_KV_CACHE_TYPE=q4_0   # aggressive; noticeable quality loss
  - OLLAMA_FLASH_ATTENTION=1
```

With `q8_0` KV, gemma4:26b-64k stays more GPU-resident (less CPU spillover),
and you could even build a `gemma4:26b-128k` modelfile that fits. Gemma
3/4 natively supports 128K; the only bottleneck is VRAM for the KV cache.

**Do not enable both Q4 KV and aggressive quantization of model weights at
the same time** — reasoning degrades visibly.

## Embedding models

| Name                       | Size  | Dim | Notes |
|----------------------------|-------|-----|-------|
| `nomic-embed-text:latest`  | 274 MB| 768 | **default** — great general quality; on our F4.3 benchmark it ties larger alternatives |
| `mxbai-embed-large:latest` | 669 MB| 1024| available, pulled, but shows no improvement on our CVE-pattern retrieval fixtures |

### F4.3 finding — why we stayed on nomic

We benchmarked both embedders on 6 labeled CVE↔query pairs
(`scripts/bench_f43_embeddings.py`). Both produce *identical rankings*:

```
nomic-embed-text   recall@1=67%  recall@3=100%  mean_rank=1.33  0.08s
mxbai-embed-large  recall@1=67%  recall@3=100%  mean_rank=1.33  0.08s
```

The bottleneck is not the embedder — it's the pattern representation.
When the corpus text already contains the CWE tag and words like
"heap overflow", any reasonable embedder does token-level matching on
those signals. To get a real uplift we'd need:

- True code-aware embeddings (CodeBERT, GraphCodeBERT, JinaCode) —
  none trivially available via Ollama; would need HuggingFace +
  sentence-transformers at 1-2 GB extra disk
- Or, structural enrichment in the pattern string itself
  (function names, ADDED/REMOVED calls, caller context) — done in
  `cve_diff_enricher._build_pattern_text` as of F4.3

### Switching embedding model at runtime

```bash
# docker/.env.docker
KRYON_EMBEDDING_BASE_URL=http://kryon-ollama:11434
KRYON_EMBEDDING_MODEL=nomic-embed-text
# or
# KRYON_EMBEDDING_MODEL=mxbai-embed-large
```

Collections are keyed per (corpus_dir, embedder); the CVE corpus code
falls back to recreate-on-mismatch when the embedder changes.

## Concurrent model slots — parallelism knobs

Ollama serializes per-model inference by default. To allow two hunters
to run simultaneously on the same model:

```yaml
# ollama service env:
- OLLAMA_NUM_PARALLEL=2
```

**VRAM cost:** each parallel slot duplicates the KV cache. At 32k ctx
this is ~2-3 GB per extra slot, so `NUM_PARALLEL=2` on our 12 GB card is
tight but workable with 32k. At 64k it will OOM.

Kryon's `HunterPool` always keeps the hunter count at
`KRYON_HUNTER_PARALLELISM` regardless of `OLLAMA_NUM_PARALLEL` — the
former bounds how many hunters are *alive*, the latter bounds how many
can be *inferring simultaneously*. The speedup benchmarks in F3.9 were
run with `OLLAMA_NUM_PARALLEL=1` and still showed ~2x speedup (overlap
of tool execution, not inference).

## Dual-model for validator (opt-in, F3.7)

If validator false positives become a problem, swap to a separate model
for the validator only:

```bash
KRYON_DUAL_MODEL=true
KRYON_VALIDATOR_MODEL=qwen2.5-coder:7b     # or deepseek-coder-v2:16b
```

The `model_swapper.py` service (F3.7, pending) will call `ollama stop`
on the hunter model before invoking the validator, then reload. Expect
~3-5s overhead per swap, amortized across many findings.

**Not recommended yet** — gemma4:26b single-model with context isolation
is working well and saves the swap penalty.

## Quick reference

| Situation | Recommended config |
|-----------|--------------------|
| Default development | `KRYON_MODEL=gemma4:26b-32k`, `OLLAMA_NUM_PARALLEL=1` |
| Long engagement, big repo | `KRYON_MODEL=gemma4:26b-64k`, consider `OLLAMA_KV_CACHE_TYPE=q8_0` |
| True parallel hunters | `OLLAMA_NUM_PARALLEL=2`, keep ctx at 32k, `KRYON_HUNTER_PARALLELISM=2` |
| Validator uplift | `KRYON_DUAL_MODEL=true`, `KRYON_VALIDATOR_MODEL=qwen2.5-coder:7b` (F3.7 needed) |
| CVE-corpus RAG | `KRYON_EMBEDDING_MODEL=nomic-embed-text` — do not upgrade until we try code-aware models |
