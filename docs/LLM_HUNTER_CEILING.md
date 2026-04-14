# LLM Hunter Ceiling — observations from 8 live runs on zlib

After 8 successive LLM hunts (gemma4:26b-32k, runner=llm, budget=1 file)
against `github.com/madler/zlib#deflate.c`, the pattern is unambiguous:
**this model cannot autonomously close the Hypothesize → Verify → Report
cycle in a single agent run**, no matter how well the playbook is tuned.

## Hunt trajectory

| # | Outcome | Key observation | Fix applied |
|---|---|---|---|
| 1 | TIMEOUT findings=0 | gemma4 guessed `fill_window` (doesn't exist; real names are `_c90`/`_sse`) | Added `list_functions` tool |
| 2 | TIMEOUT findings=0 | Comment-regex ate valid function matches | Comment-preserving-offset scanner |
| 3 | TIMEOUT findings=0 | Pool vs runner timeout race canceled harvest | Timeout stagger (runner < pool) |
| 4 | INFO tools=7 / all read_function | Exploring breadth-first, never committing | "Commit early" rule, escape hatch ≥ 6 turns |
| 5 | INFO tools=14 / run_command×5 | Wrote + ran PoCs via `run_command`, not the ASAN oracle | Explicit "use run_sandboxed only" |
| 6 | INFO tools=6 / execute_code×3 | Bypassed the run_command rule via execute_code | Added execute_code to forbidden list |
| 7 | INFO tools=9 / run_command×2 | Playbook rules alone don't hold — model regresses between runs | Structural fix: tool veto |
| 8 | INFO tools=10 / read_function heavy | Tool veto works. run_sandboxed never called. | — (ceiling reached) |

## What's working

- **The pipeline**: clone + priority + dynamic prompt + corpus pre-seed
  + HunterPool + validator + report. Every mechanical piece.
- **The tools**: `list_functions`, `read_function`, `find_callers`,
  `run_sandboxed`, `recall_similar_code_pattern`. All return correct
  data on real targets.
- **The skill system's forbidden_tools veto**: confirmed that a skill
  can physically remove ambient tools from the model's toolset.
- **Telemetry**: every timeout surfaces which tools were called, in
  what order, letting us debug without flying blind.
- **Heuristic hunter**: 4/4 confirmed findings on zlib in 0.9s
  (regression-safe across all fixes).

## Where the ceiling is

gemma4:26b-32k with CPU spillover (46% CPU / 54% GPU) on 12 GB VRAM
shows these limits on multi-step creative code-analysis tasks:

- **Turns per second**: ~0.8-1.2 (tool calls), each inference round
  takes 30-90 s
- **Context filled by tool outputs**: `read_function` returns up to
  15 KB; after 5-6 reads the model is at ~20 K tokens and effective
  reasoning degrades
- **Creative synthesis under uncertainty**: the model can read code
  correctly and query RAG correctly, but writing a small C harness
  that exercises a function with an attacker-controlled input is
  beyond what it completes autonomously in this budget

In contrast, the same pipeline under a frontier model (Claude 4.x,
GPT-5-class) per Mythos / ARTEMIS evidence:

- 2 min end-to-end for a single-file hunt vs our 10-20 min
- Reliably emits a PoC and calls the ASAN oracle
- 89 % agreement with expert reviewers (Mythos)

## What we ship

The architecture is complete and independently useful:

- **Heuristic hunter**: ready for regression-detection use. Fast,
  deterministic, finds pattern-level crashes, validator gates them.
- **CVE corpus**: 297 real entries with semantic search. Powers
  `recall_similar_code_pattern` for future hunters.
- **LLM hunter as lab**: produces INFO records with full tool trace,
  useful for studying the model's exploration behavior.
- **Tool/skill infrastructure**: `forbidden_tools`, timeout stagger,
  harvest-on-timeout, dynamic prompt generator, bounded parallel pool.

## Paths forward (when pursued)

- **Bigger model, still local**: a Q4-quantized 70 B (e.g., Qwen2.5
  72B Instruct, Llama 3.3 70B) would need ~40 GB disk + ~10-12 GB
  VRAM headroom. Requires CPU offload but that's what we already
  tolerate with gemma4:26b at 64k. Worth piloting when a stable
  GGUF drops.
- **Decompose the hunter**: split into two specialist skills —
  `triage-select` (pick 1 function from a file, cheap) and
  `poc-writer` (given ONE function body, emit ONE C harness, small
  input space). Each call is short enough for gemma4 to converge.
- **Human-in-the-loop mode**: `/hunt interactive` that runs the
  heuristic pipeline, surfaces top-3 file-function candidates with
  corpus hints, and asks the operator to approve before committing
  model time to the full LLM cycle.
- **Delegate oracle to heuristic when model stalls**: if the LLM
  hunter reaches the escape hatch, automatically retry that file
  with `runner=heuristic` as fallback. Zero wasted hunt.

None of these block current use — `/hunt --runner heuristic` is
production-ready today. The LLM runner is a research track that
scales with future model releases.
