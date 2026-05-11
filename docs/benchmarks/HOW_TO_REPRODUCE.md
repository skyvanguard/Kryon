# Reproducing the F81 HTB-style benchmark

Public scoreboard: TBD (will live at `kryon-bench.britimp.com.py` once F83 ships).

This document is the "fair-play" contract. Anyone can repeat the
benchmark following these steps and get a number comparable to the
one Kryon publishes — no proprietary infra, no closed walkthroughs.

## What gets measured

For each target in `tests/benchmarks/htb_style/labset.yaml`:
- **`pwn`** (boolean) — did Kryon's tool output match any
  `flag_pattern` regex from the walkthrough?
- **`chain_match_score`** ∈ [0, 1] — fraction of `required` tools
  from `expected_chain` that Kryon actually invoked. Order-independent.
- **`time_to_pwn_seconds`** — wall clock from harness start to first
  flag match.

Aggregated across the labset:
- **`pwn_rate`** — `pwned / total` (the headline metric).
- **`mean_chain_match`** — over `pwned` results only.
- **`median_time_to_pwn`** — robust to outliers.
- **`by_category`** — same metrics grouped by vuln class
  (sqli / xss / rce / auth / idor / ssrf / priv-esc / recon / api / crypto / ssl).

## Pre-requisites

- Docker + docker compose (for targets with `source.type: docker_compose`).
- Vagrant (only for legacy VulnHub VMs; most of the labset avoids them).
- `kryon` container running locally — see project root README.
- ~30 GB disk (target images + transcripts).
- Internet connectivity for PortSwigger Academy labs.

## Run a single target

```bash
python -m scripts.htb_bench.cli --target portswigger-sqli-where-clause \
                                --out reports/htb_2026-04-29.json
```

Output:

```
  [RUN ] portswigger-sqli-where-clause ...
  [PWN ] portswigger-sqli-where-clause  11.9s

  Total: 1  Pwned: 1  Rate: 100.0%  Errors: 0
  Report -> reports/htb_2026-04-29.json
```

The JSON has two top-level keys:
- `report`: aggregated metrics (the public scorecard format).
- `results`: per-target raw data (chains, error messages, transcript head).

## Run the full labset

```bash
python -m scripts.htb_bench.cli --all --status ready \
                                --out reports/htb_$(date +%Y-%m-%d).json
```

`--status ready` filters to targets whose walkthrough JSON exists AND
has been validated against a real spawn. `wip` and `planned` targets
are skipped — they're sketches without a working source yet.

To run absolutely every target (including unvalidated ones, expect
errors):

```bash
python -m scripts.htb_bench.cli --all
```

## Reproduce someone else's published number

1. Clone the same Kryon commit they cite (the published JSON has a
   `kryon_version` field — use that).
2. Run the same command they cite (the JSON's `command` field).
3. Compare your `report.pwn_rate` to theirs.

The harness is deterministic UP TO model non-determinism. Same
commit + same model + same target ⇒ ±5% pwn rate variance is
normal (LLMs sample, tool args wiggle). Larger gaps mean either:
- The labset drifted (someone updated a walkthrough → re-pull and retry).
- The target is non-deterministic (a flaky lab — file an issue).
- The runner is buggy (pin both repos to the same SHA and bisect).

## Comparing across model backends

Kryon supports Ollama-local and (planned) Anthropic / OpenAI APIs. The
report's `kryon_model` field records which one ran. Two reports
generated with different models are NOT directly comparable — a
qwen3-14b run at 60% pwn rate is NOT inferior to a Claude run at 85%
if the qwen run is in the customer's air-gapped data center where the
Claude run physically can't run.

We publish dual columns: "kryon-14b-local" and "kryon-claude" once
F94 (productization) ships.

## Adding a new target

1. Pick a slug (`<framework>-<vuln>-<difficulty>`).
2. Write `tests/benchmarks/htb_style/walkthroughs/<slug>.json` per
   `tests/benchmarks/htb_style/schema.md`.
3. Add the slug to `labset.yaml` with `status: wip`.
4. Run `python -m scripts.htb_bench.cli --target <slug>` — confirm
   the harness spawns the target and Kryon at least *attempts* it
   (PWN or FAIL is fine; ERR is not).
5. When the spawn + ready_url pattern is reliable, flip status to
   `ready`.
6. Open a PR. The CI workflow (TBD — F83) will run your target on
   every push.

## Failure modes and what they mean

- `error: target_not_ready` — `ready_url` didn't return 2xx in 60 s.
  Either the target is slow (raise timeout in `runner.py`) or the
  spawn failed silently. Inspect `docker compose logs`.
- `error: kryon_timeout` — Kryon exceeded `wall_budget_seconds`. The
  target may genuinely be hard for the model, or the budget is too
  tight. Compare `actual_chain` length — if it's > 20 the model is
  burning turns without progress; that's a model/skills issue, not
  a budget issue.
- `error: FileNotFoundError: <compose_path>` — the target's compose
  file isn't checked in. Either the walkthrough is `wip` (don't run
  it) or someone forgot to commit `targets/<name>/`.

## Banking-safe note

Kryon is built primarily for banking compliance. The HTB-style
benchmark is a **technical capability proxy** — it does NOT exercise
the deterministic compliance pipelines (PCI-DSS, FortiGate, Unifi,
Proxmox). Those have their own reproducibility hashes and a separate
report. A high HTB pwn rate does not imply a Kryon engagement is
"safe" for prod banking — it implies offensive capability is
real. The two are complementary signals.
