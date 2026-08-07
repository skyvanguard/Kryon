"""F86 — CyberGym vuln-hunter v2 benchmark harness.

Adapter for the CyberGym benchmark suite (sunblaze-ucb/cybergym,
Apache 2.0, arxiv 2506.02548). CyberGym ships 1,507 CVEs across 188
real open-source projects, with vulnerable and patched commits side
by side. The original framework evaluates whether an LLM agent can
produce a functioning PoC that crashes the vulnerable build and is
benign on the patched build.

This adapter takes a leaner, banca-air-gap-friendly approach:

  - No 130-240 GB binary download required. We work from a YAML
    subset manifest (subset_30.yaml) + per-task walkthrough JSONs
    that point at the upstream commits.
  - Detection signal: did Kryon identify the correct CWE in the
    correct file/line range? PoC-level validation lives behind a
    KRYON_CYBERGYM_DOCKER=1 gate for operators with the full server
    data.
  - Reuses tests/benchmarks layout, RunResult dataclass conventions,
    and the HTML reporter from scripts/htb_bench/ — drift between
    the two harnesses is a maintenance smell, so we deliberately
    keep them shape-compatible.

Subpackage:
  loader.py     — read task JSON / subset manifest
  runner.py     — orchestrate one CVE detection run
  scorer.py     — aggregate; detection_rate, false-positive-rate,
                  Wilson 95% lower bound, time-to-find median
  cli.py        — argparse entry point

Walkthroughs / manifest live under `tests/benchmarks/cybergym/`.
"""
