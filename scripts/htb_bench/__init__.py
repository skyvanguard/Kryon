"""F81 — HTB-style benchmark harness.

Subpackage layout:
  runner.py     — orchestrates a single target run
  scorer.py     — aggregates results into metrics
  reporter.py   — generates HTML/JSON reports
  cli.py        — argparse entry point (`python -m scripts.htb_bench`)

Walkthroughs are under `tests/benchmarks/htb_style/walkthroughs/`.
The labset manifest is `tests/benchmarks/htb_style/labset.yaml`.
"""
