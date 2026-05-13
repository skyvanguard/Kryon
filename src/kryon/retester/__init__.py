"""F88 — Retester package (HackerOne Retester pattern).

After Kryon hands a client a finding ("CWE-89 in POST /transfer"),
the client patches it and asks: "is it really fixed?". The Retester
takes the original finding's reproduction (RetestRecord), replays
the exact same probe, and compares the response against the
original fingerprint. Verdicts: fixed / still_open / changed /
error.

Module layout:
  record.py     — RetestRecord frozen dataclass + JSON ser/de
  replay.py     — replay_finding() — gated HTTP replay
  comparator.py — verdict_for(record, current) — pure logic
  aggregator.py — RetestReport aggregator + summary stats
  tool.py       — @function_tool retest_finding for the agent

Banca-safety: same double-gate as F87 (KRYON_RETEST_FIRE=true env +
fire=True kwarg). GET-only by default; mutations (POST/PUT/DELETE/
PATCH) require KRYON_RETEST_ALLOW_MUTATIONS=true. Stdlib only.
"""
