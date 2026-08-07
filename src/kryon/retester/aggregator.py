"""F88 — Multi-finding retest aggregator.

Given a list of RetestVerdict (one per finding replayed), produce a
RetestReport that:

  - Counts verdicts by bucket (still_open, fixed, changed, regressed,
    error, dry_run).
  - Surfaces still_open + regressed entries explicitly — those are
    the actionable items for the retest follow-up.
  - Computes a fix_rate (fixed / (fixed + still_open + regressed))
    so the report has a single headline number to share with the
    client. dry_run and error verdicts are excluded from the
    denominator — they don't speak to whether anything was actually
    fixed.

Pure data, no I/O. Same shape philosophy as F86 CyberGym's scorer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kryon.retester.comparator import RetestVerdict

__all__ = ["RetestReport", "aggregate_retest"]


@dataclass(frozen=True)
class RetestReport:
    """Aggregated outcome over a batch of replays."""

    total: int
    by_verdict: dict[str, int] = field(default_factory=dict)
    fix_rate: float = 0.0  # 0..1; excludes dry_run + error from denom
    still_open: tuple[RetestVerdict, ...] = field(default_factory=tuple)
    regressed: tuple[RetestVerdict, ...] = field(default_factory=tuple)


_DECISIVE_VERDICTS = {"fixed", "still_open", "regressed"}


def aggregate_retest(verdicts: list[RetestVerdict]) -> RetestReport:
    """Roll up a list of RetestVerdict into a RetestReport.

    fix_rate denominator covers only decisive verdicts so a batch
    that's 100% dry_run doesn't report fix_rate=0 (which would look
    catastrophic on the headline). Empty verdict list → empty report
    with fix_rate=0.0 (well-defined, no division by zero)."""
    by_verdict: dict[str, int] = {}
    still_open: list[RetestVerdict] = []
    regressed: list[RetestVerdict] = []

    for v in verdicts:
        by_verdict[v.verdict] = by_verdict.get(v.verdict, 0) + 1
        if v.verdict == "still_open":
            still_open.append(v)
        elif v.verdict == "regressed":
            regressed.append(v)

    decisive = sum(by_verdict.get(k, 0) for k in _DECISIVE_VERDICTS)
    fix_rate = (by_verdict.get("fixed", 0) / decisive) if decisive else 0.0

    return RetestReport(
        total=len(verdicts),
        by_verdict=by_verdict,
        fix_rate=fix_rate,
        still_open=tuple(still_open),
        regressed=tuple(regressed),
    )
