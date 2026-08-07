"""Regression for planner_hunter severity/dedup bugs found in the skills review.

- _SEV_RANK only knew INFO/WARNING/ERROR, so a MEDIUM (ASAN-confirmed crash from
  HeuristicHunter) fell to rank 0 and was overwritten by a WARNING in the merge.
- The semgrep dedup key (cwe, rule_id) had no line component, so the same rule
  firing at distinct call sites in one file collapsed to a single finding.
"""

from __future__ import annotations

from kryon.skills.planner_hunter import _DEDUP_LINE_RADIUS, _SEV_RANK


def test_sev_rank_understands_standard_tiers_above_semgrep():
    # ASAN-confirmed MEDIUM must not lose to a semgrep WARNING/INFO in the merge.
    assert _SEV_RANK["MEDIUM"] > _SEV_RANK["WARNING"]
    assert _SEV_RANK["MEDIUM"] > _SEV_RANK["INFO"]
    assert _SEV_RANK["CRITICAL"] > _SEV_RANK["ERROR"]
    assert _SEV_RANK["CRITICAL"] > _SEV_RANK["HIGH"] > _SEV_RANK["MEDIUM"] > _SEV_RANK["LOW"]


def test_dedup_line_bucket_separates_distinct_call_sites():
    r = _DEDUP_LINE_RADIUS
    bucket = lambda n: n // (r * 2 + 1)  # noqa: E731
    # Three distinct strcpy() call sites → three findings, not one.
    assert len({bucket(10), bucket(50), bucket(90)}) == 3
    # Near-duplicate reports of the SAME sink (line N vs N+1) still fold.
    assert bucket(10) == bucket(11)
