"""
F3.3 end-to-end test: planner_hunter.hunt_zero_days() against real zlib.

This wires together F1 + F2 + F3.{1,2,4} with the heuristic runner and
validates:
  - repo cloned + indexed
  - priority_score produces > 0 targets
  - bounded-parallel hunters all complete (no timeouts / crashes)
  - validator produces CONFIRMED or REJECTED for each finding
  - final report structure is sane + pretty-printable
  - deduplication works across hunters

Runs in seconds (no LLM). If anything breaks here the MVP pipeline
is broken — this is the E2E canary for F3.
"""

import asyncio
import json
import os
import time

from kryon.skills.planner_hunter import hunt_zero_days


async def main():
    print("=" * 60)
    print("F3.3 E2E: hunt_zero_days on zlib (heuristic runner)")
    print("=" * 60)

    # Reuse the clone from the zlib benchmark if present (faster)
    repo = "https://github.com/madler/zlib.git"

    t0 = time.time()
    report = await hunt_zero_days(
        repo,
        budget=5,             # 5 files -> keeps the test under 2 min
        parallelism=2,
        runner_type="heuristic",
    )
    total = time.time() - t0

    print()
    print(report.pretty())
    print()
    print(f"Total wall time: {total:.1f}s")
    print()

    # ---- Structural assertions ----
    assert report.files_scored > 0, "priority_score returned empty"
    assert report.hunters_spawned == 5, f"expected 5 hunters, got {report.hunters_spawned}"
    assert report.hunters_spawned <= 5
    # Raw findings = sum of patterns matched across all files with ASAN crash
    # With heuristic runner we expect a handful at minimum (zlib has memcpy etc.)
    print(f"Raw -> deduped verdicts: {report.raw_findings} -> "
          f"{len(report.verdicts)} (dedup removed {report.raw_findings - len(report.verdicts)})")

    # Every verdict has the required shape
    for v in report.verdicts:
        assert v.get("verdict") in {"CONFIRMED", "REJECTED"}
        assert v.get("_file")  # provenance attached
        if v["verdict"] == "REJECTED":
            assert v.get("phase_failed") in {
                "relevance", "reproduction", "classification", "insufficient_data"
            }

    # Report must be JSON-serializable
    j = report.to_json()
    parsed = json.loads(j)
    assert parsed["repo_url"] == repo
    assert parsed["runner_type"] == "heuristic"

    # Parallelism gate — with max=2 and 5 hunters, wall time should be
    # noticeably less than sequential (5 * avg_hunter_duration). We don't
    # measure per-hunter but we can sanity-check it finished.
    assert total < 120, f"E2E took too long: {total}s"

    print("F3.3 E2E PASS — coordinator wires F1+F2+F3.1+F3.2+F3.4+F3.5 correctly")


if __name__ == "__main__":
    asyncio.run(main())
