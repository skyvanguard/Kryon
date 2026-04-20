"""Compliance framework regression harness (F45).

Loads every registered YAML framework, computes a structural inventory
snapshot (per-framework check counts by section + severity, YAML content
hash, cross-mapping consistency), and either:

  * ``--emit``  : writes the snapshot as a new baseline JSON
  * ``--check`` : compares current state against an existing baseline
                  and exits non-zero on any ratchet-down regression

A ratchet-down regression is any of:

  - Total check count decreased
  - Severity distribution shifted toward lower severity silently
  - A framework was removed
  - A section lost all its checks
  - A cross-framework mapping references a framework that no longer
    exists in ``FRAMEWORK_META``

Content-hash changes alone are NOT failures — they indicate legitimate
additions/edits. But the per-framework counts must never decrease
without an explicit baseline update (emit step).

Usage
-----

    # Refresh baseline after intentional changes:
    python scripts/compliance/regression_bench.py --emit

    # CI check (fail on regression):
    python scripts/compliance/regression_bench.py --check

    # Diff summary only:
    python scripts/compliance/regression_bench.py --diff
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from kryon.compliance.cis import (  # noqa: E402
    available_frameworks,
    load_framework,
)

BASELINE_PATH = REPO / "tests/compliance/baselines/regression_baseline.json"


def _yaml_sha256(path: Path) -> str:
    """Hash YAML file contents to detect silent edits."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def framework_inventory(path: Path) -> dict[str, Any]:
    """Build the structural snapshot for one framework YAML.

    Stores just enough to catch regressions without coupling to individual
    check titles (those change too often and aren't regression-relevant).
    """
    fw = load_framework(path)
    sections = Counter(c.section.split(".", 1)[0] for c in fw.checks)
    severities = Counter(c.severity for c in fw.checks)
    # Commands with real body (not just 'true' or empty) — catches mass
    # stub-out regressions.
    non_stub = sum(1 for c in fw.checks if len(c.command.strip()) > 8)
    return {
        "id": fw.metadata.id,
        "version": fw.metadata.version,
        "yaml_sha256": _yaml_sha256(path),
        "total_checks": len(fw.checks),
        "non_stub_commands": non_stub,
        "sections": dict(sorted(sections.items())),
        "severities": dict(sorted(severities.items())),
    }


def build_snapshot() -> dict[str, Any]:
    """Build the full multi-framework inventory snapshot."""
    inv: dict[str, Any] = {}
    for path in available_frameworks():
        entry = framework_inventory(path)
        inv[entry["id"]] = entry

    # Cross-mapping sanity: every framework referenced in CROSS_MAPPINGS
    # must exist in the inventory.
    try:
        from kryon.reporting.multi_framework_pdf import (
            CROSS_MAPPINGS,
            FRAMEWORK_META,
        )
    except ImportError:
        CROSS_MAPPINGS = []
        FRAMEWORK_META = {}

    cross_refs = {fw for m in CROSS_MAPPINGS for fw in m["frameworks"]}
    meta_refs = set(FRAMEWORK_META)
    orphan_cross = sorted(r for r in cross_refs if r not in inv)
    orphan_meta = sorted(r for r in meta_refs if r not in inv)

    return {
        "frameworks": inv,
        "totals": {
            "frameworks": len(inv),
            "checks": sum(e["total_checks"] for e in inv.values()),
            "critical_checks": sum(
                e["severities"].get("CRITICAL", 0) for e in inv.values()
            ),
        },
        "cross_mapping_refs": sorted(cross_refs),
        "framework_meta_refs": sorted(meta_refs),
        "orphans": {
            "cross_mapping": orphan_cross,
            "framework_meta": orphan_meta,
        },
    }


def compare(
    current: dict[str, Any],
    baseline: dict[str, Any],
) -> list[str]:
    """Return a list of regression messages. Empty list = clean."""
    problems: list[str] = []

    cur_fws = set(current["frameworks"])
    base_fws = set(baseline["frameworks"])

    # Framework removed?
    for missing in sorted(base_fws - cur_fws):
        problems.append(f"framework removed: {missing}")

    # New frameworks are fine (additive).
    for new in sorted(cur_fws - base_fws):
        # Not a regression — just informational when using --diff.
        pass

    # Per-framework ratchet-down checks.
    for fw_id in sorted(cur_fws & base_fws):
        cur = current["frameworks"][fw_id]
        base = baseline["frameworks"][fw_id]

        if cur["total_checks"] < base["total_checks"]:
            problems.append(
                f"{fw_id}: total checks dropped "
                f"{base['total_checks']} → {cur['total_checks']}"
            )

        if cur["non_stub_commands"] < base["non_stub_commands"]:
            problems.append(
                f"{fw_id}: non-stub commands dropped "
                f"{base['non_stub_commands']} → {cur['non_stub_commands']} "
                f"(commands being stubbed out silently?)"
            )

        # Severity ratchet: CRITICAL + HIGH combined must not decrease.
        cur_hi = cur["severities"].get("CRITICAL", 0) + cur["severities"].get("HIGH", 0)
        base_hi = base["severities"].get("CRITICAL", 0) + base["severities"].get("HIGH", 0)
        if cur_hi < base_hi:
            problems.append(
                f"{fw_id}: CRITICAL+HIGH severity count dropped "
                f"{base_hi} → {cur_hi}"
            )

        # Section coverage: no section should go from >0 to 0.
        for section, base_count in base["sections"].items():
            cur_count = cur["sections"].get(section, 0)
            if base_count > 0 and cur_count == 0:
                problems.append(
                    f"{fw_id}: section {section} emptied ({base_count} → 0)"
                )

    # Totals ratchet-down.
    if current["totals"]["checks"] < baseline["totals"]["checks"]:
        problems.append(
            f"total checks across all frameworks dropped "
            f"{baseline['totals']['checks']} → {current['totals']['checks']}"
        )
    if current["totals"]["critical_checks"] < baseline["totals"]["critical_checks"]:
        problems.append(
            f"total CRITICAL checks dropped "
            f"{baseline['totals']['critical_checks']} → "
            f"{current['totals']['critical_checks']}"
        )

    # Cross-mapping orphans — always a bug, even in baseline mode.
    if current["orphans"]["cross_mapping"]:
        problems.append(
            f"cross-mapping orphans (refs to non-existent frameworks): "
            f"{current['orphans']['cross_mapping']}"
        )
    if current["orphans"]["framework_meta"]:
        problems.append(
            f"FRAMEWORK_META orphans: {current['orphans']['framework_meta']}"
        )

    return problems


def print_diff(current: dict[str, Any], baseline: dict[str, Any]) -> None:
    """Human-readable diff summary (stdout)."""
    cur_fws = set(current["frameworks"])
    base_fws = set(baseline["frameworks"])
    added = sorted(cur_fws - base_fws)
    removed = sorted(base_fws - cur_fws)
    print(f"frameworks: {len(base_fws)} → {len(cur_fws)}")
    if added:
        print(f"  + {added}")
    if removed:
        print(f"  - {removed}")
    print(
        f"checks: {baseline['totals']['checks']} → "
        f"{current['totals']['checks']}"
    )
    print(
        f"CRITICAL: {baseline['totals']['critical_checks']} → "
        f"{current['totals']['critical_checks']}"
    )
    for fw_id in sorted(cur_fws & base_fws):
        cur = current["frameworks"][fw_id]
        base = baseline["frameworks"][fw_id]
        if cur["total_checks"] != base["total_checks"]:
            print(
                f"  {fw_id}: {base['total_checks']} → {cur['total_checks']} "
                f"(Δ {cur['total_checks'] - base['total_checks']:+d})"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Compliance framework regression harness")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--emit", action="store_true", help="Write new baseline")
    mode.add_argument("--check", action="store_true", help="Compare against baseline (CI)")
    mode.add_argument("--diff", action="store_true", help="Human-readable diff only")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=BASELINE_PATH,
        help="Baseline JSON path",
    )
    args = parser.parse_args()

    current = build_snapshot()

    if args.emit:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(
            json.dumps(current, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Baseline written: {args.baseline}")
        print(
            f"  frameworks: {current['totals']['frameworks']}, "
            f"checks: {current['totals']['checks']}, "
            f"CRITICAL: {current['totals']['critical_checks']}"
        )
        return 0

    if not args.baseline.exists():
        print(f"ERROR: baseline not found at {args.baseline}", file=sys.stderr)
        print("Run with --emit first.", file=sys.stderr)
        return 2

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))

    if args.diff:
        print_diff(current, baseline)
        return 0

    # --check mode: fail on regression
    problems = compare(current, baseline)
    if problems:
        print("COMPLIANCE REGRESSION DETECTED", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            f"\nIf these changes are intentional, refresh the baseline:\n"
            f"  python {Path(__file__).relative_to(REPO)} --emit",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {current['totals']['frameworks']} frameworks, "
        f"{current['totals']['checks']} checks "
        f"({current['totals']['critical_checks']} CRITICAL) — no regression"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
