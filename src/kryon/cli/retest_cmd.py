"""F1.3 — ``kryon retest <target>`` — re-audit and report the remediation delta.

Re-runs ``kryon engage`` against a target that has a saved baseline, then emits
a DELTA deliverable (what got fixed, what's still open, what's new, % progress)
instead of a full report. Closes the remediation loop for the client.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_retest_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("retest", help="F1.3 — Re-audit a target and report the remediation delta")
    p.add_argument("target", help="Target host/IP previously audited (must have a saved baseline)")
    p.add_argument("--framework", default="", help="Comma-separated frameworks for engage --framework")
    p.add_argument("--client", default="", help="Client name (used in the delta deliverable)")
    p.add_argument("--out", default="", help="Output root (default: ~/.kryon/retests/<target>)")
    p.add_argument("--ssh-key", default="", help="SSH key path for the compliance runner")
    p.add_argument("--orchestrated", action="store_true", help="Pass --orchestrated to engage")
    p.add_argument("--auto-approve", action="store_true", help="Pass --auto-approve (lab/POC only)")
    p.add_argument("--engage-bin", default="", help="Override the kryon binary for the child engage call")
    p.add_argument("--format", default="xlsx", choices=["xlsx", "csv"], help="Action spreadsheet format")
    return p


def run_retest_command(args) -> int:
    from kryon.cli.queue_cmd import _build_engage_argv, _resolve_engage_bin, _run_one
    from kryon.state.baseline_diff import load_previous_findings
    from kryon.state.engagement_state import read_state, target_slug
    from kryon.state.retest import build_delta_report, format_delta_summary, write_delta_report

    if not args.target:
        print("retest: pass a target", file=sys.stderr)
        return 2

    # 1. Load the baseline (previous findings) for this target.
    prev_state = read_state(args.target)
    previous = load_previous_findings(prev_state.findings_path) if prev_state else []
    if not previous:
        print(
            f"retest: no baseline found for {args.target} — run `kryon engage {args.target}` first.",
            file=sys.stderr,
        )
        return 1
    print(f"baseline: {len(previous)} finding(s) from the previous run of {args.target}")

    # 2. Re-run engage against the same target.
    out_root = Path(args.out) if args.out else (Path.home() / ".kryon" / "retests" / target_slug(args.target))
    item_id = f"retest-{target_slug(args.target)}"
    out_dir = out_root / item_id
    argv = _build_engage_argv(
        engage_bin=_resolve_engage_bin(args.engage_bin),
        target=args.target,
        objective="",
        framework=args.framework,
        orchestrated=args.orchestrated,
        auto_approve=args.auto_approve,
        dry_run_only=False,
        out_dir=str(out_root),
        client=args.client,
        ssh_key=args.ssh_key,
        item_id=item_id,
    )
    print(f"re-auditing {args.target} → {out_dir}")
    _, rc, err = _run_one(argv, item_id)
    if rc != 0:
        print(f"retest: engage failed exit={rc} {err}", file=sys.stderr)
        return rc

    # 3. Load the fresh findings engage just wrote.
    fresh_files = sorted(out_dir.glob("*.findings.json"))
    current = load_previous_findings(str(fresh_files[0])) if fresh_files else []

    # 4. Build + write the delta deliverable.
    report = build_delta_report(previous, current)
    result = write_delta_report(report, out_dir, client_name=args.client, fmt=args.format)
    print(f"\n{format_delta_summary(report)}")
    print(f"  delta        → {result['delta_json']}")
    print(f"  action sheet → {result['action_sheet']}")
    return 0
