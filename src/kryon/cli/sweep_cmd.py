"""F1.2 — ``kryon sweep <CIDR>`` — one-command multi-host audit.

Ergonomic sugar over the F196 discover→queue→process→consolidate flow: discover
live hosts in a segment, run ``kryon engage`` against each (writing per-host
output under ``--out``), then consolidate everything into ONE client deliverable
(spreadsheet + segment summary). Banca-safe: serial by default, read-only
discovery, each engage keeps its own throttle/guardrails.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_sweep_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("sweep", help="F1.2 — One-command multi-host audit of a segment")
    p.add_argument("subnet", help="CIDR / IP range to sweep (e.g. 10.0.0.0/24)")
    p.add_argument("--framework", default="", help="Comma-separated frameworks for engage --framework")
    p.add_argument("--client", default="", help="Client name (used in the consolidated deliverable)")
    p.add_argument("--out", default="", help="Output root (default: ~/.kryon/sweeps/<subnet>)")
    p.add_argument("--orchestrated", action="store_true", help="Pass --orchestrated to each engage")
    p.add_argument("--auto-approve", action="store_true", help="Pass --auto-approve (lab/POC only)")
    p.add_argument("--ssh-key", default="", help="SSH key path for the compliance runner")
    p.add_argument("--engage-bin", default="", help="Override the kryon binary for child engage calls")
    p.add_argument("--format", default="xlsx", choices=["xlsx", "csv"], help="Consolidated spreadsheet format")
    p.add_argument("--limit", type=int, default=0, help="Stop after N hosts (0 = all)")
    return p


def _default_out(subnet: str) -> Path:
    from kryon.state.engagement_state import target_slug

    return Path.home() / ".kryon" / "sweeps" / target_slug(subnet)


def run_sweep_command(args) -> int:
    from kryon.cli.queue_cmd import _build_engage_argv, _resolve_engage_bin, _run_one, default_item_timeout
    from kryon.discovery import discover_subnet, merge_assets
    from kryon.reporting.consolidate import consolidate_engagement_dir
    from kryon.state.engagement_state import target_slug

    if not args.subnet:
        print("sweep: pass a CIDR/IP range", file=sys.stderr)
        return 2

    out_root = Path(args.out) if args.out else _default_out(args.subnet)
    out_root.mkdir(parents=True, exist_ok=True)

    print(f"discovering live hosts in {args.subnet} ...")
    report = merge_assets(discover_subnet(args.subnet), [])
    targets = report.to_targets()
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        print("no live hosts discovered.")
        return 0
    print(f"found {len(targets)} host(s); auditing serially → {out_root}")

    engage_bin = _resolve_engage_bin(args.engage_bin)
    succeeded = 0
    failed = 0
    for i, target in enumerate(targets):
        item_id = f"sweep-{i:03d}-{target_slug(target)}"
        argv = _build_engage_argv(
            engage_bin=engage_bin,
            target=target,
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
        print(f"  → {target} ({item_id})")
        _, rc, err = _run_one(argv, item_id, timeout=default_item_timeout())
        if rc == 0:
            print("    ✓ done")
            succeeded += 1
        else:
            print(f"    ✗ failed exit={rc} {err}")
            failed += 1

    result = consolidate_engagement_dir(out_root, client_name=args.client, fmt=args.format)
    summary = result["summary"]
    print(
        f"\nconsolidated: {summary['total_findings']} finding(s) across "
        f"{summary['host_count']} host(s) (succeeded={succeeded}, failed={failed})"
    )
    print(f"  spreadsheet → {result['spreadsheet']}")
    print(f"  summary     → {result['summary_json']}")
    return 0 if failed == 0 else 1
