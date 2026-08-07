"""F139 — ``kryon discover`` subcommand."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def add_discover_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("discover", help="F139 — Asset discovery (subnet + DNS + cloud)")
    p.add_argument("--subnet", default="", help="CIDR / IP range for nmap -sn sweep")
    p.add_argument("--domain", default="", help="Registered domain for crt.sh subdomain enum")
    p.add_argument("--output", default="", help="Write the report to JSON file (default: stdout)")
    p.add_argument("--queue-add", action="store_true", help="Also enqueue every target via kryon queue")
    return p


def run_discover_command(args) -> int:
    from kryon.discovery import (
        discover_subdomains,
        discover_subnet,
        merge_assets,
    )

    if not args.subnet and not args.domain:
        print("discover: pass --subnet and/or --domain", file=sys.stderr)
        return 2

    subnet_assets = discover_subnet(args.subnet) if args.subnet else []
    subdomain_assets = discover_subdomains(args.domain) if args.domain else []
    report = merge_assets(subnet_assets, subdomain_assets)

    payload = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
        print(f"wrote {report.to_dict()['count']} asset(s) → {args.output}")
    else:
        print(payload)

    if args.queue_add:
        from kryon.queue import EngagementQueue

        q = EngagementQueue.load()
        added = 0
        for target in report.to_targets():
            existing = q.add(target)
            if existing.queued_at:  # newly created have queued_at set in add()
                added += 1
        q.save()
        print(f"queued {added} new target(s)")

    return 0
