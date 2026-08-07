"""F2.3 — ``kryon scope`` subcommand (formal engagement scoping)."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


def add_scope_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("scope", help="F2.3 — Define/inspect a formal engagement scope")
    sub = p.add_subparsers(dest="scope_action", required=True)

    create = sub.add_parser("create", help="Create a signed scope.json")
    create.add_argument("--client", required=True)
    create.add_argument("--ips", default="", help="Comma-separated in-scope IPs/CIDRs")
    create.add_argument("--exclude", default="", help="Comma-separated excluded IPs/CIDRs")
    create.add_argument("--systems", default="", help="Free-text systems description (e.g. 'PCI: CDE')")
    create.add_argument("--authorized-by", default="", dest="authorized_by")
    create.add_argument("--notes", default="")
    create.add_argument("--out", default="scope.json", help="Output path (default: scope.json)")

    show = sub.add_parser("show", help="Show a scope and verify its integrity hash")
    show.add_argument("path")

    check = sub.add_parser("check", help="Is an IP in scope?")
    check.add_argument("path")
    check.add_argument("ip")
    return p


def _split(value: str) -> list[str]:
    return [s.strip() for s in value.split(",") if s.strip()]


def run_scope_command(args) -> int:
    from kryon.onboarding.scope import create_scope, is_in_scope, load_scope, save_scope, verify_scope

    action = args.scope_action

    if action == "create":
        scope = create_scope(
            args.client,
            _split(args.ips),
            exclude=_split(args.exclude),
            systems=args.systems,
            authorized_by=args.authorized_by,
            notes=args.notes,
            created_utc=datetime.now(timezone.utc).isoformat(),
        )
        path = save_scope(scope, Path(args.out))
        print(f"scope written → {path} (hash {scope.scope_hash[:12]})")
        return 0

    if action == "show":
        scope = load_scope(Path(args.path))
        ok = verify_scope(scope)
        print(f"client:        {scope.client}")
        print(f"ip_ranges:     {', '.join(scope.ip_ranges) or '-'}")
        print(f"exclude:       {', '.join(scope.exclude) or '-'}")
        print(f"systems:       {scope.systems or '-'}")
        print(f"authorized_by: {scope.authorized_by or '-'}")
        print(f"created_utc:   {scope.created_utc or '-'}")
        print(f"integrity:     {'OK' if ok else 'TAMPERED'} ({scope.scope_hash[:12]})")
        return 0 if ok else 1

    if action == "check":
        scope = load_scope(Path(args.path))
        inside = is_in_scope(scope, args.ip)
        print(f"{args.ip}: {'IN SCOPE' if inside else 'OUT OF SCOPE'}")
        return 0 if inside else 1

    print(f"scope: unknown action '{action}'", file=sys.stderr)
    return 2
