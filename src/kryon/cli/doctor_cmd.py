"""F142 — ``kryon doctor`` + ``kryon heartbeat`` subcommands."""

from __future__ import annotations

import argparse
import json
import sys


def add_doctor_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("doctor", help="F142 — Health check Kryon (dirs, env, Ollama, heartbeat)")
    p.add_argument("--no-ollama", action="store_true", help="Skip Ollama probe")
    p.add_argument("--heartbeat-threshold", type=int, default=10, help="Stale threshold in minutes")
    p.add_argument("--format", choices=("table", "json"), default="table")
    p.add_argument("--fail-on-stale", action="store_true", help="Exit non-zero if any check fails")
    return p


def add_heartbeat_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("heartbeat", help="F142 — Update the Kryon heartbeat file")
    return p


def run_doctor_command(args) -> int:
    from kryon.health import run_doctor

    results = run_doctor(
        heartbeat_threshold_minutes=args.heartbeat_threshold,
        check_ollama=not args.no_ollama,
    )
    if args.format == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        for r in results:
            symbol = "✓" if r.ok else "✕"
            print(f"  [{symbol}] {r.name:24s}  {r.detail}")
    if args.fail_on_stale and any(not r.ok for r in results):
        return 1
    return 0


def run_heartbeat_command(args) -> int:
    from kryon.health import write_heartbeat

    p = write_heartbeat()
    if p is None:
        print("heartbeat write failed", file=sys.stderr)
        return 1
    print(f"heartbeat updated → {p}")
    return 0
