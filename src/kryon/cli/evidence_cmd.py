"""F2.4 — ``kryon evidence`` subcommand (attach/inspect audit artifacts)."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


def add_evidence_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("evidence", help="F2.4 — Manage engagement evidence artifacts")
    sub = p.add_subparsers(dest="evidence_action", required=True)

    add = sub.add_parser("add", help="Attach an artifact to a finding")
    add.add_argument("--engagement-dir", required=True, dest="engagement_dir")
    add.add_argument("--finding", required=True)
    add.add_argument("--name", required=True)
    g = add.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="Inline text content (config snippet, log excerpt)")
    g.add_argument("--file", help="Path to a file/screenshot to attach")

    listp = sub.add_parser("list", help="List stored evidence")
    listp.add_argument("--engagement-dir", required=True, dest="engagement_dir")

    verify = sub.add_parser("verify", help="Re-hash artifacts and verify integrity")
    verify.add_argument("--engagement-dir", required=True, dest="engagement_dir")
    return p


def run_evidence_command(args) -> int:
    from kryon.evidence.store import EvidenceStore

    store = EvidenceStore(Path(args.engagement_dir))
    action = args.evidence_action

    if action == "add":
        stamp = datetime.now(timezone.utc).isoformat()
        if args.text is not None:
            item = store.add_text(args.finding, args.name, args.text, captured_utc=stamp)
        else:
            data = Path(args.file).read_bytes()
            kind = "screenshot" if Path(args.file).suffix.lower() in (".png", ".jpg", ".jpeg") else "file"
            item = store.add_bytes(args.finding, args.name, data, kind=kind, captured_utc=stamp)
        print(f"attached '{item.name}' to {item.finding_id} (sha256 {item.sha256[:12]})")
        return 0

    if action == "list":
        items = store.items()
        if not items:
            print("(no evidence)")
            return 0
        for it in items:
            print(f"  {it.finding_id}  {it.name}  ({it.kind})  sha256={it.sha256[:12]}")
        return 0

    if action == "verify":
        ok = store.verify()
        print("evidence integrity: OK" if ok else "evidence integrity: TAMPERED")
        return 0 if ok else 1

    print(f"evidence: unknown action '{action}'", file=sys.stderr)
    return 2
