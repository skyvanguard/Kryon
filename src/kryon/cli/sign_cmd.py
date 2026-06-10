"""F3.2 — ``kryon sign`` subcommand (sign / verify report deliverables)."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path


def add_sign_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("sign", help="F3.2 — Sign or verify a report (detached Ed25519)")
    p.add_argument("file", help="Path to the report/deliverable")
    p.add_argument("--verify", action="store_true", help="Verify instead of sign")
    p.add_argument("--signer", default="", help="Signer name embedded in the signature")
    return p


def run_sign_command(args) -> int:
    from kryon.reporting.signing import ReportSigner, verify_signature

    path = Path(args.file)
    if not path.exists():
        print(f"sign: no such file '{path}'")
        return 1

    if args.verify:
        ok = verify_signature(path)
        print(f"signature: {'VALID' if ok else 'INVALID / missing'}")
        return 0 if ok else 1

    sidecar = ReportSigner().sign_file(path, signer=args.signer, timestamp=datetime.now(timezone.utc).isoformat())
    print(f"signed → {sidecar}")
    return 0
