"""Summarise a Kryon audit JSONL file. One-off ops helper."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(path: str) -> None:
    p = Path(path)
    if not p.exists():
        print(f"not found: {path}")
        sys.exit(1)
    entries = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]
    print(f"Total entries: {len(entries)}")
    print(f"File size:     {p.stat().st_size} bytes")
    print()
    for i, e in enumerate(entries, 1):
        ts = e["timestamp"]
        phase = e["phase"]
        tool = e["tool_name"]
        ms = e["duration_ms"]
        status = e["status"]
        rc = e["redaction_count"]
        ah = e["args_hash"][:10]
        rh = e["result_hash"][:10]
        print(f"{i}. {ts} | phase={phase:14s} | tool={tool:32s} | {ms:>6}ms | {status:5} | redact={rc} | h={ah}/{rh}")
    print()
    print("Redaction totals (should be 0 if no PAN/CVV in target output):")
    total_redact = sum(e["redaction_count"] for e in entries)
    print(f"  total: {total_redact}")


if __name__ == "__main__":
    main(sys.argv[1])
