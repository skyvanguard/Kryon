"""Quick helper to dump findings.json fields. One-off ops use."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(path: str) -> None:
    p = Path(path)
    if not p.exists():
        print(f"not found: {path}")
        sys.exit(1)
    data = json.loads(p.read_text(encoding="utf-8"))
    findings = data.get("findings", []) if isinstance(data, dict) else data
    print(f"Findings count: {len(findings)}")
    print()
    for f in findings:
        rule_id = f.get("rule_id", "?")
        sev = f.get("severity", "?")
        conf = f.get("confidence", "?")
        needs = f.get("needs_verification", "?")
        host = f.get("host", "?")
        msg = (f.get("message", "") or "")[:80]
        print(f"  - rule_id={rule_id}")
        print(f"      sev={sev}  host={host}  confidence={conf}  needs_verification={needs}")
        print(f"      message: {msg}")
        print()


if __name__ == "__main__":
    main(sys.argv[1])
