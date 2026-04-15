"""F9.0 — dump every hybrid FP on the baseline corpus for manual triage.

Same 100-file sample the F6 recalibration used (first 100 .c under
/workspace/sources). For each finding, record file, rule_id, cwe, line,
snippet (±2 lines). Writes JSON so classification can be offline.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

os.environ["KRYON_HYBRID_MAX_LLM_CANDIDATES"] = "0"
os.environ.setdefault("KRYON_JOERN_ENABLED", "false")

from kryon.skills.planner_hunter import HybridHunter, _reset_hybrid_budget
from kryon.skills.supervisor_tools import HunterJob


def snippet(path: str, line: int, ctx: int = 2) -> str:
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if line <= 0 or line > len(lines):
        return ""
    lo = max(0, line - 1 - ctx)
    hi = min(len(lines), line + ctx)
    out = []
    for i in range(lo, hi):
        marker = ">" if i == line - 1 else " "
        out.append(f"{marker}{i+1:>5}: {lines[i][:100]}")
    return "\n".join(out)


async def main():
    root = Path(os.environ.get("KRYON_BASELINE_ROOT", "/workspace/sources"))
    n = int(os.environ.get("KRYON_BASELINE_N", "100"))
    files: list[Path] = []
    for ext in ("*.c",):
        files.extend(root.rglob(ext))
    files = files[:n]
    print(f"[F9.0] scanning {len(files)} baseline files...")

    _reset_hybrid_budget()
    runner = HybridHunter()

    all_fps: list[dict] = []
    for fp in files:
        job = HunterJob(hunter_id="f9", file_path=str(fp))
        try:
            findings = await asyncio.wait_for(runner(job), timeout=60)
        except Exception:
            findings = []
        for f in findings:
            raw_lr = (f.get("line_range") or "").lstrip("~").strip()
            line = 0
            try:
                line = int(raw_lr.split("-")[0]) if raw_lr else 0
            except ValueError:
                line = 0
            # Heuristic emits _pattern (regex source); semgrep emits _semgrep_rule_id
            rule_id = (
                f.get("_semgrep_rule_id")
                or f.get("_pattern")
                or f.get("_joern_rule_id")
                or ""
            )
            all_fps.append({
                "file": str(fp.relative_to(root)) if root in fp.parents else str(fp),
                "line": line,
                "cwe": f.get("cwe", ""),
                "cwe_aliases": f.get("cwe_aliases") or [],
                "rule_id": rule_id[:80],
                "hunter": f.get("_hunter", ""),
                "message": (f.get("_semgrep_message") or "")[:200],
                "snippet": snippet(str(fp), line),
                "severity": f.get("severity", ""),
            })

    out = Path("/workspace/f9_fps.json")
    out.write_text(json.dumps({
        "n_files": len(files),
        "n_fps": len(all_fps),
        "findings": all_fps,
    }, indent=2))
    print(f"wrote {out}  ({len(all_fps)} FP findings)")

    # Quick stats
    from collections import Counter
    by_rule = Counter(f["rule_id"] for f in all_fps)
    by_cwe = Counter(f["cwe"] for f in all_fps)
    by_hunter = Counter(f["hunter"] for f in all_fps)
    print("\nBy rule_id (top 15):")
    for r, c in by_rule.most_common(15):
        print(f"  {c:4d}  {r}")
    print("\nBy CWE:")
    for c_, c in by_cwe.most_common():
        print(f"  {c:4d}  {c_}")
    print("\nBy hunter:")
    for h, c in by_hunter.most_common():
        print(f"  {c:4d}  {h}")


if __name__ == "__main__":
    asyncio.run(main())
