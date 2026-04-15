"""F13.1 closing — Fineract semgrep JSON → JSONL raw (trivial reformat).

Kryon engine for Java == vanilla semgrep (no custom rules, hardcoded C
in SemgrepHunter). Raw detection for Fineract is the F13.0 baseline.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
IN = HERE / "semgrep" / "fineract-semgrep.json"
OUT = REPO_ROOT / "docs" / "bench_results" / "f13_fineract_raw.jsonl"


def main() -> None:
    d = json.loads(IN.read_text(encoding="utf-8"))
    findings = []
    for r in d.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        cwe_raw = meta.get("cwe")
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe = str(cwe_raw[0]).split(":")[0].strip()
        elif isinstance(cwe_raw, str):
            cwe = cwe_raw.split(":")[0].strip()
        else:
            cwe = ""
        findings.append({
            "_hunter": "semgrep-upstream",
            "file_path": r.get("path", "").replace("/src/fineract/", ""),
            "line_start": r.get("start", {}).get("line", 0),
            "line_end": r.get("end", {}).get("line", 0),
            "rule_id": r.get("check_id", ""),
            "severity": extra.get("severity", ""),
            "message": (extra.get("message") or "").strip()[:300],
            "cwe": cwe,
        })
    with OUT.open("w", encoding="utf-8") as f:
        for fnd in findings:
            f.write(json.dumps(fnd, ensure_ascii=False) + "\n")
    print(f"Wrote {len(findings)} findings to {OUT}")


if __name__ == "__main__":
    main()
