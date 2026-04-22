"""F13.1 — GnuCash Kryon detection scan (no LLM, no Joern).

Runs:
  1. Semgrep with upstream p/c + Kryon custom rules on top-N priority files.
  2. Heuristic regex patterns (ported from HeuristicHunter, no ASAN PoC).

Emits JSONL raw findings. One scan, fully deterministic.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent


# Heuristic patterns (reduced — C-only, high-confidence subset from F6.2/F6.3)
# Each: (regex_src, cwe, confidence)
HEURISTIC_PATTERNS: list[tuple[str, str, str]] = [
    (r"\bstrcpy\s*\([^,]+,\s*[^)]+\)", "CWE-121", "medium"),
    (r"\bstrcat\s*\([^,]+,\s*[^)]+\)", "CWE-121", "medium"),
    (r"\bsprintf\s*\(\s*\w+\s*,", "CWE-121", "medium"),
    (r"\bgets\s*\(\s*\w+\s*\)", "CWE-121", "high"),
    (r"\bmemcpy\s*\([^,]+,\s*[^,]+,\s*\w+\s*[+\-*/]\s*\w+\s*\)", "CWE-122", "medium"),
    (r"\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)", "CWE-190", "medium"),
    (r"\bsystem\s*\(\s*\w+\s*\)", "CWE-78", "high"),
    (r"\bpopen\s*\(\s*\w+", "CWE-78", "medium"),
    (r"\bprintf\s*\(\s*\w+\s*\)", "CWE-134", "medium"),
    (r"\bfree\s*\([^)]+\)\s*;[\s\S]{0,80}\bfree\s*\(", "CWE-415", "low"),
    (r"->(\w+)\s*=\s*NULL[\s\S]{0,40}->\1->", "CWE-476", "medium"),
]


def run_semgrep(
    target_files: list[str],
    semgrep_image: str = "returntocorp/semgrep:latest",
    kryon_rules_host: str = "/c/Users/skyva/Documents/Kryon/scripts/f13/kryon_rules_c",
    workspace_host: str = "/c/Users/skyva/Documents/Kryon/scripts/f13/workspace",
) -> list[dict[str, Any]]:
    """Run semgrep on the top-N file list. Returns normalized findings.

    We pass both upstream p/c (registry) and Kryon custom rules (local mount).
    """
    out_host = HERE / "kryon_scan"
    out_host.mkdir(exist_ok=True)
    manifest = out_host / "gnucash-target-files.txt"
    manifest.write_text("\n".join(target_files), encoding="utf-8")

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{workspace_host}:/src:ro",
        "-v", f"{kryon_rules_host}:/kryon-rules:ro",
        "-v", f"{HERE / 'kryon_scan'}:/out",
        "-e", "MSYS_NO_PATHCONV=1",
        semgrep_image,
        "semgrep",
        "--config=p/c",
        "--config=/kryon-rules",
        "--json",
        "-o", "/out/gnucash-kryon-semgrep.json",
        *[f"/src/gnucash/{f}" for f in target_files],
    ]
    print(f"Running semgrep on {len(target_files)} files...")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if proc.returncode not in (0, 1):
        print(f"semgrep non-zero returncode {proc.returncode}")
        print(proc.stderr[:500])
    out = json.loads((out_host / "gnucash-kryon-semgrep.json").read_text(encoding="utf-8"))
    findings = []
    for r in out.get("results", []):
        findings.append({
            "_hunter": "semgrep-kryon",
            "file_path": r.get("path", "").replace("/src/gnucash/", ""),
            "line_start": r.get("start", {}).get("line", 0),
            "line_end": r.get("end", {}).get("line", 0),
            "rule_id": r.get("check_id", ""),
            "severity": (r.get("extra", {}) or {}).get("severity", ""),
            "message": ((r.get("extra", {}) or {}).get("message") or "")[:300],
            "cwe": _extract_cwe_from_metadata(r.get("extra", {}) or {}),
        })
    errors = out.get("errors", [])
    return findings, errors


def _extract_cwe_from_metadata(extra: dict) -> str:
    meta = extra.get("metadata") or {}
    cwe = meta.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0]).split(":")[0].strip()
    if isinstance(cwe, str):
        return cwe.split(":")[0].strip()
    return ""


def run_heuristic(target_files: list[str], repo_root: Path) -> list[dict[str, Any]]:
    findings = []
    compiled = [(re.compile(src), cwe, conf) for src, cwe, conf in HEURISTIC_PATTERNS]
    for rel in target_files:
        fpath = repo_root / rel
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen_per_file: set[tuple[str, str]] = set()
        for regex, cwe, conf in compiled:
            for m in regex.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                key = (cwe, str(line_no))
                if key in seen_per_file:
                    continue
                seen_per_file.add(key)
                findings.append({
                    "_hunter": "heuristic",
                    "file_path": rel,
                    "line_start": line_no,
                    "line_end": line_no,
                    "rule_id": f"heuristic.{cwe.lower()}",
                    "severity": "WARNING",
                    "message": f"{cwe} pattern match: {m.group(0)[:80]}",
                    "cwe": cwe,
                    "confidence": conf,
                })
                if len(seen_per_file) >= 8:  # cap per file
                    break
    return findings


def main() -> None:
    priority_json = HERE / "priority" / "gnucash-priority-top200.json"
    if not priority_json.is_file():
        print(f"missing priority file: {priority_json}")
        sys.exit(1)
    top = json.loads(priority_json.read_text(encoding="utf-8"))["top"]
    target_files = [e["file"] for e in top]
    print(f"Target: {len(target_files)} files")

    sem_findings, sem_errors = run_semgrep(target_files)
    print(f"Semgrep: {len(sem_findings)} findings, {len(sem_errors)} errors")

    repo = HERE / "workspace" / "gnucash"
    heur_findings = run_heuristic(target_files, repo)
    print(f"Heuristic: {len(heur_findings)} findings")

    all_findings = sem_findings + heur_findings

    out_dir = REPO_ROOT / "docs" / "bench_results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "f13_gnucash_raw.jsonl"
    with out_path.open("w", encoding="utf-8") as f:
        for fnd in all_findings:
            f.write(json.dumps(fnd, ensure_ascii=False) + "\n")
    print(f"Wrote {len(all_findings)} findings to {out_path}")

    # Also dump semgrep errors for the parse-failure analysis
    err_path = out_dir / "f13_gnucash_semgrep_errors.json"
    err_path.write_text(json.dumps(sem_errors, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
