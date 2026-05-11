"""F13.2 — per-category sample + labeling worksheet.

Splits the GnuCash raw JSONL by CWE/hunter category, applies deterministic
sampling (seed=42), and emits a markdown worksheet with code context for
each sampled finding so labeling can be performed with evidence visible.

Categories (per F13.2 gate):
  - CWE-476 (null-deref): sample 30 of 143
  - CWE-121 (buf overflow): all 17
  - CWE-190 (int overflow): all 3
  - Heuristic (other patterns): sample 15 of 16
  - Tag test-file leak separately (parallel dimension)
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
CORPUS = HERE / "workspace" / "gnucash"
RAW = REPO_ROOT / "docs" / "bench_results" / "f13_gnucash_raw.jsonl"
OUT = REPO_ROOT / "docs" / "bench_results" / "f13_gnucash_labeling_worksheet.md"

SAMPLES = {
    "CWE-476": 30,
    "CWE-121": None,  # all
    "CWE-190": None,  # all
    "heuristic-other": 15,
}

SEED = 42


def is_test_file(path: str) -> bool:
    p = path.lower()
    return "/test/" in p or "/tests/" in p or p.startswith("test/")


def read_context(file_rel: str, line: int, radius: int = 8) -> str:
    fpath = CORPUS / file_rel
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "<file not readable>"
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    rendered = []
    for i in range(start, end):
        marker = ">>> " if (i + 1) == line else "    "
        rendered.append(f"{marker}{i+1:5d}  {lines[i]}")
    return "\n".join(rendered)


def categorize(finding: dict) -> str:
    cwe = finding.get("cwe", "")
    hunter = finding.get("_hunter", "")
    if cwe in ("CWE-476", "CWE-121", "CWE-190"):
        return cwe
    if hunter == "heuristic":
        return "heuristic-other"
    return "other"


def main() -> None:
    findings = [json.loads(l) for l in RAW.read_text(encoding="utf-8").splitlines()]
    # Index
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for i, f in enumerate(findings):
        f["_idx"] = i
        f["_is_test"] = is_test_file(f.get("file_path", ""))
        by_cat[categorize(f)].append(f)

    # Sample
    rng = random.Random(SEED)
    sampled: dict[str, list[dict]] = {}
    for cat, cap in SAMPLES.items():
        pool = by_cat.get(cat, [])
        if cap is None or len(pool) <= cap:
            sampled[cat] = list(pool)
        else:
            sampled[cat] = rng.sample(pool, cap)

    # Worksheet
    lines = [
        "# F13.2 — GnuCash labeling worksheet",
        "",
        "Seed: 42 (deterministic). Repo: gnucash@9f8f4d9e.",
        "",
        "## Summary",
        "",
        "| Category | Pool | Sampled | Test-files in sample |",
        "|----------|------|---------|----------------------|",
    ]
    for cat in SAMPLES:
        pool = by_cat.get(cat, [])
        samp = sampled.get(cat, [])
        test_n = sum(1 for f in samp if f["_is_test"])
        lines.append(f"| {cat} | {len(pool)} | {len(samp)} | {test_n} |")

    lines.append("")
    lines.append("## Labeling scheme")
    lines.append("")
    lines.append("- **TP**: real vulnerability or suspicious code worth investigation.")
    lines.append("- **FP**: rule matched but code is safe (sentinel-NULL check, dead code, test harness, etc.).")
    lines.append("- **UNK**: cannot determine without more context (mark rare).")
    lines.append("")

    for cat, samp in sampled.items():
        lines.append(f"## Category: {cat}")
        lines.append("")
        for i, f in enumerate(samp, 1):
            lines.append(f"### {cat}-{i:02d} — idx={f['_idx']} {'[TEST-FILE]' if f['_is_test'] else ''}")
            lines.append("")
            lines.append(f"- **File**: `{f.get('file_path', '?')}`")
            lines.append(f"- **Line**: {f.get('line_start', '?')}-{f.get('line_end', '?')}")
            lines.append(f"- **CWE**: {f.get('cwe', '?')}")
            lines.append(f"- **Rule**: `{f.get('rule_id', '?')}`")
            lines.append(f"- **Hunter**: {f.get('_hunter', '?')}")
            lines.append(f"- **Severity**: {f.get('severity', '?')}")
            msg = (f.get("message") or "").replace("\n", " ")[:200]
            lines.append(f"- **Message**: {msg}")
            lines.append("")
            lines.append("Code context:")
            lines.append("```c")
            lines.append(read_context(f.get("file_path", ""), int(f.get("line_start", 0))))
            lines.append("```")
            lines.append("")
            lines.append("**Label**: [ ] TP  [ ] FP  [ ] UNK")
            lines.append("")
            lines.append("**Rationale**:")
            lines.append("")
            lines.append("---")
            lines.append("")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote worksheet: {OUT}")
    total_rows = sum(len(s) for s in sampled.values())
    print(f"Total rows to label: {total_rows}")
    for cat, samp in sampled.items():
        tests = sum(1 for f in samp if f["_is_test"])
        print(f"  {cat}: {len(samp)} sampled, {tests} are test-file")


if __name__ == "__main__":
    main()
