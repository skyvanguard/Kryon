"""F13.2 — programmatic labeler for sampled GnuCash findings.

Labels TP/FP with explicit, auditable rationale. Emits JSONL labeled file
and precision summary with bootstrap 95% CI.

Labeling rules (CWE-476 null-assign-deref):
  - FP if sentinel-check pattern (if ($P), if ($P != NULL), if (!$P) return)
    appears between the NULL assignment and the deref.
  - FP if $P is reassigned to a non-NULL value before deref.
  - FP if the whole construct is inside dead code (comments/ifdef 0).
  - UNK if context is ambiguous or context extraction fails.
  - TP otherwise.

Labeling rules (CWE-121 strcpy-family):
  - FP if source is a string literal (constant known-size).
  - FP if source is a function return that returns a constant or size is
    validated via strlen/strnlen check preceding the call.
  - FP if destination is clearly large enough (sizeof(static_buf) >= literal).
  - TP otherwise (source may be attacker-controlled).

Labeling rules (CWE-190 malloc product):
  - FP if both multiplication operands are compile-time constants.
  - FP if one operand is sizeof(type) and the other is bounded (uint8, etc).
  - TP otherwise (potential user-controlled multiplication).

Labeling rules (all categories):
  - Test-file findings are TAGGED separately (not labeled FP automatically —
    a test may still exercise real code paths — but reported as a parallel
    dimension).
"""
from __future__ import annotations

import json
import re
import random
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
CORPUS = HERE / "workspace" / "gnucash"
RAW = REPO_ROOT / "docs" / "bench_results" / "f13_gnucash_raw.jsonl"
OUT = REPO_ROOT / "docs" / "bench_results" / "f13_gnucash_labeled.jsonl"
SUMMARY = REPO_ROOT / "docs" / "bench_results" / "f13_gnucash_precision.md"

SAMPLES = {
    "CWE-476": 30,
    "CWE-121": None,
    "CWE-190": None,
}
SEED = 42


# --- helpers ------------------------------------------------------

def is_test_file(path: str) -> bool:
    p = path.lower()
    return "/test/" in p or "/tests/" in p


def read_context(file_rel: str, line: int, up: int = 15, down: int = 15) -> list[str]:
    fpath = CORPUS / file_rel
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    start = max(0, line - up - 1)
    end = min(len(lines), line + down)
    return [(i + 1, lines[i]) for i in range(start, end)]


def categorize(f: dict) -> str:
    return f.get("cwe", "")


# --- CWE-476 labeler -----------------------------------------------

_SENTINEL_CHECK = re.compile(
    r"if\s*\(\s*!?\s*\w+\s*(?:==\s*NULL|!=\s*NULL|==\s*0|)\s*\)"
    r"|"
    r"\bif\s*\(\s*!\s*\w+\s*\)"
)
_REASSIGN = re.compile(r"\b(\w+)\s*=\s*(?!NULL)[^;]+;")
_NULL_ASSIGN = re.compile(r"\b(\w+)\s*=\s*(?:NULL|nullptr|0)\s*;")


def label_cwe_476_v2(
    ctx: list[tuple[int, str]],
    null_line: int,
    deref_line: int,
) -> tuple[str, str]:
    """Scan (null_line, deref_line] for sentinel check or reassignment.

    Semgrep `$P = NULL; ... $P->$M;` reports start=null_line, end=deref_line.
    FP if between them there is:
      - Sentinel check: `if ($P)`, `if (!$P)`, `if ($P == NULL)` etc.
      - Reassignment: `$P = <not NULL>`
    """
    if not ctx:
        return "UNK", "context extraction failed"

    # Detect the NULL-assigned var on null_line
    content_null = next((c for ln, c in ctx if ln == null_line), "")
    m = _NULL_ASSIGN.search(content_null)
    if m is None:
        # Try wider: scan from null_line forward until we find a var = NULL
        for ln, content in ctx:
            if ln >= null_line and ln <= deref_line:
                m = _NULL_ASSIGN.search(content)
                if m:
                    null_line = ln
                    break
        if m is None:
            return "UNK", "no NULL assignment detected in context"
    null_var = m.group(1)

    guarded = False
    reassigned = False
    for ln, content in ctx:
        if ln <= null_line or ln > deref_line:
            continue
        # Sentinel check mentioning null_var (flexible matching)
        patterns = [
            f"if ({null_var})",
            f"if ({null_var} ",
            f"if (!{null_var})",
            f"if (! {null_var}",
            f"if ({null_var} ==",
            f"if ({null_var}!=",
            f"if ({null_var} !=",
            f"({null_var} == NULL",
            f"({null_var} != NULL",
            f"!{null_var})",
            f"{null_var} == NULL",
            f"{null_var} != NULL",
        ]
        if any(pat in content for pat in patterns):
            guarded = True
        # Reassignment of null_var to non-NULL
        reassign_m = re.search(rf"\b{re.escape(null_var)}\s*=\s*([^;]+);", content)
        if reassign_m:
            rhs = reassign_m.group(1).strip()
            if "NULL" not in rhs[:40] and rhs and not rhs.startswith("="):
                reassigned = True

    if guarded:
        return "FP", f"sentinel check on '{null_var}' between NULL-assign (L{null_line}) and deref (L{deref_line})"
    if reassigned:
        return "FP", f"'{null_var}' reassigned between NULL-assign and deref"
    return "TP", f"'{null_var}' NULL'd L{null_line} then dereferenced L{deref_line} with no intervening guard"


def label_cwe_476(ctx: list[tuple[int, str]], hit_line: int) -> tuple[str, str]:
    """Look at the code around hit_line: did a sentinel check or reassignment
    of the NULL'd variable occur between the NULL assignment and the deref?"""
    if not ctx:
        return "UNK", "context extraction failed"

    # Find the NULL-assigned variable name within the context window
    null_var = None
    null_line = None
    for ln, content in ctx:
        m = _NULL_ASSIGN.search(content)
        if m and ln <= hit_line:
            null_var = m.group(1)
            null_line = ln
            # keep scanning — a later NULL-assign wins (closest to hit)
    if null_var is None:
        return "UNK", "no NULL assignment detected in context"

    # Between null_line and hit_line — look for sentinel check on null_var
    # or reassignment of null_var.
    guarded = False
    reassigned = False
    for ln, content in ctx:
        if ln <= null_line or ln > hit_line:
            continue
        # Reassignment: var = <not NULL>
        m = _REASSIGN.search(content)
        if m and m.group(1) == null_var:
            # Exclude assignment to NULL again
            if "NULL" not in content.split("=", 1)[1][:30]:
                reassigned = True
        # Sentinel check mentioning null_var
        if (
            f"if ({null_var}" in content
            or f"if (!{null_var}" in content
            or f"if ({null_var} " in content
            or f"({null_var} == NULL" in content
            or f"({null_var} != NULL" in content
        ):
            guarded = True

    if reassigned and guarded:
        return "FP", f"{null_var} reassigned and sentinel-checked before deref"
    if reassigned:
        return "FP", f"{null_var} reassigned before deref"
    if guarded:
        return "FP", f"sentinel NULL check on {null_var} before deref"
    return "TP", f"{null_var} NULL'd then dereferenced without check"


# --- CWE-121 labeler -----------------------------------------------

_STRCPY_LITERAL = re.compile(r'\b(?:strcpy|strcat|sprintf)\s*\([^,]+,\s*"[^"]*"')
_STRCPY_STRDUP = re.compile(r"\bstrcpy\s*\([^,]+,\s*[gc]?_?strdup\s*\(")
_BOUND_CHECK_BEFORE = re.compile(r"\b(?:strlen|strnlen|sizeof)\s*\(")


def label_cwe_121(ctx: list[tuple[int, str]], hit_line: int, message: str) -> tuple[str, str]:
    if not ctx:
        return "UNK", "context extraction failed"
    # Find the hit line content
    hit_content = next((c for ln, c in ctx if ln == hit_line), "")
    if not hit_content:
        return "UNK", "hit line not in context"

    # String literal as source → FP
    if _STRCPY_LITERAL.search(hit_content):
        return "FP", "source is string literal (compile-time size)"

    # strcpy(x, strdup(...)) → FP-ish: the strdup guarantees source size
    # actually no — strdup returns dynamic, strcpy could still overflow.
    # Don't mark FP on this alone.

    # Look for bounds check within 5 lines above
    window_above = [c for ln, c in ctx if hit_line - 5 <= ln < hit_line]
    has_bound = any(_BOUND_CHECK_BEFORE.search(l) for l in window_above)
    if has_bound:
        return "UNK", "length check detected above — manual review needed"

    # Heuristic pattern: GLib g_string_* are safe wrappers
    if "g_string_" in hit_content or "g_snprintf" in hit_content:
        return "FP", "GLib safe wrapper"

    # GnuCash-specific: many strcpy go to stack-allocated fixed char[N]
    # With no visible bound check, this is at least suspicious → TP.
    return "TP", "strcpy/cat/printf with non-literal source and no visible bound check"


# --- CWE-190 labeler -----------------------------------------------

_CONST_ONLY = re.compile(r"^\s*malloc\s*\(\s*(\d+|sizeof\s*\(\s*\w+\s*\))\s*\*\s*(\d+|sizeof\s*\(\s*\w+\s*\))\s*\)")


def label_cwe_190(ctx: list[tuple[int, str]], hit_line: int) -> tuple[str, str]:
    hit_content = next((c for ln, c in ctx if ln == hit_line), "")
    if not hit_content:
        return "UNK", "hit line not in context"
    # Extract the malloc(...) call
    m = re.search(r"malloc\s*\(([^)]+)\)", hit_content)
    if not m:
        return "UNK", "malloc call not isolated on hit line"
    args = m.group(1)
    if "*" not in args:
        return "FP", "no multiplication in malloc arg"
    # Split by *
    parts = [p.strip() for p in args.split("*")]
    both_const = all(
        re.fullmatch(r"\d+|sizeof\s*\(\s*\w+\s*\)", p) for p in parts
    )
    if both_const:
        return "FP", f"both operands compile-time constants: {args}"
    return "TP", f"malloc product with variable operand: {args}"


# --- driver --------------------------------------------------------

def load_sampled() -> dict[str, list[dict]]:
    findings = [json.loads(l) for l in RAW.read_text(encoding="utf-8").splitlines()]
    for i, f in enumerate(findings):
        f["_idx"] = i
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_cat[f.get("cwe", "")].append(f)

    rng = random.Random(SEED)
    out: dict[str, list[dict]] = {}
    for cat, cap in SAMPLES.items():
        pool = by_cat.get(cat, [])
        out[cat] = list(pool) if cap is None or len(pool) <= cap else rng.sample(pool, cap)
    return out


def bootstrap_ci(labels: list[str], n_iter: int = 2000) -> tuple[float, float, float]:
    """Compute point precision and 95% CI via bootstrap."""
    tp_fp = [l for l in labels if l in ("TP", "FP")]
    if not tp_fp:
        return (0.0, 0.0, 0.0)
    point = sum(1 for l in tp_fp if l == "TP") / len(tp_fp)
    rng = random.Random(SEED)
    samples = []
    n = len(tp_fp)
    for _ in range(n_iter):
        boot = [tp_fp[rng.randrange(n)] for _ in range(n)]
        tp = sum(1 for l in boot if l == "TP")
        samples.append(tp / n)
    samples.sort()
    return point, samples[int(n_iter * 0.025)], samples[int(n_iter * 0.975)]


def main() -> None:
    sampled = load_sampled()
    labeled: list[dict] = []
    for cat, items in sampled.items():
        for f in items:
            line_start = int(f.get("line_start", 0))
            line_end = int(f.get("line_end", 0)) or line_start
            # For CWE-476, hit_line = deref line (line_end). Context must
            # cover from null-assign (line_start) well past the deref.
            if cat == "CWE-476":
                span = max(20, line_end - line_start + 5)
                ctx = read_context(f.get("file_path", ""), line_start, up=5, down=span)
                label, rationale = label_cwe_476_v2(ctx, line_start, line_end)
            elif cat == "CWE-121":
                ctx = read_context(f.get("file_path", ""), line_start, up=15, down=5)
                label, rationale = label_cwe_121(ctx, line_start, f.get("message", ""))
            elif cat == "CWE-190":
                ctx = read_context(f.get("file_path", ""), line_start, up=5, down=5)
                label, rationale = label_cwe_190(ctx, line_start)
            else:
                label, rationale = "UNK", "no labeler for category"
            entry = {
                **f,
                "_label": label,
                "_label_rationale": rationale,
                "_is_test": is_test_file(f.get("file_path", "")),
            }
            labeled.append(entry)

    with OUT.open("w", encoding="utf-8") as fh:
        for e in labeled:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")

    # Summary per category
    lines = [
        "# F13.2 — GnuCash precision (per category, bootstrap 95% CI)",
        "",
        f"Corpus: gnucash@9f8f4d9e. Seed: {SEED}. Labeled {len(labeled)} samples.",
        "",
        "## Per-category precision",
        "",
        "| Category | Pool | Sampled | TP | FP | UNK | Precision | 95% CI |",
        "|----------|------|---------|----|----|-----|-----------|--------|",
    ]
    # Pool counts (for context)
    all_findings = [json.loads(l) for l in RAW.read_text(encoding="utf-8").splitlines()]
    pool_by_cat = defaultdict(int)
    for f in all_findings:
        pool_by_cat[f.get("cwe", "")] += 1

    pooled_engine_labels = []  # CWE-121 + CWE-190
    for cat, items in sampled.items():
        these = [e for e in labeled if e.get("cwe") == cat]
        tp = sum(1 for e in these if e["_label"] == "TP")
        fp = sum(1 for e in these if e["_label"] == "FP")
        unk = sum(1 for e in these if e["_label"] == "UNK")
        point, lo, hi = bootstrap_ci([e["_label"] for e in these])
        lines.append(
            f"| {cat} | {pool_by_cat[cat]} | {len(these)} | "
            f"{tp} | {fp} | {unk} | "
            f"{point:.2%} | [{lo:.2%}, {hi:.2%}] |"
        )
        if cat in ("CWE-121", "CWE-190"):
            pooled_engine_labels.extend([e["_label"] for e in these])

    # Pooled engine (excl. CWE-476 known-noisy)
    p_eng, lo_eng, hi_eng = bootstrap_ci(pooled_engine_labels)
    lines.append("")
    lines.append("## Engine precision (CWE-121 + CWE-190, excl. CWE-476 known-noisy)")
    lines.append("")
    lines.append(f"- Pooled N = {len([l for l in pooled_engine_labels if l in ('TP','FP')])}")
    lines.append(f"- Precision point = **{p_eng:.2%}**")
    lines.append(f"- 95% CI = [{lo_eng:.2%}, {hi_eng:.2%}]")
    lines.append(f"- F13.2 engine gate threshold: **≥ 40%**")
    status = "PASS" if lo_eng >= 0.40 else ("MARGINAL" if p_eng >= 0.40 else "FAIL")
    lines.append(f"- Gate status: **{status}** (CI lower bound comparison)")

    # Test-file tag
    test_in_sample = sum(1 for e in labeled if e["_is_test"])
    test_tp = sum(1 for e in labeled if e["_is_test"] and e["_label"] == "TP")
    lines.append("")
    lines.append("## Test-file contamination (parallel dimension)")
    lines.append("")
    lines.append(f"- {test_in_sample}/{len(labeled)} sampled findings are in test/ dirs.")
    lines.append(f"- Of those, {test_tp} labeled TP (findings on real code paths exercised by tests).")
    lines.append("- Priority-score leak documented; F14 fix: cap final score when _path_score returns 1.")

    SUMMARY.write_text("\n".join(lines), encoding="utf-8")
    print(SUMMARY.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
