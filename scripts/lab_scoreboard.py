"""F203.J — Vulnerable-lab scoreboard.

Compara findings emitidos por `kryon investigate` (transcript markdown)
o `kryon engage` (findings JSON) contra el ground truth declarado en
docker/vulnerable-lab/README.md.

Ground truth:
    target-web (8080):  CWE-319, CWE-1004, CWE-306, CWE-200
    target-ssh (2222):  CWE-521, CWE-287, CWE-250, CWE-307
    target-db  (33060): CWE-319, CWE-521

Métricas:
    TP — CWE en ground truth y mencionado en transcript
    FP — CWE mencionado en transcript pero NO en ground truth para ese target
    FN — CWE en ground truth pero NO mencionado
    precision = TP / (TP + FP)
    recall    = TP / (TP + FN)
    F1        = 2 * P * R / (P + R)
    wilson_lower_95 — confidence-corrected recall (TP/(TP+FN))

Uso:
    # Auto-detect target from --url o file path
    python scripts/lab_scoreboard.py --transcript reports/investigate-*.md

    # Explicit target
    python scripts/lab_scoreboard.py --transcript out.md --target web
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Ground truth — CWEs PLANTED per target (no inventar, alinear con
# docker/vulnerable-lab/README.md exactly).
GROUND_TRUTH: dict[str, set[str]] = {
    # docker/vulnerable-lab targets (F203.J)
    "web": {"CWE-319", "CWE-1004", "CWE-306", "CWE-200"},
    "ssh": {"CWE-521", "CWE-287", "CWE-250", "CWE-307"},
    "db": {"CWE-319", "CWE-521"},
    # F203.AA — OWASP Juice Shop canonical CWEs.
    # Reference: https://pwning.owasp-juice.shop/ + OWASP API security
    # findings catalogued for the F189 bench. Covers the top vulnerabilities
    # planted in Juice Shop 14.x without over-claiming (only CWEs that
    # are deterministically present in the unmodified default build).
    "juice_shop": {
        "CWE-89",  # SQLi en /rest/user/login (boolean blind)
        "CWE-79",  # Reflected/stored XSS en search + comments + 5-star
        "CWE-639",  # IDOR en /api/Baskets/{id}, /api/Feedbacks/{id}
        "CWE-285",  # Broken access control (/api/Quantitys, /administration)
        "CWE-200",  # info disclosure (server tokens, /api/Users emails)
        "CWE-22",  # Path traversal en /ftp endpoint
        "CWE-352",  # CSRF en perfil endpoints
        "CWE-915",  # Mass assignment en profile update
        "CWE-1004",  # Cookies sin HttpOnly
        "CWE-319",  # HTTP por default (sin TLS termination)
    },
}

# Acceptable port mappings to infer target from URL/host
PORT_TO_TARGET = {
    "8080": "web",
    "80": "web",
    "443": "web",
    "2222": "ssh",
    "22": "ssh",
    "33060": "db",
    "3306": "db",
    # F203.AA — Juice Shop default port 3000 (host map 3003)
    "3000": "juice_shop",
    "3003": "juice_shop",
}


# Accept ASCII hyphen, non-breaking hyphen (U+2011), en/em dashes, minus
# (LLM markdown often renders the dash as U+2011 inside table cells).
# `(?!\d)` forces the full number (no backtracking to a partial like CWE-2 from
# "cwe-22-…"); `(?!-[a-zA-Z])` skips skill identifiers like `cwe-89-sqli`
# (CWE-number-word) while still matching findings `CWE-89`, `CWE-89:`,
# `CWE-1004 ` — so loaded-skill telemetry never inflates the emitted set.
_CWE_RE = re.compile(r"CWE[-\s_‐-―−]*(\d{1,4})(?!\d)(?!-[a-zA-Z])", re.IGNORECASE)


@dataclass(frozen=True)
class ScoreResult:
    target: str
    ground_truth: set[str] = field(default_factory=set)
    emitted: set[str] = field(default_factory=set)
    tp: set[str] = field(default_factory=set)  # in both
    fp: set[str] = field(default_factory=set)  # emitted only
    fn: set[str] = field(default_factory=set)  # ground truth only

    @property
    def precision(self) -> float:
        denom = len(self.tp) + len(self.fp)
        return len(self.tp) / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = len(self.tp) + len(self.fn)
        return len(self.tp) / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0

    @property
    def wilson_lower_95(self) -> float:
        """Wilson lower bound of recall (95% confidence)."""
        n = len(self.tp) + len(self.fn)
        if n == 0:
            return 0.0
        z = 1.96
        p_hat = len(self.tp) / n
        numerator = p_hat + z * z / (2 * n) - z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n))
        denominator = 1 + z * z / n
        return max(0.0, numerator / denominator)


def extract_cwes(text: str) -> set[str]:
    """Pull all `CWE-XXX` mentions from a text blob (markdown / JSON)."""
    return {f"CWE-{int(m.group(1))}" for m in _CWE_RE.finditer(text)}


def infer_target_from_text(text: str) -> str | None:
    """Heuristic: find PORT mention (URL `:PORT`, `-p PORT`, `-P PORT`,
    `port PORT`) and map to target name.

    Order in PORT_TO_TARGET is intentional: more specific ports first
    (8080 before 80) so substring matches don't collide.
    """
    text_lower = text.lower()
    for port, target in PORT_TO_TARGET.items():
        patterns = (
            f":{port}",  # URL form: http://host:8080/
            f"port {port}",  # "port 8080" descriptive
            f"-p {port}",  # ssh -p 2222
            f"-P {port}",  # mysql -P 33060 (uppercase original)
            f"-p={port}",  # ssh -p=2222
        )
        if any(p in text or p.lower() in text_lower for p in patterns):
            return target
    return None


# A finding for a child CWE satisfies its parent in ground truth (the CWE tree
# narrows the same weakness). Conservative, well-established relationships only.
_CWE_PARENT: dict[str, str] = {
    "CWE-862": "CWE-285",  # Missing Authorization ⊂ Improper Access Control
    "CWE-306": "CWE-285",  # Missing Auth for Critical Function ⊂ Improper Access Control
}


def score_text(text: str, target: str) -> ScoreResult:
    """Compute TP/FP/FN comparing CWEs in text vs ground truth for target.

    Honors CWE parent/child relationships: an emitted child CWE credits its
    parent when the parent is in ground truth (and is then not counted as a
    false positive).
    """
    if target not in GROUND_TRUTH:
        raise ValueError(f"Unknown target '{target}'. Options: {list(GROUND_TRUTH)}")

    gt = GROUND_TRUTH[target]
    emitted = extract_cwes(text)
    # Expand emitted with parent CWEs that appear in ground truth.
    expanded = set(emitted)
    for cwe in emitted:
        parent = _CWE_PARENT.get(cwe)
        if parent and parent in gt:
            expanded.add(parent)
    tp = gt & expanded
    fp = {c for c in emitted if c not in gt and _CWE_PARENT.get(c) not in gt}
    fn = gt - expanded
    return ScoreResult(
        target=target,
        ground_truth=gt,
        emitted=emitted,
        tp=tp,
        fp=fp,
        fn=fn,
    )


def format_report(result: ScoreResult) -> str:
    """Render a human-readable scoreboard."""
    lines = [
        f"## Lab Scoreboard — target: {result.target}",
        "",
        f"Ground truth ({len(result.ground_truth)} CWEs): {', '.join(sorted(result.ground_truth))}",
        f"Emitted     ({len(result.emitted)} CWEs): "
        f"{', '.join(sorted(result.emitted)) if result.emitted else '(none)'}",
        "",
        f"TP ({len(result.tp)}): {', '.join(sorted(result.tp)) if result.tp else '(none)'}",
        f"FP ({len(result.fp)}): {', '.join(sorted(result.fp)) if result.fp else '(none)'}",
        f"FN ({len(result.fn)}): {', '.join(sorted(result.fn)) if result.fn else '(none)'}",
        "",
        f"Precision: {result.precision * 100:.1f}%",
        f"Recall:    {result.recall * 100:.1f}%",
        f"F1:        {result.f1 * 100:.1f}%",
        f"Wilson 95% lower bound (recall): {result.wilson_lower_95 * 100:.1f}%",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="F203.J — Score Kryon findings against vulnerable-lab ground truth")
    ap.add_argument(
        "--transcript",
        type=Path,
        help="Path to investigate transcript (markdown) or engage findings JSON",
    )
    ap.add_argument(
        "--text",
        help="Inline text to score (alternative to --transcript)",
    )
    ap.add_argument(
        "--target",
        choices=sorted(GROUND_TRUTH.keys()),
        help="Lab target (web/ssh/db). If omitted, inferred from URL ports.",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of human-readable text",
    )
    args = ap.parse_args(argv)

    if args.transcript:
        if not args.transcript.exists():
            print(f"ERROR: transcript not found: {args.transcript}", file=sys.stderr)
            return 2
        text = args.transcript.read_text(encoding="utf-8")
    elif args.text:
        text = args.text
    else:
        print("ERROR: provide --transcript or --text", file=sys.stderr)
        return 2

    target = args.target or infer_target_from_text(text)
    if not target:
        print(
            "ERROR: target could not be inferred (no :PORT match). Use --target.",
            file=sys.stderr,
        )
        return 2

    result = score_text(text, target)

    if args.json:
        out = {
            "target": result.target,
            "ground_truth": sorted(result.ground_truth),
            "emitted": sorted(result.emitted),
            "tp": sorted(result.tp),
            "fp": sorted(result.fp),
            "fn": sorted(result.fn),
            "precision": result.precision,
            "recall": result.recall,
            "f1": result.f1,
            "wilson_lower_95": result.wilson_lower_95,
        }
        print(json.dumps(out, indent=2))
    else:
        print(format_report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
