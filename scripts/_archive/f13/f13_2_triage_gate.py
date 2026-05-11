"""F13.2 — workflow gate: TriageAnnotator on the 50 labeled findings.

Runs qwen3-coder:30b-32k with temperature=0 explicitly pinned in the API
payload (reproducible without Modelfile variant). Computes 4-cell
confusion matrix vs the programmatic ground truth labels.

Invocation: inside the kryon docker container (which has /etc/hosts route
to ollama). We docker-cp the labeled JSONL in, run, copy results out.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

LABELED = Path("/tmp/f13_gnucash_labeled.jsonl")
OUT = Path("/tmp/f13_gnucash_triaged.jsonl")

_PROMPT = """You are a security triage analyst. A static scanner flagged the
following potential vulnerability. Decide if it's a REAL bug (KEEP), a clear
false positive (SUPPRESS), or you can't tell from the snippet (UNCERTAIN).

Rule that fired: {rule_id}
CWE: {cwe}
File: {file}
Line: {line}

Code (the marker > is the flagged line):
{snippet}

Reply in EXACTLY this format, nothing else:
VERDICT: KEEP | SUPPRESS | UNCERTAIN
REASON: <one short sentence>
CONFIDENCE: high | medium | low
"""


def build_snippet(file_path: str, line_start: int, line_end: int, corpus_root: Path) -> str:
    fpath = corpus_root / file_path
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "<file not readable>"
    if line_start <= 0:
        return ""
    ctx_lo = max(0, line_start - 4)
    ctx_hi = min(len(lines), line_end + 4 if line_end else line_start + 4)
    out = []
    for i in range(ctx_lo, ctx_hi):
        marker = ">" if line_start <= (i + 1) <= (line_end or line_start) else " "
        out.append(f"{marker}{i+1:>5}: {lines[i][:120]}")
    return "\n".join(out)


def triage_one(finding: dict, corpus_root: Path, endpoint: str, model: str) -> dict:
    prompt = _PROMPT.format(
        rule_id=finding.get("rule_id", ""),
        cwe=finding.get("cwe", ""),
        file=finding.get("file_path", ""),
        line=finding.get("line_start", 0),
        snippet=build_snippet(
            finding.get("file_path", ""),
            int(finding.get("line_start", 0)),
            int(finding.get("line_end", 0)),
            corpus_root,
        ),
    )
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "top_p": 1,
        "max_tokens": 500,
    }).encode()
    req = urllib.request.Request(
        f"{endpoint}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer ollama",
        },
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            doc = json.loads(r.read())
    except Exception as exc:
        return {
            **finding,
            "_triage_verdict": "ERROR",
            "_triage_reason": f"http: {exc}"[:200],
            "_triage_confidence": "",
            "_triage_latency_s": round(time.time() - t0, 2),
        }
    elapsed = time.time() - t0
    text = (doc.get("choices") or [{}])[0].get("message", {}).get("content", "")
    m_v = re.search(r"VERDICT:\s*(KEEP|SUPPRESS|UNCERTAIN)", text, re.I)
    m_r = re.search(r"REASON:\s*(.+)", text)
    m_c = re.search(r"CONFIDENCE:\s*(high|medium|low)", text, re.I)
    verdict = m_v.group(1).upper() if m_v else "ERROR"
    reason = (m_r.group(1).strip()[:200]) if m_r else text[:200]
    confidence = m_c.group(1).lower() if m_c else "medium"
    return {
        **finding,
        "_triage_verdict": verdict,
        "_triage_reason": reason,
        "_triage_confidence": confidence,
        "_triage_latency_s": round(elapsed, 2),
    }


def main() -> None:
    corpus_root = Path("/workspace/gnucash")
    endpoint = "http://ollama:11434/v1"
    model = "qwen3-coder:30b-32k"

    findings = [json.loads(l) for l in LABELED.read_text(encoding="utf-8").splitlines()]
    print(f"Triaging {len(findings)} findings with {model} (temp=0)")

    triaged = []
    for i, f in enumerate(findings, 1):
        t = triage_one(f, corpus_root, endpoint, model)
        triaged.append(t)
        verdict = t["_triage_verdict"]
        gt = t.get("_label", "?")
        print(f"  [{i:2d}/{len(findings)}] {verdict:10s} gt={gt:4s} "
              f"lat={t['_triage_latency_s']:.1f}s  {t['file_path']}:{t['line_start']}")
        OUT.write_text(
            "\n".join(json.dumps(x, ensure_ascii=False) for x in triaged) + "\n",
            encoding="utf-8",
        )

    # Confusion matrix
    print("\n--- Confusion matrix ---")
    cells = {("KEEP", "TP"): 0, ("KEEP", "FP"): 0,
             ("SUPPRESS", "TP"): 0, ("SUPPRESS", "FP"): 0,
             ("UNCERTAIN", "TP"): 0, ("UNCERTAIN", "FP"): 0,
             ("ERROR", "TP"): 0, ("ERROR", "FP"): 0}
    for t in triaged:
        v = t["_triage_verdict"]
        l = t.get("_label", "UNK")
        if l in ("TP", "FP") and v in ("KEEP", "SUPPRESS", "UNCERTAIN", "ERROR"):
            cells[(v, l)] = cells.get((v, l), 0) + 1
    for (v, l), c in sorted(cells.items()):
        print(f"  {v:10s} × {l:4s} = {c}")

    keep_tp = cells.get(("KEEP", "TP"), 0)
    keep_fp = cells.get(("KEEP", "FP"), 0)
    supp_tp = cells.get(("SUPPRESS", "TP"), 0)
    supp_fp = cells.get(("SUPPRESS", "FP"), 0)
    total_fp = keep_fp + supp_fp + cells.get(("UNCERTAIN", "FP"), 0) + cells.get(("ERROR", "FP"), 0)
    total_tp = keep_tp + supp_tp + cells.get(("UNCERTAIN", "TP"), 0) + cells.get(("ERROR", "TP"), 0)

    print()
    if (keep_tp + keep_fp) > 0:
        print(f"KEEP precision     = {keep_tp}/{keep_tp + keep_fp} = {keep_tp/(keep_tp+keep_fp):.1%}")
    if total_fp > 0:
        print(f"SUPPRESS recall    = {supp_fp}/{total_fp} = {supp_fp/total_fp:.1%}  (FPs caught)")
    if total_tp > 0:
        print(f"KEEP recall (TPs)  = {keep_tp}/{total_tp} = {keep_tp/total_tp:.1%}")


if __name__ == "__main__":
    main()
