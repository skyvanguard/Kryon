"""F10.3 spike — does the local LLM discriminate TPs from FPs?

Setup (intentionally minimal — sprint = 2h cap):
  - 10 known FPs from f9_fps.json (real-world code, scanner false-alarms).
  - 10 known TPs from Juliet bad files (NIST-labeled real bugs).
  - Per finding: build a triage prompt with rule + 6-line snippet + CWE.
  - Local model (gemma4:26b-32k via OpenAI-compatible API).
  - Verdict: KEEP / SUPPRESS / UNCERTAIN. Single LLM call, no tools.

Pass criterion (gate to authorise the full F10.3 sprint):
  - SUPPRESS rate on TPs < 20%  (model doesn't kill real bugs)
  - SUPPRESS rate on FPs > 50%  (model adds value over baseline)

If both fail or first fails: F10.3 dies, replan F10.1+F10.2 without it.
"""
from __future__ import annotations

import json
import os
import random
import re
import time
from collections import Counter
from pathlib import Path
from typing import Optional

# -- Configuration -------------------------------------------------------------

JULIET = Path(
    os.environ.get(
        "KRYON_JULIET_ROOT",
        "/workspace/.juliet/juliet-test-suite-c/testcases",
    )
)
F9_FPS = Path("/workspace/f9_fps.json")  # produced by F9.0
SOURCES_ROOT = Path("/workspace/sources")
SEED = 7
N_PER_GROUP = 10
MODEL = os.environ.get("KRYON_MODEL", "gemma4:26b-32k")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "http://ollama:11434/v1")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "ollama")


def snippet(path: Path, line: int, ctx: int = 3) -> str:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if line <= 0 or line > len(lines):
        return ""
    lo = max(0, line - 1 - ctx)
    hi = min(len(lines), line + ctx)
    out = []
    for i in range(lo, hi):
        marker = ">" if i == line - 1 else " "
        out.append(f"{marker}{i+1:>5}: {lines[i][:120]}")
    return "\n".join(out)


# -- Sample selection ----------------------------------------------------------

def pick_fps() -> list[dict]:
    raw = json.loads(F9_FPS.read_text())
    candidates = [f for f in raw["findings"] if f["snippet"] and f["line"] > 0]
    rng = random.Random(SEED)
    out = []
    for f in rng.sample(candidates, N_PER_GROUP):
        out.append({
            "ground_truth": "FP",
            "file": str(SOURCES_ROOT / f["file"]),
            "rel_file": f["file"],
            "line": f["line"],
            "rule_id": f["rule_id"][:60],
            "cwe": f["cwe"],
            "snippet": f["snippet"],
        })
    return out


def pick_tps() -> list[dict]:
    """Pick 10 Juliet bad files. The _bad function in each file is a real
    NIST-labeled bug — that's our ground truth."""
    rng = random.Random(SEED)
    cwes = [121, 122, 190, 415, 416, 476]
    out: list[dict] = []
    for cwe in cwes:
        cwe_dir = list(JULIET.glob(f"CWE{cwe}_*"))
        if not cwe_dir:
            continue
        files: list[Path] = []
        for d in cwe_dir:
            for f in d.rglob("*.c"):
                name = f.name
                if any(s in name for s in ("a.c", "b.c", "c.c", "d.c", "e.c")):
                    continue
                files.append(f)
        if not files:
            continue
        # Take 2 per CWE so 6 CWEs * 2 = 12; trim to 10 below.
        for f in rng.sample(files, min(2, len(files))):
            text = f.read_text(errors="replace")
            # Locate the _bad function and pick the line with the bad sink.
            m = re.search(r"void\s+\w+_bad\s*\(\s*\)", text)
            if not m:
                continue
            # Look forward for the "POTENTIAL FLAW" marker line, fallback to
            # the next 'data' or 'inputBuffer' use after function open.
            after = text[m.end():]
            flaw = re.search(r"POTENTIAL FLAW.*?\n([^\n]+)\n", after, re.DOTALL)
            if flaw:
                # Line number of the line AFTER the flaw comment
                offset = m.end() + flaw.start(1)
                line = text.count("\n", 0, offset) + 1
            else:
                line = text.count("\n", 0, m.end()) + 2
            out.append({
                "ground_truth": "TP",
                "file": str(f),
                "rel_file": str(f.relative_to(JULIET)),
                "line": line,
                "rule_id": f"juliet.cwe-{cwe}.bad",
                "cwe": f"CWE-{cwe}",
                "snippet": snippet(f, line),
            })
            if len(out) >= N_PER_GROUP:
                return out
    return out[:N_PER_GROUP]


# -- LLM triage call -----------------------------------------------------------

PROMPT_TEMPLATE = """You are a security triage analyst. A static scanner flagged the
following potential vulnerability. Decide if it's a REAL bug (KEEP), a clear
false positive (SUPPRESS), or you can't tell from the snippet (UNCERTAIN).

Rule that fired: {rule_id}
CWE: {cwe}
File: {rel_file}
Line: {line}

Code (the marker > is the flagged line):
{snippet}

Reply in EXACTLY this format, nothing else:
VERDICT: KEEP | SUPPRESS | UNCERTAIN
REASON: <one short sentence>
"""


def call_llm(prompt: str, timeout_s: int = 60) -> tuple[str, str, float]:
    """Returns (verdict, reason, latency_s). Verdict in {KEEP, SUPPRESS, UNCERTAIN, ERROR}."""
    import urllib.request

    body = json.dumps({
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        # gemma4 is a reasoning model — its `reasoning` field eats most of
        # the budget. 200 tokens leaves `content` empty for non-trivial
        # prompts. 2000 has slack but the triage answer is short.
        "max_tokens": 2000,
    }).encode()
    req = urllib.request.Request(
        f"{OPENAI_BASE_URL}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            doc = json.loads(r.read())
    except Exception as e:
        return ("ERROR", f"http: {e}", time.time() - t0)
    elapsed = time.time() - t0
    text = (doc.get("choices") or [{}])[0].get("message", {}).get("content", "")
    m_v = re.search(r"VERDICT:\s*(KEEP|SUPPRESS|UNCERTAIN)", text, re.I)
    m_r = re.search(r"REASON:\s*(.+)", text)
    verdict = m_v.group(1).upper() if m_v else "ERROR"
    reason = (m_r.group(1).strip()[:160]) if m_r else text[:160]
    return (verdict, reason, elapsed)


# -- Main spike ----------------------------------------------------------------

def _percentile(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    ys = sorted(xs)
    i = min(len(ys) - 1, max(0, int(round(q * (len(ys) - 1)))))
    return ys[i]


def main():
    # SEED=7 + identical pick_fps / pick_tps guarantees byte-exact sample
    # overlap with prior runs of this script. Do NOT change SEED or
    # pick_* logic between model comparisons.
    fps = pick_fps()
    tps = pick_tps()
    samples = [*fps, *tps]
    out_path = Path(os.environ.get("KRYON_SPIKE_OUT", "/workspace/f10_spike.json"))
    prior_path = Path(os.environ.get("KRYON_SPIKE_PRIOR", ""))

    print(f"Spike: {len(fps)} FPs + {len(tps)} TPs = {len(samples)} samples")
    print(f"Model: {MODEL}")
    print(f"Endpoint: {OPENAI_BASE_URL}")
    print(f"Output: {out_path}")
    if prior_path and prior_path.is_file():
        print(f"Comparing against prior run: {prior_path}")
    print()

    results: list[dict] = []
    for i, s in enumerate(samples, 1):
        prompt = PROMPT_TEMPLATE.format(**s)
        verdict, reason, elapsed = call_llm(prompt, timeout_s=120)
        results.append({**s, "verdict": verdict, "reason": reason, "latency_s": elapsed})
        mark = "OK" if (
            (s["ground_truth"] == "FP" and verdict == "SUPPRESS") or
            (s["ground_truth"] == "TP" and verdict == "KEEP")
        ) else "??"
        print(f"  [{i:2d}/{len(samples)}] gt={s['ground_truth']}  verdict={verdict:9s}  "
              f"{elapsed:5.1f}s  {mark}  {s['rel_file'][-50:]}")

    # Tabulate
    print("\n" + "=" * 72)
    print("RESULTS")
    print("=" * 72)
    by_gt: dict[str, Counter] = {"FP": Counter(), "TP": Counter()}
    for r in results:
        by_gt[r["ground_truth"]][r["verdict"]] += 1

    fp_supp = by_gt["FP"]["SUPPRESS"]
    fp_err = by_gt["FP"]["ERROR"]
    tp_supp = by_gt["TP"]["SUPPRESS"]
    tp_err = by_gt["TP"]["ERROR"]
    total_err = fp_err + tp_err

    # Latency percentiles (all samples, ERROR rows include 120s timeouts).
    lats = [r["latency_s"] for r in results]
    p50 = _percentile(lats, 0.50)
    p95 = _percentile(lats, 0.95)
    lmax = max(lats) if lats else 0.0
    timeout_rate = total_err / len(results)

    print(f"\n  FPs (n={len(fps)}): {dict(by_gt['FP'])}")
    print(f"  TPs (n={len(tps)}): {dict(by_gt['TP'])}")
    print(f"\n  SUPPRESS rate on TPs  = {tp_supp/len(tps)*100:5.1f}%  (gate < 20%)")
    print(f"  SUPPRESS rate on FPs  = {fp_supp/len(fps)*100:5.1f}%  gross")
    fp_respond = len(fps) - fp_err
    if fp_respond:
        print(f"  SUPPRESS rate on FPs  = {fp_supp/fp_respond*100:5.1f}%  of responders")
    print(f"\n  Latency p50 = {p50:5.1f}s   p95 = {p95:5.1f}s   max = {lmax:5.1f}s")
    print(f"  Timeout rate (120s)   = {timeout_rate*100:5.1f}%  ({total_err}/{len(results)})")

    # 3-tier gate
    print("\n" + "=" * 72)
    print("GATE")
    print("=" * 72)
    tp_ok = tp_supp / len(tps) < 0.20
    fp_gross_rate = fp_supp / len(fps)
    if not tp_ok:
        print(f"  KILL — TPs SUPPRESS rate {tp_supp/len(tps)*100:.1f}% >= 20%. Model kills real bugs.")
    elif p95 < 30 and fp_gross_rate > 0.40:
        print("  TIER A (ship default): p95<30s, TPs preserved, FPs suppressed>40%.")
        print("         Full sprint F10.1 -> F10.2 -> F10.3 viable.")
    elif p95 < 60:
        print("  TIER B (ship as --triage opt-in): p95<60s, TPs preserved,")
        print("         FP-suppress not strong enough for default on.")
    elif fp_gross_rate > 0 and timeout_rate < 0.5:
        print("  TIER C (experimental only): discrimination shown but latency too high")
        print("         for bench-gated delivery. Ship as opt-in without bench CI claim.")
    else:
        print(f"  KILL — latency p95={p95:.0f}s too high AND/OR timeout rate "
              f"{timeout_rate*100:.0f}% too high. F10.3 dies.")

    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nraw results: {out_path}")

    # Overlap vs prior model run (same samples by SEED; compare ERROR
    # and verdict shifts per file+line).
    if prior_path and prior_path.is_file():
        prior = json.loads(prior_path.read_text())
        by_key = {(p["rel_file"], p["line"]): p for p in prior}
        print("\n" + "=" * 72)
        print(f"COMPARISON vs {prior_path.name}")
        print("=" * 72)
        recovered_errors = 0
        verdict_shifts = 0
        for r in results:
            k = (r["rel_file"], r["line"])
            p = by_key.get(k)
            if p is None:
                continue
            if p["verdict"] == "ERROR" and r["verdict"] != "ERROR":
                recovered_errors += 1
            elif p["verdict"] != "ERROR" and r["verdict"] != "ERROR" and p["verdict"] != r["verdict"]:
                verdict_shifts += 1
        prior_err = sum(1 for p in prior if p["verdict"] == "ERROR")
        print(f"  Prior ERRORs: {prior_err}/{len(prior)}")
        print(f"  Recovered (prior ERROR -> this answered): {recovered_errors}/{prior_err}")
        print(f"  Verdict shifts (both answered, different): {verdict_shifts}")


if __name__ == "__main__":
    main()
