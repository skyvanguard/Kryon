"""F11.0 — tool-augmented triage spike.

Same 20 findings as F10.3 spike (seed=7, pick_fps + pick_tps identical).
Same prompt byte-for-byte EXCEPT the assistant now has one tool:

    read_function(file_path, function_name) -> function body

Gate (pre-agreed with user):
  SUPPRESS precision >= 75%   ship F11.1 full implementation
  SUPPRESS precision in [60, 75]  grey zone, re-scope
  SUPPRESS precision < 60%   kill direction — confirms 95% KEEP / 40%
                             SUPPRESS asymmetry is the model ceiling,
                             not a context deficit.

Each finding gets up to 3 tool-call rounds + final verdict. 30s per-
round timeout, 15s overall LLM budget per finding (approx — 2 rounds
typical).
"""
from __future__ import annotations

import json
import os
import random
import re
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

# -- Reuse the exact sample pickers from the F10.3 spike ----------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "f10"))
from spike_triage import pick_fps, pick_tps, _percentile  # type: ignore

# -- Config -------------------------------------------------------------------
MODEL = os.environ.get("KRYON_MODEL", "qwen3-coder:30b-32k")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "http://ollama:11434/v1")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "ollama")
MAX_ROUNDS = 3
TIMEOUT_S = 30

PROMPT_TEMPLATE = """You are a security triage analyst. A static scanner flagged the
following potential vulnerability. You can call read_function(file_path,
function_name) to inspect the enclosing function if the snippet isn't enough.
Use the tool at most twice, then commit to a verdict.

Decide if the flagged finding is a REAL bug (KEEP), a clear false positive
(SUPPRESS), or you can't tell (UNCERTAIN).

Rule that fired: {rule_id}
CWE: {cwe}
File: {file}
Line: {line}

Code (the marker > is the flagged line):
{snippet}

When you have enough context, reply in EXACTLY this format, nothing else:
VERDICT: KEEP | SUPPRESS | UNCERTAIN
REASON: <one short sentence>
CONFIDENCE: high | medium | low
"""

TOOL_SPEC = [{
    "type": "function",
    "function": {
        "name": "read_function",
        "description": (
            "Return the body of a C/C++ function by name from a given file. "
            "Use this to see how the flagged line's function validates "
            "inputs or handles bounds."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "function_name": {"type": "string"},
            },
            "required": ["file_path", "function_name"],
        },
    },
}]


# -- Tool implementation wrapper -----------------------------------------------
def tool_read_function(file_path: str, function_name: str) -> str:
    """Thin wrapper so spike doesn't need full kryon import chain."""
    from kryon.tools.code.reader import _read_function_impl
    return _read_function_impl(file_path, function_name, context_lines=0)


# -- LLM chat loop with tool execution -----------------------------------------
def _post(body: dict, timeout_s: int) -> dict:
    req = urllib.request.Request(
        f"{OPENAI_BASE_URL}/chat/completions",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as r:
        return json.loads(r.read())


def decide(sample: dict) -> dict:
    """Returns {verdict, reason, confidence, rounds, latency_s, tool_calls}."""
    prompt = PROMPT_TEMPLATE.format(**sample)
    messages: list[dict] = [{"role": "user", "content": prompt}]
    t0 = time.time()
    tool_call_count = 0

    for round_idx in range(MAX_ROUNDS):
        body = {
            "model": MODEL,
            "messages": messages,
            "tools": TOOL_SPEC,
            "temperature": 0.1,
            "max_tokens": 2000,
        }
        try:
            doc = _post(body, TIMEOUT_S)
        except Exception as e:
            return {
                "verdict": "ERROR", "reason": f"http: {e}"[:200],
                "confidence": "", "rounds": round_idx,
                "latency_s": time.time() - t0, "tool_calls": tool_call_count,
            }

        msg = doc["choices"][0]["message"]
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            # Final message. Parse verdict.
            text = msg.get("content") or ""
            m_v = re.search(r"VERDICT:\s*(KEEP|SUPPRESS|UNCERTAIN)", text, re.I)
            m_r = re.search(r"REASON:\s*(.+)", text)
            m_c = re.search(r"CONFIDENCE:\s*(high|medium|low)", text, re.I)
            return {
                "verdict": m_v.group(1).upper() if m_v else "ERROR",
                "reason": (m_r.group(1).strip()[:200]) if m_r else text[:200],
                "confidence": m_c.group(1).lower() if m_c else "",
                "rounds": round_idx,
                "latency_s": time.time() - t0,
                "tool_calls": tool_call_count,
            }

        # Execute tool calls. Append assistant message + tool responses.
        messages.append({
            "role": "assistant",
            "content": msg.get("content") or "",
            "tool_calls": tool_calls,
        })
        for call in tool_calls:
            tool_call_count += 1
            fn = call.get("function") or {}
            fname = fn.get("name")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if fname == "read_function":
                result = tool_read_function(
                    args.get("file_path") or sample["file"],
                    args.get("function_name") or "",
                )
            else:
                result = json.dumps({"error": f"unknown tool {fname}"})
            messages.append({
                "role": "tool",
                "tool_call_id": call.get("id"),
                "content": result[:3000],
            })

    # Ran out of rounds without a final verdict.
    return {
        "verdict": "ERROR", "reason": "exceeded MAX_ROUNDS without verdict",
        "confidence": "", "rounds": MAX_ROUNDS,
        "latency_s": time.time() - t0, "tool_calls": tool_call_count,
    }


# -- Main ---------------------------------------------------------------------
def main() -> None:
    fps = pick_fps()
    tps = pick_tps()
    samples = [*fps, *tps]
    out_path = Path(os.environ.get("KRYON_SPIKE_OUT", "/workspace/f11_spike.json"))

    print(f"F11.0 tool-augmented spike — {len(samples)} samples")
    print(f"Model: {MODEL}  (tool = read_function)")
    print()
    results: list[dict] = []
    for i, s in enumerate(samples, 1):
        d = decide(s)
        results.append({**s, **d})
        mark = "OK" if (
            (s["ground_truth"] == "FP" and d["verdict"] == "SUPPRESS") or
            (s["ground_truth"] == "TP" and d["verdict"] == "KEEP")
        ) else "??"
        print(f"  [{i:2d}/{len(samples)}] gt={s['ground_truth']} "
              f"verdict={d['verdict']:9s} rounds={d['rounds']} tc={d['tool_calls']} "
              f"{d['latency_s']:5.1f}s {mark}  {s['rel_file'][-45:]}")

    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nraw: {out_path}")

    # -- Precision + latency percentiles ---------------------------------------
    print("\n" + "=" * 72)
    print("RESULTS")
    print("=" * 72)
    by_gt: dict[str, Counter] = {"FP": Counter(), "TP": Counter()}
    for r in results:
        by_gt[r["ground_truth"]][r["verdict"]] += 1

    supp = [r for r in results if r["verdict"] == "SUPPRESS"]
    keep = [r for r in results if r["verdict"] == "KEEP"]
    supp_fp = sum(1 for r in supp if r["ground_truth"] == "FP")
    keep_tp = sum(1 for r in keep if r["ground_truth"] == "TP")
    supp_prec = supp_fp / len(supp) if supp else 0.0
    keep_prec = keep_tp / len(keep) if keep else 0.0

    lats = [r["latency_s"] for r in results]
    p50 = _percentile(lats, 0.5)
    p95 = _percentile(lats, 0.95)
    lmax = max(lats) if lats else 0.0
    tool_uses = sum(r["tool_calls"] for r in results)
    err = sum(1 for r in results if r["verdict"] == "ERROR")

    print(f"  FPs (n={len(fps)}): {dict(by_gt['FP'])}")
    print(f"  TPs (n={len(tps)}): {dict(by_gt['TP'])}")
    print(f"  SUPPRESS precision = {supp_prec*100:5.1f}%   n={len(supp)}")
    print(f"  KEEP     precision = {keep_prec*100:5.1f}%   n={len(keep)}")
    print(f"  Latency  p50={p50:.1f}s  p95={p95:.1f}s  max={lmax:.1f}s")
    print(f"  Tool calls total = {tool_uses}  (avg {tool_uses/len(results):.2f}/finding)")
    print(f"  Errors = {err}")

    # -- Gate ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("GATE")
    print("=" * 72)
    if supp_prec >= 0.75:
        print(f"  PASS — SUPPRESS precision {supp_prec*100:.1f}% >= 75%. Authorise F11.1.")
    elif supp_prec >= 0.60:
        print(f"  GREY  — SUPPRESS precision {supp_prec*100:.1f}% in [60, 75). Re-scope.")
    else:
        print(f"  KILL  — SUPPRESS precision {supp_prec*100:.1f}% < 60%. Model ceiling confirmed.")

    # Compare vs F10.3 spike baseline if present
    prior = Path("/workspace/f10_spike_qwen.json")
    if prior.is_file():
        p = json.loads(prior.read_text())
        p_supp = [r for r in p if r["verdict"] == "SUPPRESS"]
        p_fp = sum(1 for r in p_supp if r["ground_truth"] == "FP")
        p_prec = p_fp / len(p_supp) if p_supp else 0.0
        print(f"\n  F10.3 baseline (no tools): SUPPRESS precision {p_prec*100:.1f}% n={len(p_supp)}")
        print(f"  F11.0 tool-augmented:      SUPPRESS precision {supp_prec*100:.1f}% n={len(supp)}")
        print(f"  Delta: {(supp_prec - p_prec)*100:+.1f}pp")


if __name__ == "__main__":
    main()
