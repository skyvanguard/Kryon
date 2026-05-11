"""F11.1 — tool-augmented triage on GnuCash 50 labeled findings.

Closes the F10→F11 arc: does adding read_function + read_lines tools to
qwen3-coder rescue workflow precision on real-world C/C++?

Design anchors (per pre-agreed method):
  - Prompt rewritten from scratch with investigate-first framing (not
    "triage this finding + here's tools"). Induces tool usage explicitly.
  - Deterministic shuffle (seed=43, different from F13.2's 42) to break
    any ordering bias from the snippet-only baseline run.
  - Per-finding wall cap 90s; timeout → KEEP (conservative, doesn't hide TPs).
  - Tool usage instrumented: call count, zero-call rate. If >30% of
    findings have 0 tool calls on smoke → prompt fails, adjust before
    full run.
  - Three secondary metrics: UNCERTAIN rate, SUPPRESS recall, latency
    distribution. At least one usually moves even if primary gate fails.
  - Gate: CI non-overlap with F13.2 baseline CI, not absolute threshold.

Modes:
  --smoke       Run first 5 findings (post-shuffle), diagnose tool usage.
  --full        Run all 50.
  --findings N  Run first N findings.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import time
import urllib.request
from pathlib import Path

CORPUS_ROOT = Path("/workspace/gnucash")  # inside kryon container
LABELED_IN = Path("/tmp/f13_gnucash_labeled.jsonl")
TRIAGED_OUT = Path("/tmp/f11_1_gnucash_triaged.jsonl")
MODEL = "qwen3-coder:30b-32k"
ENDPOINT = "http://ollama:11434/v1"

PER_FINDING_CAP_S = 90
SHUFFLE_SEED = 43


_SYSTEM_PROMPT = """You are a senior security code auditor investigating static
scanner findings on real-world C/C++ code (the GnuCash accounting project,
heavy GLib/GTK macros, C++ smart pointers, std::tie structured bindings).

Each finding you see is a candidate vulnerability the scanner flagged. Your
job is to DECIDE whether it is a real bug (KEEP), a clear false positive
(SUPPRESS), or genuinely unclear from the available context (UNCERTAIN).

CRITICAL: Do NOT decide based only on the code snippet shown. The snippet is
too narrow. You MUST investigate before deciding.

You have two tools:
  - read_function(file, line): returns the full function body containing `line`.
  - read_lines(file, start, end): returns arbitrary line range [start, end].

Typical investigation pattern:
  1. Call read_function on the flagged line to see the whole function.
  2. If you see a guard/check/reassignment that could make this safe, call
     read_lines to look at callers or surrounding context as needed.
  3. Only after you understand the data flow, emit your verdict.

Budget: you have up to 6 tool calls total per finding. Do not loop
indefinitely.

After investigation, reply on a single line in EXACTLY this format:
FINAL: VERDICT=<KEEP|SUPPRESS|UNCERTAIN> REASON=<one short sentence> CONFIDENCE=<high|medium|low>
"""


_USER_TEMPLATE = """Finding to investigate:

- Rule: {rule_id}
- CWE: {cwe}
- File: {file}
- Line: {line_start} (finding span {line_start}-{line_end})
- Scanner message: {message}

Initial snippet (narrow, use tools to expand):
{snippet}

Investigate using the tools, then emit your FINAL verdict line.
"""


_TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "read_function",
            "description": "Return the full function body containing the given line number in the given file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file": {"type": "string", "description": "Relative path inside the GnuCash repo."},
                    "line": {"type": "integer", "description": "Any line number inside the function of interest."},
                },
                "required": ["file", "line"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_lines",
            "description": "Return a specific line range of a file. Use for callers or context beyond the function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "start": {"type": "integer"},
                    "end": {"type": "integer"},
                },
                "required": ["file", "start", "end"],
            },
        },
    },
]


def _read_file(rel: str) -> list[str] | None:
    try:
        return (CORPUS_ROOT / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def tool_read_function(file: str, line: int) -> str:
    lines = _read_file(file)
    if lines is None:
        return f"ERROR: file not found: {file}"
    if not (1 <= line <= len(lines)):
        return f"ERROR: line {line} out of range (file has {len(lines)} lines)"
    # Scan backward for function start (C-ish: line starts with type and (
    # or C++ method signature followed by { on same or next line).
    start = 0
    depth = 0
    # Find opening brace after line's position, then walk back to the line
    # that starts the function signature.
    # Heuristic: walk up, track braces. First '{' seen walking backward at
    # depth 0 marks function body start.
    i = line - 1
    open_brace_line = None
    # Find the most recent { at column 0 (function body convention)
    while i >= 0:
        if re.match(r"^\s*\{", lines[i]) or lines[i].rstrip().endswith("{"):
            open_brace_line = i
            break
        i -= 1
    if open_brace_line is None:
        return f"ERROR: could not locate function start for {file}:{line}"
    # Signature is usually 1-3 lines above the opening brace
    sig_start = max(0, open_brace_line - 3)
    # Walk forward from open_brace_line to find matching close
    end_line = open_brace_line
    depth = 0
    for j in range(open_brace_line, min(len(lines), open_brace_line + 500)):
        depth += lines[j].count("{") - lines[j].count("}")
        if depth == 0 and j > open_brace_line:
            end_line = j
            break
    else:
        end_line = min(open_brace_line + 500, len(lines) - 1)
    body = []
    for k in range(sig_start, end_line + 1):
        body.append(f"{k+1:5d}: {lines[k][:160]}")
    return "\n".join(body)


def tool_read_lines(file: str, start: int, end: int) -> str:
    lines = _read_file(file)
    if lines is None:
        return f"ERROR: file not found: {file}"
    if start < 1 or end < start:
        return f"ERROR: invalid range {start}-{end}"
    end = min(end, len(lines))
    # Clamp absolute window to 200 lines max
    if end - start > 200:
        end = start + 200
    out = []
    for i in range(start - 1, end):
        out.append(f"{i+1:5d}: {lines[i][:160]}")
    return "\n".join(out)


def build_snippet(file_path: str, line_start: int, line_end: int) -> str:
    lines = _read_file(file_path)
    if lines is None:
        return "<file unreadable>"
    lo = max(0, line_start - 4)
    hi = min(len(lines), (line_end or line_start) + 4)
    out = []
    for i in range(lo, hi):
        marker = ">" if line_start <= (i + 1) <= (line_end or line_start) else " "
        out.append(f"{marker}{i+1:>5}: {lines[i][:120]}")
    return "\n".join(out)


_FINAL_RE = re.compile(
    r"VERDICT\s*=\s*(KEEP|SUPPRESS|UNCERTAIN)[^A-Z]*"
    r"REASON\s*=\s*(.+?)\s*CONFIDENCE\s*=\s*(high|medium|low)",
    re.I | re.S,
)


def parse_final(text: str) -> tuple[str, str, str]:
    m = _FINAL_RE.search(text)
    if m:
        return m.group(1).upper(), m.group(2).strip()[:200], m.group(3).lower()
    # Fallback — look for lone verdict tokens
    for v in ("KEEP", "SUPPRESS", "UNCERTAIN"):
        if re.search(rf"\b{v}\b", text):
            return v, text[:200], "low"
    return "ERROR", text[:200], ""


def triage_finding(finding: dict) -> dict:
    t0 = time.time()
    system = {"role": "system", "content": _SYSTEM_PROMPT}
    user = {
        "role": "user",
        "content": _USER_TEMPLATE.format(
            rule_id=finding.get("rule_id", ""),
            cwe=finding.get("cwe", ""),
            file=finding.get("file_path", ""),
            line_start=finding.get("line_start", 0),
            line_end=finding.get("line_end", 0),
            message=finding.get("message", "")[:200],
            snippet=build_snippet(
                finding.get("file_path", ""),
                int(finding.get("line_start", 0)),
                int(finding.get("line_end", 0)),
            ),
        ),
    }
    messages = [system, user]
    tool_call_log: list[dict] = []

    for turn in range(12):  # hard safety cap
        if time.time() - t0 > PER_FINDING_CAP_S:
            return {
                **finding,
                "_f11_verdict": "KEEP",  # conservative fallback
                "_f11_reason": f"TIMEOUT after {turn} turns (cap={PER_FINDING_CAP_S}s)",
                "_f11_confidence": "low",
                "_f11_tool_calls": len(tool_call_log),
                "_f11_tool_log": tool_call_log,
                "_f11_turns": turn,
                "_f11_latency_s": round(time.time() - t0, 2),
                "_f11_timed_out": True,
            }

        body = json.dumps({
            "model": MODEL,
            "messages": messages,
            "tools": _TOOLS_SPEC,
            "tool_choice": "auto",
            "temperature": 0,
            "top_p": 1,
            "max_tokens": 1000,
        }).encode()
        req = urllib.request.Request(
            f"{ENDPOINT}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer ollama",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=PER_FINDING_CAP_S) as r:
                doc = json.loads(r.read())
        except Exception as exc:
            return {
                **finding,
                "_f11_verdict": "ERROR",
                "_f11_reason": f"http: {exc}"[:200],
                "_f11_confidence": "",
                "_f11_tool_calls": len(tool_call_log),
                "_f11_tool_log": tool_call_log,
                "_f11_turns": turn,
                "_f11_latency_s": round(time.time() - t0, 2),
            }

        msg = (doc.get("choices") or [{}])[0].get("message", {}) or {}
        tool_calls = msg.get("tool_calls") or []
        content = msg.get("content") or ""

        if tool_calls:
            # Append the assistant message with tool_calls verbatim
            messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})
            for tc in tool_calls:
                fn = tc.get("function", {}) or {}
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments", "{}") or "{}")
                except json.JSONDecodeError:
                    args = {}
                if name == "read_function":
                    result = tool_read_function(args.get("file", ""), int(args.get("line", 0)))
                elif name == "read_lines":
                    result = tool_read_lines(
                        args.get("file", ""),
                        int(args.get("start", 0)),
                        int(args.get("end", 0)),
                    )
                else:
                    result = f"ERROR: unknown tool {name}"
                tool_call_log.append({"turn": turn, "name": name, "args": args, "result_len": len(result)})
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "name": name,
                    "content": result[:8000],  # cap injection
                })
            continue

        # No tool calls → model produced final content
        verdict, reason, confidence = parse_final(content)
        return {
            **finding,
            "_f11_verdict": verdict,
            "_f11_reason": reason,
            "_f11_confidence": confidence,
            "_f11_tool_calls": len(tool_call_log),
            "_f11_tool_log": tool_call_log,
            "_f11_turns": turn + 1,
            "_f11_latency_s": round(time.time() - t0, 2),
            "_f11_raw_final": content[:500],
        }

    # Hit safety cap
    return {
        **finding,
        "_f11_verdict": "ERROR",
        "_f11_reason": "exceeded 12-turn safety cap without FINAL",
        "_f11_confidence": "",
        "_f11_tool_calls": len(tool_call_log),
        "_f11_tool_log": tool_call_log,
        "_f11_turns": 12,
        "_f11_latency_s": round(time.time() - t0, 2),
    }


def bootstrap_ci(
    labels: list[str],
    predicate,
    n_iter: int = 3000,
    seed: int = 43,
) -> tuple[float, float, float]:
    """Generic bootstrap: predicate returns (numerator_hit, denominator_hit) tuple."""
    items = [(predicate(l)) for l in labels]
    denom = sum(1 for num, den in items if den)
    if denom == 0:
        return 0.0, 0.0, 0.0
    point = sum(1 for num, den in items if num) / denom
    rng = random.Random(seed)
    n = len(items)
    samples = []
    for _ in range(n_iter):
        boot = [items[rng.randrange(n)] for _ in range(n)]
        d = sum(1 for num, den in boot if den)
        if d == 0:
            continue
        samples.append(sum(1 for num, den in boot if num) / d)
    if not samples:
        return point, point, point
    samples.sort()
    return point, samples[int(len(samples) * 0.025)], samples[int(len(samples) * 0.975)]


def summarize(triaged: list[dict]) -> None:
    # Tool usage
    zero_tool = sum(1 for t in triaged if t.get("_f11_tool_calls", 0) == 0)
    avg_tool = sum(t.get("_f11_tool_calls", 0) for t in triaged) / max(1, len(triaged))
    timed_out = sum(1 for t in triaged if t.get("_f11_timed_out"))
    errors = sum(1 for t in triaged if t.get("_f11_verdict") == "ERROR")
    avg_lat = sum(t.get("_f11_latency_s", 0) for t in triaged) / max(1, len(triaged))

    print("\n=== F11.1 tool-augmented triage ===")
    print(f"N: {len(triaged)}")
    print(f"Zero-tool-calls: {zero_tool}/{len(triaged)} = {zero_tool/len(triaged):.1%}")
    print(f"Avg tool calls/finding: {avg_tool:.2f}")
    print(f"Timeouts: {timed_out} | Errors: {errors}")
    print(f"Avg latency: {avg_lat:.1f}s")

    # Verdict distribution
    from collections import Counter
    verdicts = Counter(t.get("_f11_verdict", "?") for t in triaged)
    print(f"\nVerdicts: {dict(verdicts)}")

    # Confusion matrix (needs _label from ground truth)
    labeled_triaged = [t for t in triaged if t.get("_label") in ("TP", "FP")]
    if not labeled_triaged:
        print("\nNo ground-truth labels on triaged items — cannot compute precision.")
        return

    cells: dict[tuple[str, str], int] = {}
    for t in labeled_triaged:
        key = (t["_f11_verdict"], t["_label"])
        cells[key] = cells.get(key, 0) + 1

    print("\n--- Confusion matrix (ground-truth × F11.1 verdict) ---")
    for v in ["KEEP", "SUPPRESS", "UNCERTAIN", "ERROR"]:
        tp = cells.get((v, "TP"), 0)
        fp = cells.get((v, "FP"), 0)
        print(f"  {v:10s}: TP={tp:3d}  FP={fp:3d}")

    # KEEP precision with CI
    keep_labels = [t["_label"] for t in labeled_triaged if t["_f11_verdict"] == "KEEP"]
    point, lo, hi = bootstrap_ci(keep_labels, lambda l: (l == "TP", l in ("TP", "FP")))
    print(f"\nKEEP precision (F11.1): {point:.1%} [{lo:.1%}, {hi:.1%}] (N={len(keep_labels)})")
    print("Baseline F13.2:         57.1% (N=7 — CI wide, computed separately)")

    # SUPPRESS recall
    fp_labels = [t["_label"] for t in labeled_triaged if t["_label"] == "FP"]
    supp_fp = sum(1 for t in labeled_triaged if t["_label"] == "FP" and t["_f11_verdict"] == "SUPPRESS")
    if fp_labels:
        print(f"SUPPRESS recall: {supp_fp}/{len(fp_labels)} = {supp_fp/len(fp_labels):.1%}  "
              f"(baseline 73.0%)")

    # UNCERTAIN rate
    unc = sum(1 for t in triaged if t["_f11_verdict"] == "UNCERTAIN")
    print(f"UNCERTAIN rate: {unc}/{len(triaged)} = {unc/len(triaged):.1%}  "
          f"(baseline 22.0%)")


def main() -> None:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--smoke", action="store_true")
    g.add_argument("--full", action="store_true")
    g.add_argument("--findings", type=int)
    args = ap.parse_args()

    findings = [json.loads(l) for l in LABELED_IN.read_text(encoding="utf-8").splitlines()]
    rng = random.Random(SHUFFLE_SEED)
    rng.shuffle(findings)

    n = 5 if args.smoke else (args.findings if args.findings else len(findings))
    batch = findings[:n]
    print(f"Running F11.1 on {n} findings (shuffled seed={SHUFFLE_SEED})")

    triaged: list[dict] = []
    for i, f in enumerate(batch, 1):
        t = triage_finding(f)
        triaged.append(t)
        print(f"  [{i:2d}/{n}] {t.get('_f11_verdict','?'):10s} "
              f"tools={t.get('_f11_tool_calls',0):2d}  "
              f"lat={t.get('_f11_latency_s',0):.1f}s  "
              f"gt={t.get('_label','?'):3s}  "
              f"{t['file_path']}:{t['line_start']}")
        # Incremental save
        TRIAGED_OUT.write_text(
            "\n".join(json.dumps(x, ensure_ascii=False) for x in triaged) + "\n",
            encoding="utf-8",
        )

    summarize(triaged)


if __name__ == "__main__":
    main()
