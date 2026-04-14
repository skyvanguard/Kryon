"""F7.4 benchmark — taint queries + Python guard post-filter.

Adversarial setup: each Juliet test file contains 3 functions in the same
CPG: `_bad`, `goodG2B`, `goodB2G`. Correct behavior:

  bad     → detected as vulnerable (true positive)
  goodG2B → not detected (true negative — uses safe source, same sink)
  goodB2G → not detected (true negative — same source, guard before sink)

The structural guard filter inspects every node in the taint flow path and
drops flows that transit through a CONTROL_STRUCTURE whose code mentions
the tainted identifier (indicating a bounds/value check).

Gate:
  recall (bad)   >= 80%
  fpr (good*)    <= 40%
  stop if fpr    >  60% after filter
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from cpgqls_client import CPGQLSClient

SERVER = "127.0.0.1:8080"
CPG_DIR = "/tmp/f7-cpgs"

# -----------------------------------------------------------------------------
# CPGQL queries. We return a JSON-serialisable string so we can json.loads()
# in Python without fighting Scala pretty-printing. Joern has ujson bundled.
# -----------------------------------------------------------------------------

def _flow_query(source_pattern: str, sink_expr: str) -> str:
    """Build a CPGQL query whose final value is JSON with:
      { "flows": [...],  "guards": { method_name: [control_struct_codes] } }

    `reachableByFlows` returns only data-flow nodes (IDENTIFIER/CALL/LITERAL)
    — CONTROL_STRUCTURE nodes are NOT in the path. So we emit the flows plus
    a separate per-method list of guards (if/while conditions) and let the
    Python post-filter correlate by tainted identifier.
    """
    return f"""
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
val sources = cpg.call.name("{source_pattern}").l
val sinks   = {sink_expr}
val flows   = sinks.reachableByFlows(sources.argument).l

val flowsJs = ujson.Arr.from(flows.map {{ f =>
  val methodName = f.elements.collectFirst {{ case n: CfgNode => n.method.name }}.getOrElse("?")
  ujson.Obj(
    "method" -> methodName,
    "path" -> ujson.Arr.from(f.elements.map {{ n =>
      ujson.Obj(
        "line"  -> n.lineNumber.map(_.toInt).getOrElse(-1),
        "label" -> n.label,
        "code"  -> n.code.replaceAll("[\\n\\r\\t]", " ").take(200)
      )
    }})
  )
}})

// Collect all control structures grouped by method name. Each method
// present in `flows` gets a list of if/while/switch conditions so the
// Python post-filter can decide whether any guard references the
// tainted variable between source and sink.
val methodNames = flows.map(_.elements.collectFirst {{ case n: CfgNode => n.method.name }}.getOrElse("?")).toSet
val guardsJs = ujson.Obj()
for (m <- methodNames) {{
  val ctrls = cpg.method.name(m).controlStructure.l
  val items = ctrls.map(c => ujson.Obj(
    "line" -> c.lineNumber.map(_.toInt).getOrElse(-1),
    "type" -> c.controlStructureType,
    "code" -> c.code.replaceAll("[\\n\\r\\t]", " ").take(200)
  ))
  guardsJs(m) = ujson.Arr.from(items)
}}

// Base64-encode the output to sidestep Scala's string-literal pretty-printing,
// which doubles up escape sequences when the JSON contains embedded quotes
// (e.g., `"%c"` literals from Juliet sources).
val jsonStr = ujson.write(ujson.Obj("flows" -> flowsJs, "guards" -> guardsJs))
java.util.Base64.getEncoder.encodeToString(jsonStr.getBytes("UTF-8"))
"""


QUERY_CWE_121 = _flow_query(
    "recv|read|fgets|atoi|scanf|fscanf",
    'cpg.call.name("<operator>.indirectIndexAccess").argument(2).l',
)

QUERY_CWE_190 = _flow_query(
    "fscanf|scanf|recv|read|fgets|atoi",
    'cpg.call.name("<operator>.addition|<operator>.multiplication|<operator>.subtraction").argument.l',
)


_B64_RE = re.compile(r"val\s+res\d+:\s*String\s*=\s*\"([A-Za-z0-9+/=]+)\"")


def extract_payload(stdout: str) -> dict:
    """Decode the base64-wrapped payload from Joern stdout.

    The CPGQL server pretty-prints the last expression. We make the last
    expression a base64 string so embedded quotes and control chars in
    source-code snippets (e.g., Juliet's `"%c"` format strings) can't
    break JSON parsing after Scala's double-quote escape layer.
    """
    import base64

    s = re.sub(r"\x1b\[[0-9;]*m", "", stdout)
    m = _B64_RE.search(s)
    if not m:
        return {"flows": [], "guards": {}}
    try:
        raw = base64.b64decode(m.group(1)).decode("utf-8")
    except Exception as exc:
        print(f"  [b64 err] {exc}", file=sys.stderr)
        return {"flows": [], "guards": {}}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"  [json err] {exc}  head={raw[:200]}", file=sys.stderr)
        return {"flows": [], "guards": {}}


# -----------------------------------------------------------------------------
# Structural guard filter
# -----------------------------------------------------------------------------


@dataclass
class FlowVerdict:
    method: str
    has_guard: bool
    tainted_vars: list[str]
    guard_code: str | None


def _tainted_vars(path: list[dict]) -> set[str]:
    """Collect candidate tainted identifier names from a flow path."""
    vars_: set[str] = set()
    for n in path:
        code = n.get("code", "").strip()
        if n["label"] == "IDENTIFIER" and code:
            vars_.add(code)
        elif n["label"] == "CALL" and code.startswith("&"):
            vars_.add(code[1:].strip())
    return vars_


# Upper-bound check tokens: catches `data < N`, `data <= sizeof(x)`,
# `data < CHAR_MAX`, and bounded conjunctions like `data < 10 && data >= 0`.
# A bare `data >= 0` is NOT sufficient for an array-index / overflow sink:
# it protects against negative indices but not against the overflow the
# sink actually expresses. We require at least one of:
#   - `<` or `<=` comparison following the tainted var, OR
#   - reference to a *_MAX bound constant.
_UPPER_BOUND_RE = re.compile(
    r"(?:<=?(?!=)[^<>=!&|]{0,40})"
    r"|\bCHAR_MAX\b|\bINT_MAX\b|\bSHRT_MAX\b|\bLONG_MAX\b|\bSIZE_MAX\b"
)


def _has_upper_bound(gcode: str, var: str) -> bool:
    """Does the guard impose an upper bound on `var`?"""
    # Cheap slice: find any occurrence of `var` and look at the clause
    # containing it (split by `&&`/`||`/`)`). If that clause has a `<` or
    # `<=` (not `>=`, not just `>`), accept.
    for clause in re.split(r"\|\||&&|;", gcode):
        if not re.search(rf"\b{re.escape(var)}\b", clause):
            continue
        # `data < X`, `data <= X`
        if re.search(rf"\b{re.escape(var)}\s*<=?\s*[^<>=]", clause):
            return True
        # `X > data`, `X >= data` (upper bound on var in reversed form)
        if re.search(rf"[^<>=]\s*>=?\s*\b{re.escape(var)}\b", clause):
            return True
        # Reference to *_MAX in a comparison anywhere in this clause.
        if re.search(r"\b(?:CHAR|INT|SHRT|LONG|SIZE)_MAX\b", clause) and re.search(
            r"[<>]", clause
        ):
            return True
    return False


def flow_has_guard(path: list[dict], guards: list[dict]) -> tuple[bool, str | None]:
    """Does a structural guard impose an upper bound on the tainted var
    at-or-before the sink? Lower-bound-only checks (`data >= 0`) do NOT
    qualify — they would be a false sanitiser for overflow sinks.
    """
    if not guards:
        return (False, None)
    tainted = _tainted_vars(path)
    if not tainted:
        return (False, None)
    sink_line = path[-1].get("line", -1) if path else -1

    for g in guards:
        gcode = g.get("code", "")
        g_line = g.get("line", -1)
        if sink_line >= 0 and g_line > sink_line:
            continue  # guard after sink can't sanitise
        for var in tainted:
            if _has_upper_bound(gcode, var):
                return (True, gcode[:120])
    return (False, None)


def analyze_flow(path: list[dict], guards: list[dict]) -> FlowVerdict:
    method = path[0].get("method", "?") if path else "?"
    has_g, g_code = flow_has_guard(path, guards)
    return FlowVerdict(method, has_g, sorted(_tainted_vars(path)), g_code)


# -----------------------------------------------------------------------------
# Harness
# -----------------------------------------------------------------------------


_METHOD_LIST_RE = re.compile(r"val\s+res\d+:\s*String\s*=\s*\"([A-Za-z0-9+/=]+)\"")


def list_methods(client: CPGQLSClient) -> list[str]:
    """Return all user-defined Juliet bad/good method names in the loaded CPG."""
    q = """
    import java.util.Base64
    val names = cpg.method.filter(m =>
      m.name.endsWith("_bad") || m.name.startsWith("goodG2B") || m.name.startsWith("goodB2G")
    ).name.l.distinct
    Base64.getEncoder.encodeToString(names.mkString("\\n").getBytes("UTF-8"))
    """
    r = client.execute(q)
    s = re.sub(r"\x1b\[[0-9;]*m", "", r.get("stdout", ""))
    m = _METHOD_LIST_RE.search(s)
    if not m:
        return []
    import base64
    try:
        raw = base64.b64decode(m.group(1)).decode("utf-8")
    except Exception:
        return []
    return [x for x in raw.split("\n") if x]


def classify_cpg(
    client: CPGQLSClient, cpg_path: str, query: str
) -> tuple[list[str], dict[str, bool]]:
    """Return (all_test_methods, {method: detected_after_filter}).

    `all_test_methods` is the full list of bad/good* methods present in the
    CPG — used as the FPR denominator. `detections` covers only methods
    where Joern found at least one flow; absent method → 0 flows → FP=False.
    """
    client.execute("workspace.reset")
    r = client.execute(f'importCpg("{cpg_path}")')
    if not r.get("success"):
        print(f"  [importCpg failed] {str(r)[:200]}", file=sys.stderr)
        return ([], {})

    all_methods = list_methods(client)

    r = client.execute(query)
    if not r.get("success"):
        print(f"  [query failed] {str(r)[:200]}", file=sys.stderr)
        return (all_methods, {})

    payload = extract_payload(r.get("stdout", ""))
    flows = payload.get("flows", [])
    guards_by_method = payload.get("guards", {})

    per_method_verdicts: dict[str, list[FlowVerdict]] = {}
    for f in flows:
        method = f.get("method", "?")
        guards = guards_by_method.get(method, [])
        v = analyze_flow(f.get("path", []), guards)
        v.method = method
        per_method_verdicts.setdefault(method, []).append(v)

    detections: dict[str, bool] = {}
    for method, verdicts in per_method_verdicts.items():
        survivors = [v for v in verdicts if not v.has_guard]
        detections[method] = len(survivors) > 0
    return (all_methods, detections)


def method_label(method_name: str) -> str:
    """Classify a Juliet method name. Variants _02.c, _03.c split goodB2G /
    goodG2B into suffixed versions (goodB2G1, goodB2G2, goodG2B_if, ...)."""
    if method_name.endswith("_bad"):
        return "bad"
    if method_name.startswith("goodG2B"):
        return "goodG2B"
    if method_name.startswith("goodB2G"):
        return "goodB2G"
    return "other"


def main() -> int:
    client = CPGQLSClient(SERVER)
    cpgs = sorted(Path(CPG_DIR).glob("*.cpg"))
    print(f"[F7.4] {len(cpgs)} CPGs to analyse")
    totals = {"bad": [0, 0], "goodG2B": [0, 0], "goodB2G": [0, 0]}  # [detected, total]

    for cpg in cpgs:
        cwe = "121" if "CWE121" in cpg.name else "190"
        query = QUERY_CWE_121 if cwe == "121" else QUERY_CWE_190
        print(f"\n[{cwe}] {cpg.name}")
        all_methods, detections = classify_cpg(client, str(cpg), query)

        # Every bad/good* method in the CPG is a test-point. Joern-found
        # flows that survive the guard filter are detections.
        for method in all_methods:
            label = method_label(method)
            if label == "other":
                continue
            detected = detections.get(method, False)
            totals[label][1] += 1
            if detected:
                totals[label][0] += 1
            mark = "HIT" if detected else "---"
            print(f"   {mark} {label:8s} :: {method}")

    print("\n" + "=" * 60)
    print("F7.4 RESULTS")
    print("=" * 60)
    bad_d, bad_t = totals["bad"]
    g2b_d, g2b_t = totals["goodG2B"]
    b2g_d, b2g_t = totals["goodB2G"]
    good_d = g2b_d + b2g_d
    good_t = g2b_t + b2g_t
    recall = (bad_d / bad_t) if bad_t else 0.0
    fpr = (good_d / good_t) if good_t else 0.0
    print(f"  Recall (bad):        {bad_d:3d}/{bad_t:3d} = {recall*100:5.1f}%  (gate ≥80%)")
    print(f"  FPR   (goodG2B):     {g2b_d:3d}/{g2b_t:3d}")
    print(f"  FPR   (goodB2G):     {b2g_d:3d}/{b2g_t:3d}")
    print(f"  FPR   (total good):  {good_d:3d}/{good_t:3d} = {fpr*100:5.1f}%  (gate ≤40%, stop >60%)")
    print("=" * 60)

    if fpr > 0.60:
        print("FAIL: FPR > 60% — STOP, revisit approach.")
        return 2
    if recall < 0.80 or fpr > 0.40:
        print("SOFT-FAIL: gate not met, iterate on queries/filter.")
        return 1
    print("PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
