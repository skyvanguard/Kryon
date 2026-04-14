"""
joern_scan — @function_tool wrapper around the Joern CPGQL server (F7.2).

Data-flow analysis complement to semgrep_scan. Catches Juliet variants
regex/AST cannot: socket->array-index (CWE-121/129) and
recv->atoi->multiply (CWE-190). Backed by the `joern` docker-compose
service running joern --server on the kryon-mgmt network.

## Concurrency invariant

**One caller at a time.** `workspace.reset` is destructive and global —
two concurrent scans on the same server silently corrupt each other's
results. A module-level threading.Lock serialises all calls. Future
multi-agent setups must NOT remove this lock before introducing per-CPG
project isolation in the Joern side.

## Failure modes — noisy, not silent

- Server down or unreachable -> {"status": "unavailable", ...}
- Timeout on import or query -> {"status": "timeout", ...}
- Query raised on Joern side -> {"status": "error", ...}

A hybrid hunter that unions Joern with semgrep/heuristic MUST distinguish
"status == ok with empty findings" (target really clean w.r.t. these
patterns) from "status != ok" (no signal, do NOT treat as clean).

## Return schema (converged with semgrep_scan)

```
{
  "status": "ok" | "unavailable" | "timeout" | "error",
  "count": N,
  "target": str,
  "cwe_focus": "121" | "190" | "auto",
  "findings": [
    {
      "path": str,
      "start_line": int,
      "end_line": int,
      "rule_id": "joern.cwe-121.tainted-array-index",
      "check_id": same as rule_id,
      "severity": "ERROR" | "WARNING",
      "confidence": "high" | "medium" | "low",
      "cwe": "CWE-121",
      "message": str,
      "method": str,              # function containing the sink
      "flow": [{"line", "label", "code"}, ...]
    }
  ],
  "stats": {"parse_ms": int, "query_ms": int},
  "reason": str,                  # set when status != ok
}
```
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

_DEFAULT_SERVER = os.environ.get("KRYON_JOERN_URL", "ws://joern:8080")
_ENABLED = os.environ.get("KRYON_JOERN_ENABLED", "false").strip().lower() in {
    "1", "true", "yes", "on",
}
_DEFAULT_IMPORT_TIMEOUT_S = int(os.environ.get("KRYON_JOERN_IMPORT_TIMEOUT_S", "120"))
_DEFAULT_QUERY_TIMEOUT_S = int(os.environ.get("KRYON_JOERN_QUERY_TIMEOUT_S", "60"))
_DEFAULT_MAX_FINDINGS = int(os.environ.get("KRYON_JOERN_MAX_FINDINGS", "200"))

# Global serialisation lock — see module docstring.
_SCAN_LOCK = threading.Lock()

_B64_RE = re.compile(r'val\s+res\d+:\s*String\s*=\s*"([A-Za-z0-9+/=]+)"')

# -----------------------------------------------------------------------------
# CPGQL queries. Both end with a base64-encoded JSON string so Scala's
# string-literal escape layer cannot mangle source-code snippets containing
# embedded quotes ("%c" etc.) or control characters.
# -----------------------------------------------------------------------------


def _flow_query(source_pattern: str, sink_expr: str) -> str:
    return f"""
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
val sources = cpg.call.name("{source_pattern}").l
val sinks   = {sink_expr}
val flows   = sinks.reachableByFlows(sources.argument).l

val flowsJs = ujson.Arr.from(flows.map {{ f =>
  val methodName = f.elements.collectFirst {{ case n: CfgNode => n.method.name }}.getOrElse("?")
  val fileName   = f.elements.collectFirst {{ case n: CfgNode => n.file.name.headOption.getOrElse("") }}.getOrElse("")
  ujson.Obj(
    "method" -> methodName,
    "file"   -> fileName,
    "path" -> ujson.Arr.from(f.elements.map {{ n =>
      ujson.Obj(
        "line"  -> n.lineNumber.map(_.toInt).getOrElse(-1),
        "label" -> n.label,
        "code"  -> n.code.replaceAll("[\\n\\r\\t]", " ").take(200)
      )
    }})
  )
}})

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

val jsonStr = ujson.write(ujson.Obj("flows" -> flowsJs, "guards" -> guardsJs))
java.util.Base64.getEncoder.encodeToString(jsonStr.getBytes("UTF-8"))
"""


_QUERIES: dict[str, tuple[str, str, str, str]] = {
    # (cwe_label, source_pattern, sink_expr, rule_id)
    "121": (
        "CWE-121",
        "recv|read|fgets|atoi|scanf|fscanf",
        'cpg.call.name("<operator>.indirectIndexAccess").argument(2).l',
        "joern.cwe-121.tainted-array-index",
    ),
    "190": (
        "CWE-190",
        "fscanf|scanf|recv|read|fgets|atoi",
        'cpg.call.name("<operator>.addition|<operator>.multiplication|<operator>.subtraction").argument.l',
        "joern.cwe-190.tainted-arith",
    ),
}


# -----------------------------------------------------------------------------
# Python post-filter: structural guard detection
# -----------------------------------------------------------------------------


def _tainted_vars(path: list[dict]) -> set[str]:
    vars_: set[str] = set()
    for n in path:
        code = (n.get("code") or "").strip()
        if n.get("label") == "IDENTIFIER" and code:
            vars_.add(code)
        elif n.get("label") == "CALL" and code.startswith("&"):
            vars_.add(code[1:].strip())
    return vars_


def _has_upper_bound(gcode: str, var: str) -> bool:
    """Does this guard clause impose an upper bound on var? `>= 0` alone
    is NOT enough for array-index / overflow sinks — we require `<`, `<=`,
    or a *_MAX constant reference."""
    for clause in re.split(r"\|\||&&|;", gcode):
        if not re.search(rf"\b{re.escape(var)}\b", clause):
            continue
        if re.search(rf"\b{re.escape(var)}\s*<=?\s*[^<>=]", clause):
            return True
        if re.search(rf"[^<>=]\s*>=?\s*\b{re.escape(var)}\b", clause):
            return True
        if re.search(r"\b(?:CHAR|INT|SHRT|LONG|SIZE)_MAX\b", clause) and re.search(
            r"[<>]", clause
        ):
            return True
    return False


def _flow_has_guard(path: list[dict], guards: list[dict]) -> bool:
    if not guards:
        return False
    tainted = _tainted_vars(path)
    if not tainted:
        return False
    sink_line = path[-1].get("line", -1) if path else -1
    for g in guards:
        g_line = g.get("line", -1)
        if sink_line >= 0 and g_line > sink_line:
            continue
        gcode = g.get("code") or ""
        for var in tainted:
            if _has_upper_bound(gcode, var):
                return True
    return False


# -----------------------------------------------------------------------------
# Timeout-aware CPGQL client wrapper
# -----------------------------------------------------------------------------


@dataclass
class _JoernError(Exception):
    status: str  # "unavailable" | "timeout" | "error"
    reason: str
    phase: str = ""


def _execute_with_timeout(client, query: str, timeout_s: int, phase: str) -> dict:
    """Run client.execute(query) in a fresh thread with a hard timeout.

    Each call uses its own thread + event loop because cpgqls-client does
    `asyncio.get_event_loop()` at __init__ AND internally, which fails on
    Python 3.11+ when no loop is bound to the current thread. The outer
    `_SCAN_LOCK` already guarantees only one such thread runs at a time,
    so there is no contention with the executor model.
    """
    result: dict = {}
    exc_holder: list[BaseException] = []

    def _runner():
        try:
            # Bind a fresh event loop to this thread so cpgqls-client's
            # `asyncio.get_event_loop()` resolves cleanly.
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                client._loop = loop  # noqa: SLF001 — point client at our loop
                result.update(client.execute(query))
            finally:
                loop.close()
        except BaseException as e:  # noqa: BLE001
            exc_holder.append(e)

    t = threading.Thread(target=_runner, name="joern-call", daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    if t.is_alive():
        # Leak the thread — it will finish when the websocket times out
        # internally. Safe: next call begins with workspace.reset.
        raise _JoernError("timeout", f"{phase} exceeded {timeout_s}s", phase)
    if exc_holder:
        raise _JoernError(
            "error", f"{phase} raised: {exc_holder[0]!r}", phase
        ) from exc_holder[0]
    return result


def _get_payload(result: dict) -> dict:
    """Decode the base64-wrapped JSON payload from Joern stdout."""
    if not result.get("success"):
        raise _JoernError(
            "error",
            f"query failed: {str(result.get('stderr') or result)[:200]}",
        )
    s = re.sub(r"\x1b\[[0-9;]*m", "", result.get("stdout", ""))
    m = _B64_RE.search(s)
    if not m:
        return {"flows": [], "guards": {}}
    try:
        raw = base64.b64decode(m.group(1)).decode("utf-8")
        return json.loads(raw)
    except Exception as exc:
        raise _JoernError("error", f"payload decode: {exc}") from exc


def _connect(server: str):
    """Create a CPGQLSClient. Raises _JoernError(unavailable) on failure.

    The cpgqls-client constructor calls `asyncio.get_event_loop()` which
    raises in worker threads on Python 3.11+. We ensure a loop exists for
    the calling thread before constructing the client.
    """
    try:
        from cpgqls_client import CPGQLSClient
    except ImportError as exc:
        raise _JoernError(
            "unavailable",
            "cpgqls-client not installed — install pip extra `dataflow`",
        ) from exc

    # Guarantee a running event loop for this thread before CPGQLSClient init.
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    endpoint = re.sub(r"^wss?://", "", server).rstrip("/")
    try:
        return CPGQLSClient(endpoint)
    except Exception as exc:
        raise _JoernError("unavailable", f"connect {server!r}: {exc}") from exc


# -----------------------------------------------------------------------------
# Finding normalisation
# -----------------------------------------------------------------------------


def _severity_to_confidence(severity: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(severity, "medium")


def _make_finding(
    cwe: str,
    rule_id: str,
    method: str,
    file_path: str,
    flow_path: list[dict],
) -> dict:
    """Emit a single normalised finding record."""
    sink = flow_path[-1] if flow_path else {}
    src = flow_path[0] if flow_path else {}
    sink_line = int(sink.get("line") or 0)
    severity = "ERROR"
    return {
        "path": file_path or "",
        "start_line": sink_line,
        "end_line": sink_line,
        "rule_id": rule_id,
        "check_id": rule_id,
        "severity": severity,
        "confidence": _severity_to_confidence(severity),
        "cwe": cwe,
        "message": (
            f"Tainted data from {src.get('code','source')!s} reaches "
            f"{sink.get('code','sink')!s} without upper-bound validation"
        )[:500],
        "method": method or "",
        "flow": flow_path,
    }


def _is_cpg(path: Path) -> bool:
    return path.is_file() and path.suffix == ".cpg"


# -----------------------------------------------------------------------------
# Main implementation
# -----------------------------------------------------------------------------


def _import_target(
    client,
    target: Path,
    import_timeout_s: int,
) -> int:
    """workspace.reset + import. Returns wall-clock ms."""
    t0 = time.perf_counter()
    _execute_with_timeout(client, "workspace.reset", timeout_s=30, phase="reset")
    if _is_cpg(target):
        cmd = f'importCpg("{target}")'
    else:
        # importCode parses source dir / file into a fresh CPG.
        cmd = f'importCode("{target}")'
    _execute_with_timeout(client, cmd, timeout_s=import_timeout_s, phase="import")
    return int((time.perf_counter() - t0) * 1000)


def _run_one_query(
    client,
    cwe_key: str,
    query_timeout_s: int,
    max_findings: int,
) -> tuple[list[dict], int]:
    cwe_label, source_pattern, sink_expr, rule_id = _QUERIES[cwe_key]
    q = _flow_query(source_pattern, sink_expr)
    t0 = time.perf_counter()
    res = _execute_with_timeout(client, q, timeout_s=query_timeout_s, phase="query")
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    payload = _get_payload(res)
    flows = payload.get("flows", [])
    guards_by_method = payload.get("guards", {})

    findings: list[dict] = []
    for f in flows:
        path_nodes = f.get("path", []) or []
        method = f.get("method", "")
        guards = guards_by_method.get(method, [])
        if _flow_has_guard(path_nodes, guards):
            continue
        findings.append(
            _make_finding(cwe_label, rule_id, method, f.get("file", ""), path_nodes)
        )
        if len(findings) >= max_findings:
            break
    return (findings, elapsed_ms)


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    """Collapse duplicate flows that Joern emits for the same (method, sink)."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        key = (f["path"], f["start_line"], f["cwe"], f["method"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _joern_scan_impl(
    target_path: str,
    cwe_focus: str,
    import_timeout_s: int,
    query_timeout_s: int,
    max_findings: int,
) -> str:
    if not _ENABLED:
        return json.dumps({
            "status": "unavailable",
            "reason": "KRYON_JOERN_ENABLED is not true — bring up the "
                      "`joern` compose service (profile: dataflow)",
            "count": 0,
            "findings": [],
            "target": target_path,
        })

    target = Path(target_path)
    if not target.exists():
        return json.dumps({
            "status": "error",
            "reason": f"target not found: {target_path}",
            "count": 0,
            "findings": [],
            "target": target_path,
        })

    keys = list(_QUERIES.keys()) if cwe_focus == "auto" else [cwe_focus]
    unknown = [k for k in keys if k not in _QUERIES]
    if unknown:
        return json.dumps({
            "status": "error",
            "reason": f"unsupported cwe_focus={unknown!r}, known: {list(_QUERIES)}",
            "count": 0,
            "findings": [],
            "target": target_path,
        })

    with _SCAN_LOCK:
        try:
            client = _connect(_DEFAULT_SERVER)
            parse_ms = _import_target(client, target, import_timeout_s)
            all_findings: list[dict] = []
            total_query_ms = 0
            for k in keys:
                try:
                    findings, q_ms = _run_one_query(
                        client, k, query_timeout_s, max_findings
                    )
                    all_findings.extend(findings)
                    total_query_ms += q_ms
                except _JoernError as exc:
                    logger.warning("joern query %s failed: %s", k, exc.reason)
                    # Continue with remaining CWEs, but surface the error in status.
                    return json.dumps({
                        "status": exc.status,
                        "reason": f"cwe={k}: {exc.reason}",
                        "phase": exc.phase,
                        "count": len(all_findings),
                        "findings": _dedupe_findings(all_findings)[:max_findings],
                        "target": target_path,
                    })
            all_findings = _dedupe_findings(all_findings)[:max_findings]
            return json.dumps({
                "status": "ok",
                "count": len(all_findings),
                "target": target_path,
                "cwe_focus": cwe_focus,
                "findings": all_findings,
                "stats": {"parse_ms": parse_ms, "query_ms": total_query_ms},
            })
        except _JoernError as exc:
            return json.dumps({
                "status": exc.status,
                "reason": exc.reason,
                "phase": exc.phase,
                "count": 0,
                "findings": [],
                "target": target_path,
            })
        except Exception as exc:  # catch-all: never raise to the agent
            logger.exception("joern_scan fatal")
            return json.dumps({
                "status": "error",
                "reason": f"unexpected: {exc!r}",
                "count": 0,
                "findings": [],
                "target": target_path,
            })


@function_tool(strict_mode=False)
def joern_scan(
    target_path: str,
    cwe_focus: str = "auto",
    import_timeout_s: int = _DEFAULT_IMPORT_TIMEOUT_S,
    query_timeout_s: int = _DEFAULT_QUERY_TIMEOUT_S,
    max_findings: int = _DEFAULT_MAX_FINDINGS,
) -> str:
    """Data-flow (taint) scan via Joern CPGQL. Complements semgrep_scan.

    Catches tainted-source -> unchecked-sink flows that regex/AST miss:
    socket->recv->array-index (CWE-121/129), scanf->arithmetic (CWE-190).
    A Python post-filter drops flows sanitised by an upper-bound guard on
    the tainted variable (lower-bound-only `data >= 0` is NOT treated as
    sufficient for overflow sinks).

    NOTE: this tool serialises — only one call at a time runs on the
    Joern server. If the agent has multiple concurrent scans, they queue.

    NOTE: failure is noisy. status in {"unavailable","timeout","error"}
    means "no signal" — do NOT conclude the target is clean.

    Args:
        target_path: Absolute path to a .cpg file (preferred for speed)
            or a source directory/file to be parsed on the fly.
        cwe_focus: "auto" runs all supported CWEs. Or pass "121" / "190"
            to target one. Unknown values return an error status.
        import_timeout_s: Max seconds for workspace.reset + importCpg/Code.
        query_timeout_s: Max seconds per taint query.
        max_findings: Cap returned findings (post-dedupe).

    Returns JSON matching the converged schema — see module docstring.
    """
    return _joern_scan_impl(
        target_path=target_path,
        cwe_focus=cwe_focus,
        import_timeout_s=import_timeout_s,
        query_timeout_s=query_timeout_s,
        max_findings=max_findings,
    )
