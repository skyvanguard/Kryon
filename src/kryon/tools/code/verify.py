"""verify_finding — agentic single-finding verification (gap #3).

The zero-day loop can only verify findings in *batch*, inside a full
``hunt_zero_days`` run. But the agent often has ONE finding from somewhere
else — a web pentest, a semgrep hit, a report the operator pasted — and wants
to know if it's real. This exposes the same oracle for a single finding.

It builds a ``SourceFinding`` from the args and runs it through the closed loop
(``zeroday_verify.build_default_loop``): memory bugs go to ASAN, injection/
deser/traversal go to a canary harness, and the novelty gate says known-vs-new.
This is the eslabón that turns ALLEGED → CONFIRMED agentically, in any context.

Safety: it EXECUTES a model-generated PoC, so it's double-gated — the arg is a
finding, but nothing runs unless ``KRYON_ZERODAY_VERIFY`` is on. Off = a note
telling the operator how to enable it.
"""

from __future__ import annotations

import os
from pathlib import Path

from kryon.sdk.agents import function_tool


def _gate_on() -> bool:
    return os.environ.get("KRYON_ZERODAY_VERIFY", "").strip().lower() in ("1", "true", "yes", "on")


def _verify_impl(
    file: str,
    line: int,
    cwe: str,
    title: str = "",
    evidence: str = "",
    sink: str = "",
    code_root: str = ".",
    severity: str = "MEDIUM",
) -> str:
    """Implementation, separated from the function_tool wrapper for tests."""
    if not _gate_on():
        return (
            "Verification is OFF. Set KRYON_ZERODAY_VERIFY=true to prove this finding "
            "with ASAN (memory bugs) or a canary harness (injection/deser/traversal). "
            "It executes a generated PoC, so it stays gated + inside the container."
        )

    try:
        from kryon.intelligence.source_review import SourceFinding
        from kryon.intelligence.zeroday_verify import build_default_loop
    except ImportError as e:
        return f"ERROR: verification stack unavailable: {e}"

    try:
        ln = max(0, int(line))
    except (TypeError, ValueError):
        ln = 0

    finding = SourceFinding(
        file=file,
        line=ln,
        cwe=(cwe or "").upper().strip(),
        severity=(severity or "MEDIUM").upper().strip(),
        title=title or cwe,
        evidence=evidence,
        sink=sink or evidence,
        confidence=0.5,
    )
    root = Path(code_root).expanduser()

    try:
        out = build_default_loop(root)([finding])
    except Exception as e:  # noqa: BLE001 — surface to the model, don't crash the turn
        return f"ERROR during verification: {type(e).__name__}: {e}"

    if not out:
        return "No verification result produced."
    vf = out[0]

    if vf.verified:
        verdict = "✅ CONFIRMED" + (f" — ASAN {vf.crash_type}" if vf.crash_type else "")
    elif vf.verification_verdict == "unsupported":
        verdict = "⚠ no oracle for this class (not a memory or injection/deser bug)"
    elif vf.verification_verdict:
        verdict = f"❌ {vf.verification_verdict}"
    else:
        verdict = "unverified"

    if vf.novelty_verdict == "likely-novel":
        nov = "🎯 NOVEL — no known CVE looks like this"
    elif vf.novelty_verdict == "likely-known":
        nov = f"known — resembles {vf.nearest_cve or 'a CVE'}"
    elif vf.novelty_verdict == "uncertain":
        nov = "uncertain (resembles a CVE but not identical)"
    else:
        nov = "not assessed (no corpus)"

    return "\n".join(
        [
            f"# Verificación — {vf.cwe} · `{vf.file}:{vf.line}`",
            "",
            f"**Verdict**: {verdict}",
            f"**Novelty**: {nov}",
        ]
    )


@function_tool(strict_mode=False)
def verify_finding(
    file: str,
    line: int,
    cwe: str,
    title: str = "",
    evidence: str = "",
    sink: str = "",
    code_root: str = ".",
    severity: str = "MEDIUM",
) -> str:
    """Verify (prove) a SINGLE vulnerability finding against its oracle.

    Use this when you have one specific finding — from a web pentest, a semgrep
    hit, a pasted report, or your own reasoning — and want to know if it's REAL,
    not just alleged. Memory bugs (C/C++) are proven with AddressSanitizer;
    injection / deserialization / path-traversal with a canary harness. Also
    reports whether it's a NOVEL bug or a re-detected known CVE.

    Args:
        file: Path to the source file (relative to code_root) holding the bug.
        line: Line number of the vulnerable code.
        cwe: The CWE id, e.g. "CWE-89" (SQLi) or "CWE-787" (out-of-bounds write).
        title: Short description of the vulnerability.
        evidence: The exact vulnerable line(s) — the more precise, the better the PoC.
        sink: The dangerous call/expression (defaults to evidence).
        code_root: Root directory the file path is relative to (default ".").
        severity: CRITICAL | HIGH | MEDIUM | LOW.

    Returns the verdict (CONFIRMED / not-reproduced / poc-build-failed / …) and
    the novelty verdict (NOVEL vs a known CVE). Requires KRYON_ZERODAY_VERIFY=true
    to actually run (it executes a generated PoC).
    """
    return _verify_impl(file, line, cwe, title, evidence, sink, code_root, severity)
