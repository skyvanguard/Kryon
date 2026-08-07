"""hunt_zero_days — the agentic entry point to the closed zero-day loop.

Kryon's zero-day stack (source-review + F1 novelty + F2 ASAN + F3 canary) used
to be reachable ONLY via ``kryon investigate <dir>``. But the product goal is a
Claude-Code-style agent: the operator says *"buscá zero-days en este código"*
and the model just does it. This tool is that bridge — a single high-level
capability the unified agent can call, so the whole hunt happens autonomously
inside a normal REPL/TUI turn instead of a rigid CLI subcommand.

It wraps ``source_review.review_tree`` (reason over the tree) and, when
verification is enabled, ``zeroday_verify.build_default_loop`` (prove each
finding with its oracle + filter known CVEs), then formats a report the model
narrates back.

Safety: the verification loop EXECUTES model-generated PoCs (compiles C with
ASAN, runs interpreters), so it is double-gated — the ``verify`` arg AND
``KRYON_ZERODAY_VERIFY`` must both be on, and it must run inside the container's
isolation boundary. Without the gate it returns the raw reasoned review (no
execution), which is banca-safe read-only.
"""

from __future__ import annotations

import os
from pathlib import Path

from kryon.sdk.agents import function_tool


def _gate_on() -> bool:
    return os.environ.get("KRYON_ZERODAY_VERIFY", "").strip().lower() in ("1", "true", "yes", "on")


def _fmt_findings(findings: list, *, verified_loop: bool) -> list[str]:
    """Render findings as markdown, surfacing verification + novelty."""
    lines: list[str] = []
    for f in findings:
        # confirmation tag
        if f.verified:
            tag = "✅ CONFIRMED"
        elif f.verification_verdict and f.verification_verdict not in ("unsupported", ""):
            tag = f"⚠ {f.verification_verdict}"
        else:
            tag = "unverified"
        # novelty tag
        nov = ""
        if f.novelty_verdict == "likely-novel":
            nov = " · 🎯 NOVEL"
        elif f.novelty_verdict == "likely-known":
            nov = f" · known ({f.nearest_cve or 'CVE'})"
        elif f.novelty_verdict == "uncertain":
            nov = " · novelty: uncertain"

        lines.append(f"## [{tag}] {f.severity} · {f.cwe} · `{f.file}:{f.line}`{nov}")
        lines.append(f"**{f.title}** (confidence {f.confidence:.2f})")
        if f.description:
            lines.append("")
            lines.append(f.description)
        if f.evidence:
            lines.append("")
            lines.append(f"```\n{f.evidence}\n```")
        if verified_loop and f.crash_type:
            lines.append(f"_ASAN: {f.crash_type}_")
        lines.append("")
    return lines


def _hunt_impl(code_path: str, max_files: int = 25, verify: bool = True) -> str:
    """Implementation, separated from the function_tool wrapper for tests."""
    root = Path(code_path).expanduser()
    if not root.exists():
        return f"ERROR: code_path does not exist: {code_path}"

    try:
        from kryon.intelligence.source_review import LocalReviewer, review_tree
    except ImportError as e:
        return f"ERROR: source-review unavailable: {e}"

    try:
        wall = float(os.environ.get("KRYON_WALL_BUDGET_S", "") or 0) or None
    except ValueError:
        wall = None

    try:
        result = review_tree(root, reviewer=LocalReviewer(), max_files=max(1, max_files), wall_budget_s=wall)
    except Exception as e:  # noqa: BLE001 — surface the error to the model, don't crash the turn
        return f"ERROR during source review: {type(e).__name__}: {e}"

    findings = result.findings
    verified_loop = False
    summary_line = ""

    if verify and _gate_on():
        try:
            from kryon.intelligence.zeroday_verify import build_default_loop, summarize

            findings = build_default_loop(root)(list(findings))
            summary_line = summarize(findings).as_line()
            verified_loop = True
        except Exception as e:  # noqa: BLE001 — verification best-effort; raw findings still returned
            summary_line = f"(verification loop skipped: {type(e).__name__})"

    header = [
        f"# Zero-day hunt — `{code_path}`",
        "",
        f"**Reviewed**: {result.files_reviewed} files "
        f"(+{result.variant_files_reviewed} via variant analysis) / {result.files_total} total "
        f"· {result.elapsed_seconds:.1f}s",
    ]
    if verify and not _gate_on():
        header.append(
            "_Verification loop OFF (set KRYON_ZERODAY_VERIFY=true to prove findings with "
            "ASAN/canary + filter known CVEs). Findings below are reasoned, unverified._"
        )
    if summary_line:
        header.append(f"**Verification**: {summary_line}")
    header.append("")

    if not findings:
        header.append("_No vulnerabilities surfaced._")
        return "\n".join(header)

    header.append(f"**{len(findings)} findings** (confirmed-and-novel first):")
    header.append("")
    return "\n".join(header + _fmt_findings(findings, verified_loop=verified_loop))


@function_tool(strict_mode=False)
def hunt_zero_days(code_path: str, max_files: int = 25, verify: bool = True) -> str:
    """Hunt vulnerabilities / zero-days in a LOCAL source tree, Mythos-style.

    Call this whenever the operator asks to find bugs, vulnerabilities, or
    zero-days in a code path or directory (e.g. "buscá zero-days en /repo",
    "audita este código", "revisá este source por vulnerabilidades"). It
    reviews the tree by reasoning over each file, and — when verification is
    enabled — PROVES each finding with its oracle (AddressSanitizer for memory
    bugs, a canary harness for injection/deserialization/traversal) and filters
    out re-detected known CVEs, returning confirmed-and-novel findings first.

    Args:
        code_path: Path to the local source directory (or single file) to review.
        max_files: Max files to send to the reviewer under triage (default 25).
        verify: Run the ASAN/canary verification + novelty-filter loop. This
            EXECUTES model-generated PoCs, so it only runs when
            KRYON_ZERODAY_VERIFY is also enabled; otherwise you get the raw
            reasoned review (read-only, no execution).

    Returns a markdown report: per-finding CWE, severity, file:line, the
    verification verdict (CONFIRMED/not-reproduced/…) and the novelty verdict
    (NOVEL vs a known CVE). Confirmed-and-novel findings are the moonshot bucket.
    """
    return _hunt_impl(code_path, max_files, verify)
