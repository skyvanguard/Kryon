"""F199 — shared helpers for Windows checks.

Reduces boilerplate vs the per-file `_err` pattern used by fortigate.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult


def make_result(
    *,
    check,
    verdict: str,
    cmd: str,
    out: str,
    err: str,
    parsed: dict,
    t0: float,
    ctx: CheckContext,
) -> CheckResult:
    """Build a CheckResult with the standard truncation + duration."""
    return CheckResult(
        control_id=check.control_id,
        control_title=check.control_title,
        section=check.section,
        verdict=verdict,
        evidence_command=cmd,
        evidence_stdout=out[:2048],
        evidence_stderr=err[:512],
        evidence_parsed=parsed,
        remediation_static=check.remediation_static,
        severity=check.severity,
        duration_ms=int((time.time() - t0) * 1000),
        host=ctx.host,
        run_id="",
    )


def make_error(check, *, cmd: str, out: str, err: str, t0: float, ctx: CheckContext, reason: str) -> CheckResult:
    return make_result(
        check=check,
        verdict="ERROR",
        cmd=cmd,
        out=out,
        err=err,
        parsed={"reason": reason},
        t0=t0,
        ctx=ctx,
    )
