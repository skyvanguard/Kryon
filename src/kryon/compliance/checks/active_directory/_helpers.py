"""Shared AD check helpers — env-var read, pre-flight, error wrapping."""

from __future__ import annotations

import os
import time
from typing import Callable

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import run_cmd


def ad_env() -> tuple[str, str, str, str]:
    """Return (domain, user, pass, dc). Empty strings if unset."""
    return (
        os.environ.get("KRYON_AD_DOMAIN", "").strip(),
        os.environ.get("KRYON_AD_USER", "").strip(),
        os.environ.get("KRYON_AD_PASS", "").strip(),
        os.environ.get("KRYON_AD_DC", "").strip(),
    )


def missing_creds_error(
    control_id: str,
    control_title: str,
    section: str,
    severity: str,
    remediation: str,
    host: str,
    t0: float,
    needs: tuple[str, ...] = ("KRYON_AD_DOMAIN", "KRYON_AD_USER", "KRYON_AD_PASS"),
) -> CheckResult:
    return CheckResult(
        control_id=control_id,
        control_title=control_title,
        section=section,
        verdict="ERROR",
        evidence_command=f"env | grep -E '^{'|'.join(needs)}='",
        evidence_stdout="",
        evidence_stderr=(
            f"required env vars missing: {', '.join(needs)}. "
            f"export KRYON_AD_DOMAIN=BANK.LOCAL KRYON_AD_USER=auditor@BANK.LOCAL "
            f"KRYON_AD_PASS='...' KRYON_AD_DC=dc01.bank.local"
        ),
        evidence_parsed={"reason": "missing AD credentials", "needed": list(needs)},
        remediation_static=remediation,
        severity=severity,
        duration_ms=int((time.time() - t0) * 1000),
        host=host,
        run_id="",
    )


def tool_missing_error(
    control_id: str,
    control_title: str,
    section: str,
    severity: str,
    remediation: str,
    host: str,
    t0: float,
    tool: str,
    install_hint: str,
) -> CheckResult:
    return CheckResult(
        control_id=control_id,
        control_title=control_title,
        section=section,
        verdict="ERROR",
        evidence_command=f"command -v {tool}",
        evidence_stdout="",
        evidence_stderr=f"{tool} not found in PATH. Install: {install_hint}",
        evidence_parsed={"reason": "tool missing", "tool": tool, "install": install_hint},
        remediation_static=remediation,
        severity=severity,
        duration_ms=int((time.time() - t0) * 1000),
        host=host,
        run_id="",
    )


def check_tool(ctx: CheckContext, tool: str) -> bool:
    """Returns True if `tool` exists in PATH on ctx.host."""
    out, _, rc = run_cmd(ctx, f"command -v {tool} >/dev/null 2>&1 && echo ok", shell=True, timeout_s=3)
    return rc == 0 and "ok" in out
