"""F200.A — Shared fingerprint helper for Tomcat checks.

Each TOMCAT-* check needs the same recon data (version, manager
status, AJP status). Without caching, 8 checks × 5 HTTP probes each
= 40 round trips. With LRU caching keyed by (host, port), we do 5
probes total per (host, port).

The LRU is intentionally process-local (not file-cached) so test
runs don't pollute each other.
"""

from __future__ import annotations

import time
from functools import lru_cache

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.tools.web.tomcat_recon import TomcatFingerprint, _fingerprint_one


@lru_cache(maxsize=64)
def fingerprint(host: str, port: int = 8080, scheme: str = "http") -> TomcatFingerprint:
    """Fetch the Tomcat fingerprint once per (host, port, scheme).

    Cached for the lifetime of the process — safe because the check
    runner spins up a fresh interpreter per audit.
    """
    return _fingerprint_one(host, port, scheme)


def target_port(ctx: CheckContext) -> int:
    """Resolve the Tomcat port from CheckContext.

    Defaults to 8080 (Tomcat's canonical HTTP connector). Operators
    can override per-engagement via KRYON_TOMCAT_PORT env if needed
    (e.g. when Tomcat sits behind a non-standard load-balancer port).
    """
    import os

    raw = os.environ.get("KRYON_TOMCAT_PORT", "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return 8080


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


def na_result(check, *, ctx: CheckContext, reason: str, t0: float) -> CheckResult:
    return make_result(
        check=check,
        verdict="N/A",
        cmd="tomcat_recon",
        out="",
        err="",
        parsed={"reason": reason},
        t0=t0,
        ctx=ctx,
    )
