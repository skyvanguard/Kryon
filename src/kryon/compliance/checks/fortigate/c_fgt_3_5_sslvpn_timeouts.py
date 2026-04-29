"""FGT-3.5 — SSL VPN session timeouts are reasonable.

Idle and absolute (`auth-timeout`) limits on SSL VPN sessions:
  - idle-timeout > 30 minutes is too lenient
  - auth-timeout > 28800 seconds (8h) means a stolen session is reusable
    long after the working day
PCI-DSS 8.1.8 caps idle at 15 min for in-scope systems.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


_MAX_IDLE_SEC = 1800       # 30 min
_MAX_AUTH_SEC = 28800      # 8 h


class _SslVpnTimeoutsCheck:
    control_id = "FGT-3.5"
    control_title = (
        f"SSL VPN idle <= {_MAX_IDLE_SEC // 60} min, auth <= {_MAX_AUTH_SEC // 3600}h"
    )
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "config vpn ssl settings\n"
        f"  set idle-timeout {_MAX_IDLE_SEC}\n"
        f"  set auth-timeout {_MAX_AUTH_SEC}\n"
        "  set login-timeout 30                # quick fail on stalled login\n"
        "end"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show full-configuration vpn ssl settings"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read sslvpn settings"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        def num(name: str, default: int) -> int:
            m = re.search(rf"^\s*set\s+{re.escape(name)}\s+(\d+)", out, re.M)
            try:
                return int(m.group(1)) if m else default
            except (ValueError, AttributeError):
                return default

        idle = num("idle-timeout", 300)         # FortiOS default 300s
        auth = num("auth-timeout", 28800)       # FortiOS default 8h

        issues: list[str] = []
        if idle > _MAX_IDLE_SEC:
            issues.append(f"idle-timeout={idle}s > {_MAX_IDLE_SEC}s (30min)")
        if auth > _MAX_AUTH_SEC:
            issues.append(f"auth-timeout={auth}s > {_MAX_AUTH_SEC}s (8h)")

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed={
                "idle_timeout_sec": idle,
                "auth_timeout_sec": auth,
                "max_idle_sec": _MAX_IDLE_SEC,
                "max_auth_sec": _MAX_AUTH_SEC,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SslVpnTimeoutsCheck()
register_check(CHECK)
