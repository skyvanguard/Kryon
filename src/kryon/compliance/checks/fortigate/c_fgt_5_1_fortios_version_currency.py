"""FGT-5.1 — FortiOS version is current (>= N-2 minor of latest GA).

`get system status` reports the running version. We compare against a
hardcoded floor — the threshold updates with each Kryon release. Anything
below the floor is FAIL (HIGH) because it certainly missed at least one
security release window.

This intentionally does NOT call out to FortiGuard's online catalog —
that would break determinism. Operator can override the floor via
env var `KRYON_FGT_MIN_VERSION` (format `MAJOR.MINOR`).
"""

from __future__ import annotations

import os
import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


# Update on each Kryon release. As of 2026-04-28 the FortiOS GA branches
# under active maintenance are 7.6.x and 7.4.x; 7.2.x is in extended
# support. So the supported floor is 7.2.x; below that is FAIL.
_DEFAULT_MIN_MAJOR = 7
_DEFAULT_MIN_MINOR = 2


def _parse_floor() -> tuple[int, int]:
    raw = os.environ.get("KRYON_FGT_MIN_VERSION", "").strip()
    if not raw:
        return _DEFAULT_MIN_MAJOR, _DEFAULT_MIN_MINOR
    m = re.match(r"^(\d+)\.(\d+)", raw)
    if not m:
        return _DEFAULT_MIN_MAJOR, _DEFAULT_MIN_MINOR
    return int(m.group(1)), int(m.group(2))


class _FortiosVersionCurrencyCheck:
    control_id = "FGT-5.1"
    control_title = "FortiOS version is within supported (N-2) maintenance window"
    section = "5"
    severity = "HIGH"
    remediation_static = (
        "Schedule a FortiOS upgrade in a maintenance window:\n"
        "  - Backup current config: `execute backup config tftp <name> <ip>`\n"
        "  - Download target image to TFTP / USB.\n"
        "  - `execute restore image tftp <image.out> <ip>` then reboot.\n"
        "Always go one minor at a time (e.g. 6.4 → 7.0 → 7.2 → 7.4).\n"
        "On HA pair, upgrade secondary first, fail over, then primary."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "get system status"
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
                evidence_parsed={"reason": "could not read system status"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Version: FortiGate-VM64 v7.4.3,build2573,240314 (GA.M)
        # Match the "vN.N.N" token regardless of model prefix between "Version:" and version.
        ver_match = re.search(r"Version[^\n]*?v(\d+)\.(\d+)\.(\d+)", out)
        if not ver_match:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not parse Version line"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        major = int(ver_match.group(1))
        minor = int(ver_match.group(2))
        patch = int(ver_match.group(3))
        min_major, min_minor = _parse_floor()

        below_floor = (major, minor) < (min_major, min_minor)
        issues: list[str] = []
        if below_floor:
            issues.append(
                f"FortiOS {major}.{minor}.{patch} < supported floor {min_major}.{min_minor}.x"
            )

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:512],
            evidence_parsed={
                "version_major": major,
                "version_minor": minor,
                "version_patch": patch,
                "min_supported_major": min_major,
                "min_supported_minor": min_minor,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _FortiosVersionCurrencyCheck()
register_check(CHECK)
