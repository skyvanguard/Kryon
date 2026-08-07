"""VOIP-3.3 — Asterisk major version within currency window (N or N-1 LTS).

Asterisk follows a 1-year cadence with even-numbered Long-Term-Support
(LTS) releases (16, 18, 20, 22). LTS releases get security backports
for ~4 years; non-LTS for ~1 year. This check FAILs when the running
version is below the floor (anything older than the second-most-recent
LTS), WARNS by emitting MEDIUM severity when it's an LTS that's
within 12 months of EOL.

LTS table (as of 2026-05):
  - Asterisk 16: EOL October 2025 → DEAD
  - Asterisk 18: EOL April 2027 → near-EOL
  - Asterisk 20: EOL April 2029 → current LTS
  - Asterisk 22: EOL April 2031 → current LTS (released 2024)
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# Minimum major version considered supported (latest two LTS).
_MIN_SUPPORTED_MAJOR = 20
# Versions that are LTS but within 12 months of EOL.
_NEAR_EOL_MAJORS = {18}
# Versions that are definitely dead.
_DEAD_MAJORS = {1, 2, 3, 4, 6, 8, 10, 11, 13, 14, 15, 16, 17, 19}


class _AsteriskVersionCheck:
    control_id = "VOIP-3.3"
    control_title = "Asterisk major version within currency window"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Plan an upgrade to the latest LTS Asterisk:\n"
        "  - Asterisk 22 LTS (released Oct 2024, EOL April 2031).\n"
        "  - Asterisk 20 LTS (released Oct 2022, EOL April 2029).\n"
        "Steps:\n"
        "  1. Take a backup of /etc/asterisk and the call recordings dir.\n"
        "  2. Test in staging — chan_sip vs PJSIP migration matters.\n"
        "  3. Apply during maintenance window (calls drop on reload).\n"
        "Asterisk 16 and below stopped receiving security fixes — running\n"
        "them in production means exposure to unpatched CVEs."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "asterisk -V 2>/dev/null || /usr/sbin/asterisk -V 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return _err(self, cmd, out, err, t0, ctx, "could not run `asterisk -V`")

        # Output looks like: "Asterisk 20.5.1"
        m = re.search(r"Asterisk\s+(\d+)\.(\d+)\.(\d+)", out)
        if not m:
            return _err(self, cmd, out, err, t0, ctx, "could not parse asterisk version banner")

        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3))
        version_str = f"{major}.{minor}.{patch}"

        if major in _DEAD_MAJORS or major < _MIN_SUPPORTED_MAJOR:
            verdict = "FAIL"
        elif major in _NEAR_EOL_MAJORS:
            verdict = "FAIL"
        else:
            verdict = "PASS"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:512],
            evidence_stderr=err[:256],
            evidence_parsed={
                "version": version_str,
                "major": major,
                "min_supported": _MIN_SUPPORTED_MAJOR,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


def _err(check, cmd, out, err, t0, ctx, reason):
    return CheckResult(
        control_id=check.control_id,
        control_title=check.control_title,
        section=check.section,
        verdict="ERROR",
        evidence_command=cmd,
        evidence_stdout=out[:512],
        evidence_stderr=err[:512],
        evidence_parsed={"reason": reason},
        remediation_static=check.remediation_static,
        severity=check.severity,
        duration_ms=int((time.time() - t0) * 1000),
        host=ctx.host,
        run_id="",
    )


CHECK = _AsteriskVersionCheck()
register_check(CHECK)
