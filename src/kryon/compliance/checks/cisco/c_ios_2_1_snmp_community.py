"""IOS-2.1 — SNMP does not use default communities.

CIS Cisco Benchmark: an `snmp-server community public` (or private) string is
the vendor default and grants read (or read-write) access to anyone who
reaches the device. Defaults must be removed.

FAIL if a public/private community is configured. PASS otherwise. ERROR if
the output isn't an IOS running-config.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.cisco._common import SHOW_RUN, looks_like_ios, make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_COMMUNITY_RE = re.compile(r"^snmp-server community (\S+)", re.IGNORECASE | re.MULTILINE)
_DEFAULTS = {"public", "private"}


class _SnmpCommunityCheck:
    control_id = "IOS-2.1"
    control_title = "SNMP does not use default communities"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Remove default communities; prefer SNMPv3 auth+priv:\n"
        "  no snmp-server community public\n  no snmp-server community private"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, SHOW_RUN, shell=True, timeout_s=15)
        if not looks_like_ios(out):
            return make_error(
                self, cmd=SHOW_RUN, out=out, err=err, t0=t0, ctx=ctx, reason="not an IOS running-config (Cisco host?)"
            )

        communities = {c.lower() for c in _COMMUNITY_RE.findall(out)}
        offenders = sorted(_DEFAULTS & communities)
        verdict = "FAIL" if offenders else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=SHOW_RUN,
            out=out[:1024],
            err=err,
            parsed={"default_communities": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _SnmpCommunityCheck()
register_check(CHECK)
