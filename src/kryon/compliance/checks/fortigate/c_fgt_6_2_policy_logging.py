"""FGT-6.2 — Accept firewall policies log traffic.

An accept policy with `set logtraffic disable` produces no audit trail —
PCI Req 10, SWIFT CSCF 6.4 and incident response all depend on it. FortiOS
defaults logtraffic to `utm`; only an explicit `disable` turns it off.

FAIL on any accept policy that explicitly disables logging. ERROR if the
policy table can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_POLICY_RE = re.compile(r"edit\s+(\d+)\s*(.*?)\bnext\b", re.S)


def _set_tokens(body: str, key: str) -> set[str]:
    m = re.search(rf"^\s*set\s+{re.escape(key)}\s+(.+)$", body, re.M)
    return {t.strip('"') for t in m.group(1).split()} if m else set()


class _PolicyLoggingCheck:
    control_id = "FGT-6.2"
    control_title = "Accept firewall policies log traffic"
    section = "6"
    severity = "HIGH"
    remediation_static = (
        "Enable logging on every accept policy:\n"
        "  config firewall policy\n"
        "    edit <id>\n"
        "      set logtraffic all      # or 'utm' at minimum\n"
        "    next\n"
        "  end\n"
        "Forward the logs to syslog/FortiAnalyzer (see FGT-4.x)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show firewall policy"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out:
            return self._result("ERROR", cmd, out, err, {"reason": "could not read firewall policy table"}, t0, ctx)

        no_log: list[str] = []
        accept_total = 0
        for m in _POLICY_RE.finditer(out):
            pid, body = m.group(1), m.group(2)
            if "accept" not in _set_tokens(body, "action"):
                continue
            accept_total += 1
            if "disable" in _set_tokens(body, "logtraffic"):
                no_log.append(pid)

        issues = [f"accept policy {pid} has logtraffic disable" for pid in no_log]
        verdict = "PASS" if not issues else "FAIL"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"accept_policy_count": accept_total, "policies_without_logging": no_log, "issues": sorted(issues)},
            t0,
            ctx,
        )

    def _result(self, verdict, cmd, out, err, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:3072],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _PolicyLoggingCheck()
register_check(CHECK)
