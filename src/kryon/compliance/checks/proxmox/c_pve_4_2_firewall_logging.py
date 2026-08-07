"""PVE-4.2 — Datacenter firewall logging enabled.

The cluster firewall (4.1) is only useful with an audit trail. The
[OPTIONS] section of /etc/pve/firewall/cluster.fw controls log_level_in /
log_level_out; the Proxmox default is `nolog`, so logging must be turned
on explicitly (info or higher) to record dropped/rejected traffic.

FAIL if both log levels are nolog/unset. N/A if the cluster firewall file
doesn't exist (no firewall configured — that's 4.1's finding).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_LOGGING_LEVELS = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


def _opt(text: str, key: str) -> str | None:
    m = re.search(rf"^\s*{re.escape(key)}:\s*(\S+)", text, re.M)
    return m.group(1).lower() if m else None


class _FirewallLoggingCheck:
    control_id = "PVE-4.2"
    control_title = "Datacenter firewall logging enabled"
    section = "4"
    severity = "MEDIUM"
    remediation_static = (
        "Enable firewall logging in /etc/pve/firewall/cluster.fw:\n"
        "  [OPTIONS]\n"
        "  log_level_in: info\n"
        "  log_level_out: info\n"
        "Forward /var/log/pve-firewall.log to your SIEM."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/pve/firewall/cluster.fw 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if not out.strip():
            return self._result(
                "N/A", cmd, out, err, {"reason": "no cluster.fw (firewall unconfigured — see 4.1)"}, t0, ctx
            )

        lvl_in = _opt(out, "log_level_in")
        lvl_out = _opt(out, "log_level_out")

        def _logs(v: str | None) -> bool:
            return v in _LOGGING_LEVELS

        verdict = "PASS" if (_logs(lvl_in) or _logs(lvl_out)) else "FAIL"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"log_level_in": lvl_in or "(nolog/unset)", "log_level_out": lvl_out or "(nolog/unset)"},
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
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _FirewallLoggingCheck()
register_check(CHECK)
