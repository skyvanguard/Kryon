"""PVE-5.2 — APT repository hygiene (no unstable test repo in production).

The Proxmox `pvetest` repository ships unvalidated packages and must never
be active on a production node. This check reads the APT sources and FAILs
if an uncommented `deb` line referencing `pvetest` is present.

(The pve-enterprise-without-subscription case is a separate, subscription-
dependent finding and is out of scope for this read-only check.)
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _RepoHygieneCheck:
    control_id = "PVE-5.2"
    control_title = "No unstable pvetest APT repository active"
    section = "5"
    severity = "MEDIUM"
    remediation_static = (
        "Remove or comment the pvetest repo on production nodes:\n"
        "  sed -i '/pvetest/s/^deb/#deb/' /etc/apt/sources.list /etc/apt/sources.list.d/*.list\n"
        "Use pve-enterprise (with a support contract) or pve-no-subscription for prod."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read APT sources"}, t0, ctx)

        pvetest_lines: list[str] = []
        for raw in out.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if (line.startswith("deb") or line.startswith("URIs:")) and "pvetest" in line.lower():
                pvetest_lines.append(line[:200])

        verdict = "FAIL" if pvetest_lines else "PASS"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"pvetest_active": bool(pvetest_lines), "lines": pvetest_lines},
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


CHECK = _RepoHygieneCheck()
register_check(CHECK)
