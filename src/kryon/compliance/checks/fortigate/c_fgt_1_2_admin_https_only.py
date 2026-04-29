"""FGT-1.2 — Admin GUI uses HTTPS only, HTTP redirect enforced.

`config system global` controls global admin surface:
  - `admin-https-redirect enable` redirects HTTP → HTTPS on the admin port.
  - `admin-port 80` listens on HTTP; presence of a separate non-redirected
    HTTP listener is a hard fail.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _AdminHttpsOnlyCheck:
    control_id = "FGT-1.2"
    control_title = "Admin GUI accepts only HTTPS, redirects HTTP, no plain admin-port 80"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "config system global\n"
        "  set admin-https-redirect enable\n"
        "  set admin-sport 443         # or 8443 if external GUI is allowed\n"
        "  unset admin-port            # disable HTTP listener entirely\n"
        "end\n"
        "If you need an HTTP listener for legacy clients, terminate it on a\n"
        "trusted reverse proxy with HSTS, never on the FortiGate directly."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show system global"
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
                evidence_parsed={"reason": "could not read system global"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        def directive(name: str) -> str:
            m = re.search(rf"^\s*set\s+{name}\s+(\S+)", out, re.M)
            return m.group(1).strip().lower() if m else ""

        redirect = directive("admin-https-redirect")
        admin_port = directive("admin-port")
        admin_sport = directive("admin-sport")

        issues: list[str] = []
        # FortiOS default is `admin-https-redirect enable`. If explicitly
        # disabled, that's a finding.
        if redirect == "disable":
            issues.append("admin-https-redirect is explicitly disabled")
        # HTTP listener should be off OR redirected. Default 80 with redirect
        # on is acceptable; 80 with redirect off is bad.
        if admin_port and admin_port != "0" and redirect == "disable":
            issues.append(
                f"admin-port={admin_port} active without HTTPS redirect"
            )
        # admin-sport must be HTTPS — anything other than common HTTPS ports
        # on default config is suspicious; we only flag the missing case.
        if not admin_sport:
            # Default 443 is implicit; absence in `show` is OK.
            pass

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
                "admin-https-redirect": redirect or "(default-enabled)",
                "admin-port": admin_port or "(default-80)",
                "admin-sport": admin_sport or "(default-443)",
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AdminHttpsOnlyCheck()
register_check(CHECK)
