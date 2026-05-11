"""PVE-1.2 — Unauthenticated API endpoints do not leak sensitive info.

Proxmox exposes /api2/json/version without auth — that's by design and
only leaks version strings. But misconfig sometimes opens more. We probe:
  - /api2/json/version         → version only (expected)
  - /api2/json/nodes           → should 401
  - /api2/json/cluster/status  → should 401
  - /api2/json/access/domains  → should 401
  - Unreachable from arbitrary source  (advisory — assume mgmt VLAN)

This runs from the node via `curl -k` (cert may be self-signed from
PVE-1.1 finding), reading its own 8006/tcp.
"""

from __future__ import annotations

import json
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

SHOULD_BE_AUTHED = [
    "/api2/json/nodes",
    "/api2/json/cluster/status",
    "/api2/json/access/domains",
    "/api2/json/access/users",
]


class _UnauthApiCheck:
    control_id = "PVE-1.2"
    control_title = "Privileged API endpoints require authentication"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "If endpoints respond 200 without auth, something has tampered "
        "with PVEAPIServer ACLs. Inspect /etc/pve/datacenter.cfg for "
        "'notify' or custom auth, revert, then: systemctl restart pveproxy "
        "pvedaemon. Verify TLS is active on port 8006 — if not, API "
        "traffic is in cleartext."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        issues: list[str] = []
        parsed: dict = {"endpoints": {}}

        # First: confirm /version responds (sanity that pveproxy is up).
        ver_cmd = "curl -sk -m 5 -o /dev/null -w '%{http_code}' https://127.0.0.1:8006/api2/json/version"
        v_out, v_err, _ = run_cmd(ctx, ver_cmd, shell=True, timeout_s=8)
        version_code = v_out.strip() or "ERR"
        parsed["endpoints"]["/api2/json/version"] = version_code

        if version_code not in ("200",):
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=ver_cmd,
                evidence_stdout=v_out[:256],
                evidence_stderr=v_err[:256],
                evidence_parsed={"reason": f"pveproxy unreachable (/version → {version_code})"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Now every privileged endpoint must NOT return 200.
        for ep in SHOULD_BE_AUTHED:
            cmd = f"curl -sk -m 5 -o /dev/null -w '%{{http_code}}' https://127.0.0.1:8006{ep}"
            c_out, _, _ = run_cmd(ctx, cmd, shell=True, timeout_s=8)
            code = c_out.strip() or "ERR"
            parsed["endpoints"][ep] = code
            if code == "200":
                issues.append(f"{ep} returned 200 without auth (expected 401)")

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="curl -sk -m 5 -o /dev/null -w '%{http_code}' <endpoints>",
            evidence_stdout=json.dumps(parsed["endpoints"], indent=2)[:1024],
            evidence_stderr="",
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _UnauthApiCheck()
register_check(CHECK)
