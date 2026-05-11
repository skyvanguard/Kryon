"""UNF-1.2 — Controller HTTPS port not bound to a public interface.

Unifi controllers should be reachable from the LAN / VPN only. Exposing
8443 (and 8080 for HTTP redirect) to the WAN is a CRITICAL finding —
the controller has had multiple unauth RCEs over the years (CVE-2021-22893,
CVE-2024-42026), and every exposure becomes a foothold the moment a new
advisory drops.

Detection (heuristic, on the controller host itself):
  - `ss -tlnp` shows what TCP ports are listening on which IPs.
  - If 0.0.0.0:8443 or :::8443 → externally reachable surface (FAIL).
  - 127.0.0.1:8443 or LAN-only IP → PASS.
We can't verify "is the public Internet seeing this" from inside the box;
operator should also confirm via external scan.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_PUBLIC_BIND_PATTERN = re.compile(
    r"\b(0\.0\.0\.0|::|\*):(?:8443|8080|8843|8880)\b"
)


class _ControllerInternetExposureCheck:
    control_id = "UNF-1.2"
    control_title = "Controller HTTPS not bound to a public interface"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Restrict the controller listener to LAN / loopback. On UDM-Pro:\n"
        "  Settings → System → Application Configuration → Override Inform Host\n"
        "Or front the controller with a reverse proxy on a hardened jump host.\n"
        "On self-hosted Linux controllers:\n"
        "  - Bind via `system.properties`: `unifi.https.host=192.168.1.5`\n"
        "  - Restart unifi: `systemctl restart unifi`\n"
        "Confirm with: `ss -tlnp | grep -E ':(8443|8080|8843|8880)'`"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "ss -tlnp 2>/dev/null | grep -E ':(8443|8080|8843|8880)'"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        # rc=1 from grep with no matches is fine; treat as no listener (N/A).
        if rc not in (0, 1):
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not query ss"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )
        if not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command=cmd,
                evidence_stdout="",
                evidence_stderr=err[:512],
                evidence_parsed={
                    "reason": "no controller listener detected (likely not the controller host)",
                },
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        public_binds = _PUBLIC_BIND_PATTERN.findall(out)
        all_binds = re.findall(r"\b([\d\.]+|::|\*):(\d+)\b", out)

        issues: list[str] = []
        if public_binds:
            issues.append(
                f"controller HTTPS bound to public-style address(es): {sorted(set(public_binds))}"
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
                "all_binds": sorted({f"{i}:{p}" for i, p in all_binds}),
                "public_binds": sorted(set(public_binds)),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _ControllerInternetExposureCheck()
register_check(CHECK)
