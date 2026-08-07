"""UNF-2.6 — Guest SSIDs have client isolation enabled.

Without isolation, two devices on the same guest SSID can reach each
other directly (peer-to-peer / SMB / SSDP discovery). For a public
WiFi this is a confidentiality and lateral-movement risk. The wlanconf
field is `l2_isolation` (or `is_guest` group's network with
`networkconf.purpose=guest` + `networkconf.l2_isolation=true`).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _GuestIsolationCheck:
    control_id = "UNF-2.6"
    control_title = "Guest SSIDs have L2 client isolation enabled"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "For each guest SSID:\n"
        "  Settings → WiFi → <SSID> → Advanced → Client Device Isolation → ON\n"
        "Also confirm the guest *network* has L2 isolation:\n"
        "  Settings → Networks → <guest> → Isolation → ON\n"
        "Combined effect: each guest device sees only the gateway, never\n"
        "another guest device — required for any reception/lobby WiFi."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({is_guest: true}, "
            "{name:1, l2_isolation:1, enabled:1, no2ghz_oui:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not query wlanconf"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        guest_count = 0
        no_isolation: list[str] = []
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            guest_count += 1
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            iso_m = re.search(r'"l2_isolation"\s*:\s*(\w+)', ls)
            enabled_m = re.search(r'"enabled"\s*:\s*(\w+)', ls)
            if enabled_m and enabled_m.group(1).lower() == "false":
                continue
            if not name_m:
                continue
            isolation_on = iso_m and iso_m.group(1).lower() == "true"
            if not isolation_on:
                no_isolation.append(name_m.group(1))

        if guest_count == 0:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command=cmd,
                evidence_stdout="",
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "no guest SSIDs configured"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        issues = [f"guest SSID '{n}' has L2 isolation OFF" for n in sorted(set(no_isolation))]
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
                "guest_ssid_count": guest_count,
                "guest_ssids_without_isolation": sorted(set(no_isolation)),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _GuestIsolationCheck()
register_check(CHECK)
