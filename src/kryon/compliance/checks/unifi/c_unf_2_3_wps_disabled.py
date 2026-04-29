"""UNF-2.3 — WPS disabled on every SSID.

WPS PIN is brute-forceable in <= 4 hours per Reaver. Even with rate
limiting, no enterprise-grade scenario justifies leaving WPS on.
The `wlanconf` field is `wps`. We FAIL on any enabled SSID with wps=true.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _WpsDisabledCheck:
    control_id = "UNF-2.3"
    control_title = "WPS disabled on every SSID"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "For each affected SSID:\n"
        "  Settings → WiFi → <SSID> → Advanced → WPS → Disable\n"
        "Or via mongo (one-shot):\n"
        '  db.wlanconf.update({}, {$set: {wps: false}}, {multi: true})\n'
        "Then `force-provision` the impacted APs from the Unifi UI."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({}, {name:1, wps:1, enabled:1})"
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

        wps_enabled: list[str] = []
        ssid_count = 0
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            ssid_count += 1
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            wps_m = re.search(r'"wps"\s*:\s*(\w+)', ls)
            enabled_m = re.search(r'"enabled"\s*:\s*(\w+)', ls)
            if enabled_m and enabled_m.group(1).lower() == "false":
                continue
            if wps_m and wps_m.group(1).lower() == "true" and name_m:
                wps_enabled.append(name_m.group(1))

        issues = [f"SSID '{n}' has WPS enabled" for n in sorted(set(wps_enabled))]
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
                "ssid_count": ssid_count,
                "ssids_with_wps": sorted(set(wps_enabled)),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _WpsDisabledCheck()
register_check(CHECK)
