"""UNF-2.5 — No open SSID broadcasting without captive portal.

`security: open` SSIDs are acceptable ONLY when paired with a captive
portal (guest portal). An open SSID without a captive portal is a free
WiFi anyone-can-pivot-from-the-parking-lot problem.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _OpenSsidCheck:
    control_id = "UNF-2.5"
    control_title = "No open SSID without captive portal / guest control"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Either:\n"
        "  (a) Add a passphrase: Settings → WiFi → <SSID> → Security → WPA2 / WPA3.\n"
        "  (b) If guest WiFi is intentional, enable Guest Control:\n"
        "      Settings → Insights → Hotspot Manager → Authentication → Captive Portal.\n"
        "      Tie the open SSID to the guest network configured for it.\n"
        "An open SSID with no portal effectively shares your LAN with the street."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({}, {name:1, security:1, is_guest:1, "
            "enabled:1, networkconf_id:1, schedule_enabled:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        cmd2 = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.portalcustomized.find({}, {site_id:1, _id:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        out2, err2, rc2 = run_cmd(ctx, cmd2, shell=True, timeout_s=8)

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

        portal_configured = bool(out2 and out2.strip().startswith("{"))

        risky: list[str] = []
        ssid_count = 0
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            ssid_count += 1
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            sec_m = re.search(r'"security"\s*:\s*"([^"]+)"', ls)
            is_guest_m = re.search(r'"is_guest"\s*:\s*(\w+)', ls)
            enabled_m = re.search(r'"enabled"\s*:\s*(\w+)', ls)
            if enabled_m and enabled_m.group(1).lower() == "false":
                continue
            if not name_m or not sec_m:
                continue
            if sec_m.group(1).lower() != "open":
                continue
            is_guest = is_guest_m and is_guest_m.group(1).lower() == "true"
            if not is_guest or not portal_configured:
                risky.append(name_m.group(1))

        issues = [f"open SSID '{n}' without guest portal" for n in sorted(set(risky))]
        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{cmd} ; {cmd2}",
            evidence_stdout=(out + "\n---\n" + out2)[:3072],
            evidence_stderr=(err + "\n" + err2)[:512],
            evidence_parsed={
                "ssid_count": ssid_count,
                "open_ssids_at_risk": sorted(set(risky)),
                "captive_portal_configured": portal_configured,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _OpenSsidCheck()
register_check(CHECK)
