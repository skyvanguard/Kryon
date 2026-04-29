"""UNF-2.7 — Hidden SSID is not the only protection.

`hide_ssid: true` is security-by-obscurity. It does NOT hide the BSSID
from probe responses; any wireless analyzer trivially uncovers the SSID
once a client connects. We surface SSIDs that are hidden AND on weak
WPA modes — those are still treated by some operators as "secure
enough", which it isn't.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _HideSsidOnlyCheck:
    control_id = "UNF-2.7"
    control_title = "Hidden SSIDs not relied upon as sole defence"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Hidden SSIDs are NOT a security control. They:\n"
        "  - leak the SSID name to any client that has previously associated\n"
        "  - encourage clients to probe constantly for the network in plaintext\n"
        "  - leave WPA-strength as the actual security boundary\n"
        "Recommendation: unhide the SSID and rely on strong WPA2/WPA3 + MFA.\n"
        "If hiding remains a policy preference, ensure WPA3 + 14-char passphrase."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({hide_ssid: true}, "
            "{name:1, hide_ssid:1, security:1, wpa_mode:1, enabled:1})"
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

        hidden_with_weak: list[str] = []
        hidden_total = 0
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            hidden_total += 1
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            wpa_m = re.search(r'"wpa_mode"\s*:\s*"([^"]+)"', ls)
            enabled_m = re.search(r'"enabled"\s*:\s*(\w+)', ls)
            if enabled_m and enabled_m.group(1).lower() == "false":
                continue
            if not name_m:
                continue
            wpa = wpa_m.group(1).lower() if wpa_m else ""
            if wpa in ("wpa1", "wpa2") and "wpa3" not in wpa:
                hidden_with_weak.append(name_m.group(1))

        if hidden_total == 0:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command=cmd,
                evidence_stdout="",
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "no hidden SSIDs configured"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        issues = [
            f"hidden SSID '{n}' relies on weak WPA (security-by-obscurity not security)"
            for n in sorted(set(hidden_with_weak))
        ]
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
                "hidden_ssid_total": hidden_total,
                "hidden_ssids_with_weak_wpa": sorted(set(hidden_with_weak)),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _HideSsidOnlyCheck()
register_check(CHECK)
