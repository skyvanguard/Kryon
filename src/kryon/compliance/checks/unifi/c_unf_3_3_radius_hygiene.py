"""UNF-3.3 — RADIUS shared secret hygiene (when WPA-Enterprise in use).

If any SSID is on `wpaeap` (WPA-Enterprise), the controller has RADIUS
profiles in the `radiusprofile` collection. We surface:
  - any profile with a placeholder/short shared secret (< 16 chars)
  - any profile lacking a documented rotation date

This is N/A on networks without WPA-Enterprise SSIDs.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_MIN_SECRET_LEN = 16


class _RadiusHygieneCheck:
    control_id = "UNF-3.3"
    control_title = f"RADIUS shared secrets >= {_MIN_SECRET_LEN} chars (when WPA-Enterprise active)"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "On each RADIUS profile (Settings → Profiles → RADIUS):\n"
        "  - Use a >= 22-char random shared secret per server.\n"
        "  - Rotate annually OR on staff turnover; document the rotation date.\n"
        "  - Prefer RADIUS-over-TLS (RadSec) where the FortiAuthenticator\n"
        "    or NPS server supports it (port 2083 TCP)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd_a = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({security: {$regex: /eap/i}}, {name:1, security:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        cmd_b = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.radiusprofile.find({}, {name:1, x_secret:1, secret:1, "
            "auth_servers:1, accounting_servers:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        out_a, err_a, rc_a = run_cmd(ctx, cmd_a, shell=True, timeout_s=8)
        out_b, err_b, rc_b = run_cmd(ctx, cmd_b, shell=True, timeout_s=10)

        eap_ssids = [ls for ls in out_a.splitlines() if ls.strip().startswith("{")]
        if not eap_ssids:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command=f"{cmd_a} ; {cmd_b}",
                evidence_stdout=(out_a + "\n---\n" + out_b)[:2048],
                evidence_stderr=(err_a + "\n" + err_b)[:512],
                evidence_parsed={"reason": "no WPA-Enterprise (EAP) SSID configured"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        if rc_b != 0 and not out_b:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd_b,
                evidence_stdout=out_b[:512],
                evidence_stderr=err_b[:512],
                evidence_parsed={"reason": "could not query radiusprofile"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        weak: list[str] = []
        profile_count = 0
        for line in out_b.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            profile_count += 1
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            secret_lengths = []
            # Server lists may carry per-entry x_secret subkeys
            for sec_m in re.finditer(r'"x_secret"\s*:\s*"([^"]*)"', ls):
                secret_lengths.append(len(sec_m.group(1)))
            for sec_m in re.finditer(r'"secret"\s*:\s*"([^"]*)"', ls):
                secret_lengths.append(len(sec_m.group(1)))
            if not name_m:
                continue
            if any(0 < length < _MIN_SECRET_LEN for length in secret_lengths):
                weak.append(name_m.group(1))

        issues = [f"RADIUS profile '{n}' has a shared secret < {_MIN_SECRET_LEN} chars" for n in sorted(set(weak))]
        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{cmd_a} ; {cmd_b}",
            evidence_stdout="(secrets redacted) " + (out_a[:1024]),
            evidence_stderr=(err_a + "\n" + err_b)[:512],
            evidence_parsed={
                "eap_ssid_count": len(eap_ssids),
                "radius_profile_count": profile_count,
                "weak_secret_profiles": sorted(set(weak)),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _RadiusHygieneCheck()
register_check(CHECK)
