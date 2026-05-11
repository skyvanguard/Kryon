"""UNF-2.4 — WPA3 (or WPA3-Transition) used where APs support it.

This is a forward-looking check: if all APs in the controller support
WPA3 (Wi-Fi 6+ generation: U6-Lite, U6-Pro, U6-Enterprise, U7 series),
the corporate SSIDs should be on `wpa3-sae` or `wpa3-sae-mixed`. Older
APs (UAP-AC-LR, etc.) do NOT support WPA3 → this becomes informational.

We dump the AP firmware list and the wlanconf wpa_mode and apply the
heuristic: if any corp SSID is wpa2-only AND we can detect at least one
WPA3-capable AP model in the device list, the check FAILs (medium).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# Best-effort list of WPA3-capable Ubiquiti AP model strings.
_WPA3_CAPABLE_MODELS = {
    "U6-Lite", "U6-LR", "U6-Pro", "U6-Mesh", "U6-Enterprise",
    "U6-IW", "U6-Plus", "U6+", "U6 IW",
    "U7-Pro", "U7", "UWP-700",
}


class _Wpa3AvailableCheck:
    control_id = "UNF-2.4"
    control_title = "WPA3 (or WPA3-Transition) enabled where APs support it"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "For each non-guest SSID, set:\n"
        "  Settings → WiFi → <SSID> → Security → WPA3 (or WPA2/WPA3 mixed)\n"
        "  Encryption: AES (CCMP/GCMP-128)\n"
        "Use WPA3-Transition where IoT or older clients still need WPA2.\n"
        "Verify post-change: `mongo ... db.wlanconf.find({}, {name:1, wpa_mode:1})`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd_a = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({is_guest: {$ne: true}}, "
            "{name:1, wpa_mode:1, security:1, enabled:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        cmd_b = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.device.find({adopted: true}, {model:1, name:1, version:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        out_a, err_a, rc_a = run_cmd(ctx, cmd_a, shell=True, timeout_s=10)
        out_b, err_b, rc_b = run_cmd(ctx, cmd_b, shell=True, timeout_s=10)

        if (rc_a != 0 and not out_a) or (rc_b != 0 and not out_b):
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=f"{cmd_a} ; {cmd_b}",
                evidence_stdout=(out_a + "\n---\n" + out_b)[:1024],
                evidence_stderr=(err_a + "\n" + err_b)[:512],
                evidence_parsed={"reason": "could not query mongo"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # AP capability inference
        ap_models: list[str] = []
        wpa3_capable_aps: list[str] = []
        for line in out_b.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            model_m = re.search(r'"model"\s*:\s*"([^"]+)"', ls)
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            if not model_m:
                continue
            model = model_m.group(1)
            ap_models.append(model)
            for m in _WPA3_CAPABLE_MODELS:
                if m in model or m == model:
                    wpa3_capable_aps.append(name_m.group(1) if name_m else model)
                    break

        if not wpa3_capable_aps:
            # No WPA3-capable APs detected → check is N/A.
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command=f"{cmd_a} ; {cmd_b}",
                evidence_stdout=(out_a + "\n---\n" + out_b)[:2048],
                evidence_stderr=(err_a + "\n" + err_b)[:512],
                evidence_parsed={
                    "ap_models": sorted(set(ap_models)),
                    "wpa3_capable_aps": [],
                    "reason": "no WPA3-capable AP detected — upgrade hardware first",
                },
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        wpa2_only_corp_ssids: list[str] = []
        ssid_count = 0
        for line in out_a.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            ssid_count += 1
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            wpa_m = re.search(r'"wpa_mode"\s*:\s*"([^"]+)"', ls)
            enabled_m = re.search(r'"enabled"\s*:\s*(\w+)', ls)
            if enabled_m and enabled_m.group(1).lower() == "false":
                continue
            if not name_m:
                continue
            wpa = wpa_m.group(1).lower() if wpa_m else "wpa2"
            if "wpa3" not in wpa:
                wpa2_only_corp_ssids.append(name_m.group(1))

        issues: list[str] = []
        if wpa2_only_corp_ssids:
            issues.append(
                f"{len(wpa2_only_corp_ssids)} corporate SSID(s) on WPA2-only despite WPA3-capable APs"
            )

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{cmd_a} ; {cmd_b}",
            evidence_stdout=(out_a + "\n---\n" + out_b)[:3072],
            evidence_stderr=(err_a + "\n" + err_b)[:512],
            evidence_parsed={
                "ssid_count_corp": ssid_count,
                "wpa3_capable_aps": sorted(set(wpa3_capable_aps)),
                "wpa2_only_corp_ssids": sorted(set(wpa2_only_corp_ssids)),
                "ap_models": sorted(set(ap_models)),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _Wpa3AvailableCheck()
register_check(CHECK)
