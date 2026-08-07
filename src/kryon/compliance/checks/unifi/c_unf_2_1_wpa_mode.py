"""UNF-2.1 — All SSIDs use WPA2-AES or WPA3 (no WEP / WPA1 / TKIP).

The `wlanconf` collection holds the per-SSID security settings:
  - `security`: "open" | "wep" | "wpapsk" | "wpaeap" | "wpa3-sae" | ...
  - `wpa_mode`: "wpa1" | "wpa2" | "wpa3" | "wpa3-mixed" | ...
  - `wpa_enc`: "tkip" | "ccmp" | "auto"
We FAIL on:
  - security = wep
  - wpa_mode = wpa1
  - wpa_enc = tkip
PASS = AES-CCMP only with WPA2 or WPA3.

Open SSIDs are covered by UNF-2.5 (separate check).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _WpaModeCheck:
    control_id = "UNF-2.1"
    control_title = "All SSIDs use WPA2-AES or WPA3 (no WEP / WPA1 / TKIP)"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "For each affected SSID:\n"
        "  Settings → WiFi → <SSID> → Security Protocol → WPA2 or WPA3\n"
        "  Encryption: AES (CCMP). Disable TKIP-only mixed modes.\n"
        "WPA3-Personal (SAE) is preferred where client support exists.\n"
        "If you need WPA2 fallback for legacy IoT, use WPA3-Transition\n"
        "rather than WPA1 / WPA2-mixed-with-TKIP."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({}, {name:1, security:1, wpa_mode:1, wpa_enc:1, "
            "is_guest:1, enabled:1}).forEach(function(d){print(JSON.stringify(d))})'"
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

        ssids: list[dict[str, object]] = []
        bad_ssids: list[str] = []
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            name = (re.search(r'"name"\s*:\s*"([^"]+)"', ls) or _N).group(1)
            sec = (re.search(r'"security"\s*:\s*"([^"]+)"', ls) or _N).group(1)
            wpa = (re.search(r'"wpa_mode"\s*:\s*"([^"]+)"', ls) or _N).group(1)
            enc = (re.search(r'"wpa_enc"\s*:\s*"([^"]+)"', ls) or _N).group(1)
            enabled = re.search(r'"enabled"\s*:\s*(\w+)', ls)
            is_enabled = (enabled and enabled.group(1).lower() == "true") or enabled is None
            ssids.append(
                {
                    "name": name,
                    "security": sec,
                    "wpa_mode": wpa,
                    "wpa_enc": enc,
                    "enabled": is_enabled,
                }
            )
            if not is_enabled:
                continue
            bad_reasons = []
            if sec.lower() == "wep":
                bad_reasons.append("WEP")
            if wpa.lower() == "wpa1":
                bad_reasons.append("wpa_mode=wpa1")
            if enc.lower() == "tkip":
                bad_reasons.append("wpa_enc=tkip")
            if bad_reasons:
                bad_ssids.append(f"{name}: {', '.join(bad_reasons)}")

        issues = [f"SSID {b}" for b in sorted(set(bad_ssids))]
        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:3072],
            evidence_stderr=err[:512],
            evidence_parsed={
                "ssid_count": len(ssids),
                "bad_ssids": sorted(set(bad_ssids)),
                "ssid_names": sorted(str(s["name"]) for s in ssids),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


# Sentinel: regex match object with a group(1) returning empty string. Used as
# a fallback so callers can write `(re.search(...) or _N).group(1)` without a
# verbose ternary chain.
class _Null:
    def group(self, _idx: int = 0) -> str:
        return ""


_N = _Null()

CHECK = _WpaModeCheck()
register_check(CHECK)
