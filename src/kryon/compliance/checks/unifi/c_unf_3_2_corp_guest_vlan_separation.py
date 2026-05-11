"""UNF-3.2 — Corporate SSID and Guest SSID resolve to different VLANs.

The wlanconf binds an SSID to a network via `networkconf_id`. We trace
each enabled SSID to the VLAN it lives on. If a corp SSID and a guest
SSID share the same VLAN, that defeats segmentation regardless of
networkconf metadata.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _CorpGuestVlanSeparationCheck:
    control_id = "UNF-3.2"
    control_title = "Corporate and guest SSIDs land on different VLANs"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Per SSID, set:\n"
        "  Settings → WiFi → <SSID> → Network → <unique_VLAN_for_SSID_class>\n"
        "Corporate SSID → corp VLAN.  Guest SSID → guest VLAN.  IoT → IoT VLAN.\n"
        "Verify on the controller:\n"
        "  db.wlanconf.find({}, {name:1, networkconf_id:1, is_guest:1})\n"
        "  db.networkconf.find({}, {_id:1, name:1, vlan:1, vlan_enabled:1, purpose:1})"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd_a = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({enabled: {$ne: false}}, "
            "{name:1, networkconf_id:1, is_guest:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        cmd_b = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.networkconf.find({}, {_id:1, name:1, vlan:1, vlan_enabled:1, purpose:1})"
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

        # Build network-id → vlan map
        net_vlan: dict[str, int] = {}
        for line in out_b.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            id_m = re.search(r'"_id"\s*:\s*ObjectId\("([^"]+)"\)', ls) or re.search(r'"_id"\s*:\s*"([^"]+)"', ls)
            vlan_m = re.search(r'"vlan"\s*:\s*(\d+)', ls)
            if id_m:
                net_vlan[id_m.group(1)] = int(vlan_m.group(1)) if vlan_m else 0

        ssid_vlan: dict[str, tuple[int, bool]] = {}
        for line in out_a.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            netid_m = re.search(r'"networkconf_id"\s*:\s*ObjectId\("([^"]+)"\)', ls) or re.search(
                r'"networkconf_id"\s*:\s*"([^"]+)"', ls
            )
            guest_m = re.search(r'"is_guest"\s*:\s*(\w+)', ls)
            if not name_m or not netid_m:
                continue
            vlan_id = net_vlan.get(netid_m.group(1), 0)
            is_guest = bool(guest_m and guest_m.group(1).lower() == "true")
            ssid_vlan[name_m.group(1)] = (vlan_id, is_guest)

        guest_vlans = {v for v, g in ssid_vlan.values() if g}
        corp_vlans = {v for v, g in ssid_vlan.values() if not g}
        overlapping = guest_vlans & corp_vlans

        issues: list[str] = []
        if overlapping:
            issues.append(f"VLAN(s) {sorted(overlapping)} carry BOTH guest and corporate SSIDs")

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
                "ssid_to_vlan": {k: v[0] for k, v in ssid_vlan.items()},
                "guest_vlans": sorted(guest_vlans),
                "corp_vlans": sorted(corp_vlans),
                "overlapping_vlans": sorted(overlapping),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _CorpGuestVlanSeparationCheck()
register_check(CHECK)
