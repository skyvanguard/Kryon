"""UNF-3.1 — Management network VLAN is NOT shared with guest VLAN.

Mongo `networkconf` collection has each network's purpose:
  - "corporate" / lan (default management)
  - "guest" (captive-portal scope)
  - "wan" / "vpn-client" / etc.
A network with `purpose: "guest"` AND `vlan_enabled: false` (== untagged)
sharing the same broadcast domain as the management LAN is a CRITICAL
finding — guest WiFi reaches the controller / switches.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _MgmtVsGuestVlanCheck:
    control_id = "UNF-3.1"
    control_title = "Management VLAN not shared with guest network"
    section = "3"
    severity = "CRITICAL"
    remediation_static = (
        "Move the guest network to a dedicated VLAN:\n"
        "  Settings → Networks → New Network → Purpose: Guest → VLAN: 200\n"
        "Confirm `vlan_enabled: true` and a unique `vlan` value distinct\n"
        "from the management LAN. On UDM, ensure the firewall rule\n"
        "`Guest In → Allow [Internet] / Block [LAN]` is present."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.networkconf.find({}, {name:1, purpose:1, vlan_enabled:1, "
            "vlan:1, networkgroup:1, is_guest:1, enabled:1})"
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
                evidence_parsed={"reason": "could not query networkconf"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        guest_nets: list[dict[str, object]] = []
        mgmt_vlans: set[int] = set()
        all_nets: list[dict[str, object]] = []
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            purp_m = re.search(r'"purpose"\s*:\s*"([^"]+)"', ls)
            vlan_en_m = re.search(r'"vlan_enabled"\s*:\s*(\w+)', ls)
            vlan_m = re.search(r'"vlan"\s*:\s*(\d+)', ls)
            net = {
                "name": name_m.group(1) if name_m else "",
                "purpose": purp_m.group(1) if purp_m else "",
                "vlan_enabled": vlan_en_m and vlan_en_m.group(1).lower() == "true",
                "vlan": int(vlan_m.group(1)) if vlan_m else 0,
            }
            all_nets.append(net)
            if net["purpose"] == "guest":
                guest_nets.append(net)
            elif net["purpose"] in ("corporate", ""):
                if net["vlan_enabled"] and net["vlan"]:
                    mgmt_vlans.add(net["vlan"])  # type: ignore[arg-type]

        issues: list[str] = []
        for g in guest_nets:
            if not g["vlan_enabled"]:
                issues.append(
                    f"guest network '{g['name']}' has VLAN tagging disabled "
                    "— shares broadcast domain with management"
                )
            elif g["vlan"] in mgmt_vlans:
                issues.append(
                    f"guest network '{g['name']}' uses VLAN {g['vlan']} which is also a management VLAN"
                )

        if not guest_nets:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command=cmd,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "no guest networks configured"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

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
                "network_count": len(all_nets),
                "guest_networks": [g["name"] for g in guest_nets],
                "mgmt_vlans": sorted(mgmt_vlans),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _MgmtVsGuestVlanCheck()
register_check(CHECK)
