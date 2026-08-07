"""PVE-4.1 — Datacenter firewall is enabled with a default-deny policy.

Proxmox firewall has three scopes: datacenter, node, and VM. Any one of
them off means traffic bypasses the rules. In banking environments we
demand datacenter-level ENABLE + policy_in DROP + default reject for
ICMP and enumerate inbound allow-lists.

`pve-firewall status` reports running state; cluster.fw holds policy.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _FirewallEnabledCheck:
    control_id = "PVE-4.1"
    control_title = "Datacenter firewall enabled with default-deny ingress"
    section = "4"
    severity = "HIGH"
    remediation_static = (
        "Web UI → Datacenter → Firewall → Options: Firewall=Yes, "
        "Input Policy=DROP, Output Policy=ACCEPT. "
        "Then enable per-node: Node → Firewall → Options: Firewall=Yes. "
        "Audit rules on each VM. CLI: edit /etc/pve/firewall/cluster.fw."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        status_cmd = "pve-firewall status 2>&1 || true"
        cluster_fw = "cat /etc/pve/firewall/cluster.fw 2>/dev/null"
        s_out, s_err, _ = run_cmd(ctx, status_cmd, shell=True, timeout_s=6)
        c_out, c_err, _ = run_cmd(ctx, cluster_fw, shell=True, timeout_s=4)

        issues: list[str] = []
        parsed: dict = {}

        # Status block example:
        #   Status: enabled/running
        #   Firewall enabled:      1
        status_line = ""
        m = re.search(r"^Status:\s*(.+)$", s_out, re.M)
        if m:
            status_line = m.group(1).strip().lower()
            parsed["status"] = status_line
        if not status_line:
            issues.append("could not parse pve-firewall status (is pve-firewall installed?)")
        elif "disabled" in status_line or "stopped" in status_line:
            issues.append(f"pve-firewall status={status_line}")

        # Parse [OPTIONS] block for enable + policy_in
        opts_block = ""
        m2 = re.search(r"\[OPTIONS\](.*?)(?:\n\[|\Z)", c_out, re.S)
        if m2:
            opts_block = m2.group(1)
        enable = _kv(opts_block, "enable") or "0"
        policy_in = _kv(opts_block, "policy_in") or ""
        parsed["enable"] = enable
        parsed["policy_in"] = policy_in

        if enable.strip() != "1":
            issues.append(f"cluster.fw enable={enable} (need 1)")
        if policy_in.lower() not in ("drop", "reject"):
            issues.append(f"policy_in={policy_in or 'ACCEPT (default)'} (need DROP/REJECT)")

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{status_cmd} ; {cluster_fw}",
            evidence_stdout=(f"=== pve-firewall status ===\n{s_out}\n\n=== cluster.fw [OPTIONS] ===\n{opts_block}")[
                :2048
            ],
            evidence_stderr=(s_err + "\n" + c_err)[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


def _kv(block: str, key: str) -> str:
    m = re.search(rf"^\s*{re.escape(key)}:\s*(\S+)", block, re.M)
    return m.group(1).strip() if m else ""


CHECK = _FirewallEnabledCheck()
register_check(CHECK)
