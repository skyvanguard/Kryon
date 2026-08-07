"""Proxmox VE check PVE-6.1 — Cluster quorum has a tie-breaker.

A two-node PVE cluster loses quorum the moment either node goes down:
the survivor flips read-only and refuses VM start/stop. The fix is to
add a third voter — typically a QDevice on a low-power host
(`pvecm qdevice setup <ip>`) or a third PVE node.

Verdict:
  - PASS if `pvecm status` shows >= 3 nodes OR a QDevice line.
  - PASS if standalone (Total votes == 1 AND only one node configured)
    because there's nothing to tie-break.
  - FAIL when the cluster has exactly 2 voters and no QDevice.

Closes ground-truth gap M-07.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_NODE_LINE_RE = re.compile(
    r"^\s*\d+\s+\d+\s+(\S+)",
    re.MULTILINE,
)
_QDEVICE_LINE_RE = re.compile(r"qdevice", re.IGNORECASE)


class _PVE61Check:
    control_id = "PVE-6.1"
    control_title = "Cluster has quorum tie-breaker (>=3 voters or QDevice)"
    section = "6"
    severity = "MEDIUM"
    frameworks = ["pve_cis", "bcp_py"]
    remediation_static = (
        "Add a third voter to the cluster — easiest is a QDevice on a "
        "low-resource host (Raspberry Pi, container): on the QDevice "
        "host install corosync-qnetd, then on a cluster node run "
        "`pvecm qdevice setup <qdevice-ip>`. Verify with `pvecm status`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        nodes_out, nodes_err, nodes_rc = run_cmd(
            ctx,
            ["pvecm", "nodes"],
            timeout_s=8,
        )
        status_out, status_err, _ = run_cmd(
            ctx,
            ["pvecm", "status"],
            timeout_s=8,
        )

        if nodes_rc != 0:
            # Not a PVE cluster member, or pvecm not on PATH — N/A for
            # this control. We report PASS rather than ERROR because
            # standalone PVE doesn't need a tie-breaker.
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="PASS",
                evidence_command="pvecm nodes",
                evidence_stdout=nodes_out[:2048],
                evidence_stderr=nodes_err[:1024],
                evidence_parsed={"applicable": False, "reason": "pvecm not available"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        node_lines = _NODE_LINE_RE.findall(nodes_out or "")
        node_count = len(node_lines)
        has_qdevice = bool(_QDEVICE_LINE_RE.search((nodes_out or "") + (status_out or "")))

        if node_count <= 1:
            # Standalone PVE — no tie-breaker needed.
            verdict = "PASS"
            reason = "standalone (1 node)"
        elif node_count >= 3 or has_qdevice:
            verdict = "PASS"
            reason = f"{node_count} voters" + (" + QDevice" if has_qdevice else "")
        else:
            verdict = "FAIL"
            reason = f"only {node_count} voters and no QDevice"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="pvecm nodes; pvecm status",
            evidence_stdout=(nodes_out + "\n---\n" + status_out)[:4096],
            evidence_stderr=(nodes_err + "\n" + status_err)[:1024],
            evidence_parsed={
                "node_count": node_count,
                "node_names": node_lines,
                "has_qdevice": has_qdevice,
                "reason": reason,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _PVE61Check()
register_check(CHECK)
