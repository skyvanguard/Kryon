"""PCI-DSS v4 control 11.5.1 — Intrusion-detection and/or intrusion-prevention
techniques detect and/or prevent intrusions.

Probes, in a single `systemctl is-active` call, for a running IDS/IPS/HIDS:
  - NIDS/NIPS: snort, suricata, zeek
  - host IPS / HIDS: fail2ban, ossec, wazuh-agent, samhain, aide

PASS if any is active. FAIL if none is (PCI requires intrusion detection at
the perimeter and critical points). ERROR if systemctl is unavailable.

(Overlap is expected: fail2ban also satisfies 2.2.8, and wazuh/ossec 5.2.1 —
one tool can cover several controls. This check is specifically about
intrusion detection capability.)
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_SERVICES = (
    "snort",
    "suricata",
    "zeek",
    "fail2ban",
    "ossec",
    "wazuh-agent",
    "samhain",
    "aide",
)


class _C1151Check:
    control_id = "11.5.1"
    control_title = "Intrusion detection / prevention"
    section = "11"
    severity = "HIGH"
    remediation_static = (
        "Deploy an IDS/IPS and keep it running. Network: Suricata or Snort in IDS/IPS "
        "mode at the perimeter (`systemctl enable --now suricata`). Host: fail2ban for "
        "brute-force prevention plus a HIDS (Wazuh/OSSEC/AIDE) for file-integrity and "
        "log-based detection, with alerting to personnel (PCI-DSS 11.5.1)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, ["systemctl", "is-active", *_SERVICES], timeout_s=6)

        if not out.strip() and rc != 0:
            return self._result("ERROR", out, err, {"reason": "systemctl unavailable"}, t0, ctx)

        statuses = out.splitlines()
        active = [svc for svc, status in zip(_SERVICES, statuses) if status.strip() == "active"]

        return self._result(
            "PASS" if active else "FAIL",
            out,
            err,
            {"active_ids_ips": sorted(active), "probed": list(_SERVICES)},
            t0,
            ctx,
        )

    def _result(self, verdict, stdout, stderr, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"systemctl is-active {' '.join(_SERVICES)}",
            evidence_stdout=stdout[:4096],
            evidence_stderr=stderr[:1024],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C1151Check()
register_check(CHECK)
