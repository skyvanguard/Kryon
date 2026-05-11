"""FGT-4.1 — Logs forwarded to upstream syslog or FortiAnalyzer.

PCI-DSS 10.5.3 requires logs to be promptly backed up to a centralised
log server outside the device generating them. FortiGate has two paths:
  - syslog (config log syslogd setting)
  - FortiAnalyzer (config log fortianalyzer setting)
Either MUST be enabled; ideally both.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _SyslogUpstreamCheck:
    control_id = "FGT-4.1"
    control_title = "Logs forwarded to upstream syslog and/or FortiAnalyzer"
    section = "4"
    severity = "HIGH"
    remediation_static = (
        "Enable a syslog destination:\n"
        "  config log syslogd setting\n"
        "    set status enable\n"
        "    set server <SIEM_IP>\n"
        "    set port 514                          # 6514 for TLS\n"
        "    set facility local7\n"
        "    set source-ip <fgt_management_ip>\n"
        "    set reliable enable                   # TCP delivery\n"
        "  end\n"
        "Or attach FortiAnalyzer:\n"
        "  config log fortianalyzer setting\n"
        "    set status enable\n"
        "    set server <FAZ_IP>\n"
        "    set upload-option realtime\n"
        "  end"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd_a = "show full-configuration log syslogd setting"
        cmd_b = "show full-configuration log fortianalyzer setting"
        out_a, err_a, rc_a = run_cmd(ctx, cmd_a, shell=True, timeout_s=8)
        out_b, err_b, rc_b = run_cmd(ctx, cmd_b, shell=True, timeout_s=8)

        if (rc_a != 0 and not out_a) and (rc_b != 0 and not out_b):
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=f"{cmd_a} ; {cmd_b}",
                evidence_stdout=(out_a + "\n---\n" + out_b)[:1024],
                evidence_stderr=(err_a + "\n" + err_b)[:512],
                evidence_parsed={"reason": "could not read log settings"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        def status_of(blob: str) -> str:
            m = re.search(r"^\s*set\s+status\s+(\S+)", blob, re.M)
            return m.group(1).lower() if m else "disable"

        syslogd_status = status_of(out_a)
        faz_status = status_of(out_b)

        issues: list[str] = []
        if syslogd_status == "disable" and faz_status == "disable":
            issues.append("neither syslog nor FortiAnalyzer is enabled — logs only local")

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{cmd_a} ; {cmd_b}",
            evidence_stdout=(out_a + "\n---\n" + out_b)[:2048],
            evidence_stderr=(err_a + "\n" + err_b)[:512],
            evidence_parsed={
                "syslogd_status": syslogd_status,
                "fortianalyzer_status": faz_status,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SyslogUpstreamCheck()
register_check(CHECK)
