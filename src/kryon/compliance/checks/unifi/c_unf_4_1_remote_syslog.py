"""UNF-4.1 — Controller forwards events to a remote syslog.

`setting.super_remote_syslog` controls upstream forwarding. Without it,
all events live only inside the controller — losing the controller =
losing audit history. PCI-DSS 10.5.3.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _RemoteSyslogCheck:
    control_id = "UNF-4.1"
    control_title = "Controller forwards events to remote syslog"
    section = "4"
    severity = "HIGH"
    remediation_static = (
        "Settings → System → Application Configuration → Remote Logging\n"
        "  - Server: <SIEM_IP>\n"
        "  - Port: 514 (or 6514 for TLS)\n"
        "  - Protocol: TCP if SIEM supports it (UDP loses messages on burst)\n"
        "Or via mongo (one-shot):\n"
        '  db.setting.update({key:"super_remote_syslog"},\n'
        '                    {$set: {value: {server: "siem.corp", port: 514}}})'
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            '\'var d=db.setting.findOne({key:"super_remote_syslog"});'
            "print(JSON.stringify(d || {}))'"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not query mongo"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        is_empty = out.strip() in ("", "{}", "null")
        enabled_m = re.search(r'"enabled"\s*:\s*(\w+)', out)
        server_m = re.search(r'"server"\s*:\s*"([^"]+)"', out)
        port_m = re.search(r'"port"\s*:\s*(\d+)', out)

        enabled = enabled_m and enabled_m.group(1).lower() == "true"
        server = server_m.group(1) if server_m else ""
        port = int(port_m.group(1)) if port_m else 0

        issues: list[str] = []
        if is_empty or not server:
            issues.append("remote-syslog setting absent (logs only on controller)")
        elif not enabled:
            issues.append(f"remote-syslog configured (server={server}) but enabled=false")

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:512],
            evidence_parsed={
                "enabled": bool(enabled),
                "server": server,
                "port": port,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _RemoteSyslogCheck()
register_check(CHECK)
