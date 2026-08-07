"""PCI-DSS v4 control 2.2.5 — Insecure services, protocols, and daemons.

Detects cleartext / legacy services listening on the host that PCI-DSS
requires to be disabled (or documented with a business justification and
compensating controls):

  telnet (23/tcp), ftp (21/tcp), rsh (514/tcp), rlogin (513/tcp),
  tftp (69/udp).

FAIL if any are listening. PASS if none. Uses `ss -tlnu`.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# port → service label for the insecure services PCI 2.2.5 flags
_INSECURE_TCP = {23: "telnet", 21: "ftp", 514: "rsh", 513: "rlogin", 512: "rexec"}
_INSECURE_UDP = {69: "tftp"}


def _listening_ports(stdout: str) -> set[int]:
    ports: set[int] = set()
    for line in stdout.splitlines():
        # ss shows "...:PORT " in the Local Address:Port column.
        for m in re.finditer(r":(\d+)\s", line):
            try:
                ports.add(int(m.group(1)))
            except ValueError:
                pass
    return ports


class _C225Check:
    control_id = "2.2.5"
    control_title = "Insecure services, protocols, and daemons"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Disable cleartext/legacy services. Stop and mask the daemons "
        "(e.g. `systemctl disable --now telnet.socket vsftpd tftpd`), remove the "
        "packages, and use encrypted replacements (SSH/SFTP/HTTPS). If a service is "
        "truly required, document the business justification + compensating controls "
        "(PCI-DSS 2.2.5)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        stdout, stderr, rc = run_cmd(ctx, ["ss", "-tlnu"], timeout_s=5)
        if rc != 0 and not stdout.strip():
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command="ss -tlnu",
                evidence_stdout=stdout,
                evidence_stderr=stderr[:1024],
                evidence_parsed={"reason": "ss unavailable"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        ports = _listening_ports(stdout)
        found: list[str] = []
        for port, name in {**_INSECURE_TCP, **_INSECURE_UDP}.items():
            if port in ports:
                found.append(f"{name} ({port})")

        verdict = "FAIL" if found else "PASS"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="ss -tlnu",
            evidence_stdout=stdout[:4096],
            evidence_stderr="",
            evidence_parsed={"insecure_services_listening": sorted(found)},
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C225Check()
register_check(CHECK)
