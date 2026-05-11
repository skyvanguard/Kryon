"""CIS section 10 control 10.2.2 — Logging daemon active.

Audit trail durability requires a logging daemon that forwards to a
remote collector (Wazuh, SIEM, syslog server). At minimum the local
journald-to-disk path must be intact, but for compliance we expect a
syslog-compatible service running:

  - rsyslog        (Debian/Ubuntu default)
  - syslog-ng      (alternative)
  - systemd-journal-upload  (modern alternative when rsyslog removed)

Verdict FAIL when none is active. PVE hosts ship rsyslog active by
default — when it's down, alerts to Wazuh stop flowing silently.

Closes ground-truth gap H-04.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_CANDIDATES = ("rsyslog", "syslog-ng", "systemd-journal-upload")


class _C1022Check:
    control_id = "10.2.2"
    control_title = "Syslog daemon active"
    section = "10"
    severity = "HIGH"
    remediation_static = (
        "Enable a syslog daemon: `systemctl enable --now rsyslog`. If "
        "rsyslog was removed deliberately, configure systemd-journal-"
        "upload to forward to a remote collector instead."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        states: dict[str, str] = {}
        combined_stdout = []
        combined_stderr = []
        for unit in _CANDIDATES:
            out, err, _ = run_cmd(
                ctx, ["systemctl", "is-active", unit], timeout_s=5,
            )
            state = (out or "").strip().lower()
            states[unit] = state
            combined_stdout.append(f"{unit}: {state}")
            if err:
                combined_stderr.append(err)

        any_active = any(s == "active" for s in states.values())
        verdict = "PASS" if any_active else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="; ".join(
                f"systemctl is-active {u}" for u in _CANDIDATES
            ),
            evidence_stdout="\n".join(combined_stdout)[:4096],
            evidence_stderr="\n".join(combined_stderr)[:1024],
            evidence_parsed={
                "service_states": states,
                "any_active": any_active,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C1022Check()
register_check(CHECK)
