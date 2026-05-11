"""UNF-3.4 — AP ↔ controller inform channel uses encryption.

Unifi APs talk to the controller on port 8080 via the "inform" protocol.
Modern firmware encrypts this channel by default (`mgmt_cfg.cfgversion`
includes a per-AP secret). Legacy / Mongo migrations sometimes carry
unencrypted inform — `db.device.find({})` field `inform_authkey` and
`mgmt_cfg.cfgversion` indicate which.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _InformEncryptionCheck:
    control_id = "UNF-3.4"
    control_title = "AP ↔ controller inform channel uses encryption"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Re-provision affected APs:\n"
        "  Devices → <AP> → Manage → Provision\n"
        "If the inform_authkey is empty in mongo, run:\n"
        '  mongo ... db.setting.update({key:"mgmt"}, {$set: {x_inform_authkey: "<NEW>"}})\n'
        "Then force AP reconnect:\n"
        "  ssh ubnt@<AP> set-inform http://<controller>:8080/inform\n"
        "Confirm with `info` on the AP CLI: Status: Connected (encrypted)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.device.find({adopted: true}, "
            "{name:1, model:1, inform_authkey:1, mgmt_cfg:1, state:1})"
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
                evidence_parsed={"reason": "could not query device"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        unencrypted: list[str] = []
        device_count = 0
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            device_count += 1
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            authkey_m = re.search(r'"inform_authkey"\s*:\s*"([^"]*)"', ls)
            cfgver_m = re.search(r'"cfgversion"\s*:\s*"([^"]*)"', ls)
            if not name_m:
                continue
            authkey = authkey_m.group(1) if authkey_m else ""
            cfgver = cfgver_m.group(1) if cfgver_m else ""
            if not authkey and not cfgver:
                unencrypted.append(name_m.group(1))

        issues = [f"AP '{n}' inform channel unencrypted (no authkey / cfgversion)" for n in sorted(set(unencrypted))]
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
                "device_count": device_count,
                "unencrypted_inform_aps": sorted(set(unencrypted)),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _InformEncryptionCheck()
register_check(CHECK)
