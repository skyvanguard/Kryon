"""UNF-4.2 — Adopted APs run firmware no older than N-2 minor revisions.

Each device document carries `version` (firmware running) and
`upgradable_firmware` / `upgrade_to_firmware` (controller's view of
the latest). If the running version is more than 2 minor revisions
behind the available, FAIL.

This is a soft check — strict CVE chain requires correlating with the
Ubiquiti security advisory feed which we don't bundle here.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# Threshold in minor revisions. Anything above is FAIL.
_MAX_MINOR_BEHIND = 2


def _parse_version(raw: str) -> tuple[int, int, int] | None:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


class _ApFirmwareCurrencyCheck:
    control_id = "UNF-4.2"
    control_title = f"AP firmware not more than {_MAX_MINOR_BEHIND} minor revisions behind"
    section = "4"
    severity = "MEDIUM"
    remediation_static = (
        "Update affected APs:\n"
        "  Devices → <AP> → Upgrade → Apply\n"
        "Or batch:\n"
        "  Settings → System → Updates → Auto Update → Enable\n"
        "Test in a maintenance window — firmware updates briefly drop SSIDs.\n"
        "On Wi-Fi 6 APs, schedule overnight to avoid client churn."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.device.find({adopted: true}, "
            "{name:1, model:1, version:1, upgradable:1, upgrade_to_firmware:1})"
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

        outdated: list[dict[str, str]] = []
        device_count = 0
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            device_count += 1
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            ver_m = re.search(r'"version"\s*:\s*"([\d\.]+)', ls)
            target_m = re.search(r'"upgrade_to_firmware"\s*:\s*"([\d\.]+)', ls)
            upgradable_m = re.search(r'"upgradable"\s*:\s*(\w+)', ls)
            if not name_m or not ver_m:
                continue
            running = _parse_version(ver_m.group(1))
            target = _parse_version(target_m.group(1)) if target_m else None
            upgradable = upgradable_m and upgradable_m.group(1).lower() == "true"
            if not running or not target:
                continue
            # Compute minor delta on the same major branch.
            if running[0] == target[0]:
                minor_delta = target[1] - running[1]
            else:
                minor_delta = (target[0] - running[0]) * 100 + (target[1] - running[1])
            if upgradable and minor_delta > _MAX_MINOR_BEHIND:
                outdated.append(
                    {
                        "name": name_m.group(1),
                        "running": ver_m.group(1),
                        "target": target_m.group(1) if target_m else "",
                        "minor_delta": minor_delta,
                    }
                )

        issues = [
            f"AP '{o['name']}' on {o['running']} (target {o['target']}, {o['minor_delta']} minors behind)"
            for o in outdated
        ]
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
                "outdated_aps": [o["name"] for o in outdated],
                "max_minors_behind": _MAX_MINOR_BEHIND,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _ApFirmwareCurrencyCheck()
register_check(CHECK)
