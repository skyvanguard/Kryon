"""UNF-1.4 — Controller / UDM firmware is current and not on a known-vuln branch.

The UDM-OS / Unifi Network Application versions are in `/etc/version` (UDM)
or in the Unifi Network app's `system.properties`. We surface the version
and flag anything below a hardcoded floor (updated per Kryon release).

Operator can override via env var `KRYON_UNIFI_MIN_NETWORK` (e.g. `8.0`).
"""

from __future__ import annotations

import os
import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


# Unifi Network Application supported floor as of 2026-04-28. The 7.x line
# is in security-only support; anything below 7.5 has known unpatched issues
# in older builds. 8.x is current GA.
_DEFAULT_MIN_MAJOR = 8
_DEFAULT_MIN_MINOR = 0


def _parse_floor() -> tuple[int, int]:
    raw = os.environ.get("KRYON_UNIFI_MIN_NETWORK", "").strip()
    if not raw:
        return _DEFAULT_MIN_MAJOR, _DEFAULT_MIN_MINOR
    m = re.match(r"^(\d+)\.(\d+)", raw)
    if not m:
        return _DEFAULT_MIN_MAJOR, _DEFAULT_MIN_MINOR
    return int(m.group(1)), int(m.group(2))


class _ControllerFirmwareCheck:
    control_id = "UNF-1.4"
    control_title = "Unifi Network Application is at supported version"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Schedule controller upgrade in maintenance window:\n"
        "  - UDM/UDM-Pro: Settings → System → Updates → Apply\n"
        "  - Self-hosted: download .deb from ui.com/download and `dpkg -i`\n"
        "Always backup first: Settings → Backup → Download Backup.\n"
        "After upgrade, re-test AP adoption status — old APs sometimes\n"
        "need re-provisioning."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'var s=db.setting.findOne({key:\"super_identity\"});"
            "var i=db.setting.findOne({key:\"super_install_info\"});"
            "print(JSON.stringify({version: (i && i.version) || \"\", build: (i && i.build) || \"\"}))'"
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
                evidence_parsed={"reason": "could not read controller version"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        ver_match = re.search(r'"version"\s*:\s*"([\d\.]+)', out)
        version_raw = ver_match.group(1) if ver_match else ""
        major, minor, patch = 0, 0, 0
        if version_raw:
            parts = version_raw.split(".")
            try:
                major = int(parts[0])
                minor = int(parts[1]) if len(parts) > 1 else 0
                patch = int(parts[2]) if len(parts) > 2 else 0
            except (ValueError, IndexError):
                pass

        min_major, min_minor = _parse_floor()
        issues: list[str] = []
        if version_raw and (major, minor) < (min_major, min_minor):
            issues.append(
                f"Controller {version_raw} < supported floor {min_major}.{min_minor}.x"
            )
        if not version_raw:
            issues.append("could not parse controller version from setting collection")

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
                "version_raw": version_raw,
                "version_major": major,
                "version_minor": minor,
                "version_patch": patch,
                "min_supported_major": min_major,
                "min_supported_minor": min_minor,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _ControllerFirmwareCheck()
register_check(CHECK)
