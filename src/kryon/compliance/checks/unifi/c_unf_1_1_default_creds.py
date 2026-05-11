"""UNF-1.1 — No admin account uses default Unifi credentials.

Unifi controllers ship with `ubnt/ubnt` on legacy APs (pre-adoption) and
allow `admin/admin` patterns on self-deploys. Mongo `admin` collection
holds super-admin entries; vendor defaults are unsalted SHA1, easy to
fingerprint.

Detection: dump all admins with their stored x_password digest length.
Modern Unifi uses bcrypt ($2a$/$2b$) → length 60. Legacy SHA1 → 40 hex.
A bcrypt hash with the known-default password produces a fingerprint we
do NOT have access to (salt is unique), so this check uses the much
simpler heuristic: any admin named exactly `ubnt` or `admin` with a
SHA1-style hash is FAIL.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_DEFAULT_NAMES = {"ubnt", "admin", "root"}
_SHA1_HEX = re.compile(r"^[0-9a-fA-F]{40}$")


class _UnifiDefaultCredsCheck:
    control_id = "UNF-1.1"
    control_title = "No admin account uses default Unifi credentials"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Rotate the bootstrap admin to a strong unique password and create\n"
        "per-operator named accounts:\n"
        "  Settings → Admins & Users → Add Admin\n"
        "Delete `ubnt` and rename the original `admin` account. Always\n"
        "configure a fresh AP via secure adoption (Network Application\n"
        "or set-inform with rotated credentials) — never leave it on the\n"
        "vendor default.\n"
        "On self-hosted controllers, also rotate the OS root password\n"
        "and disable SSH password auth (PubkeyAuthentication only)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.admin.find({}, {name:1, x_shadow:1, x_password:1, "
            "site_id:1, role:1}).forEach(function(d){print(JSON.stringify(d))})'"
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
                evidence_parsed={
                    "reason": "could not query mongo (controller offline / no SSH)"
                },
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        admins: list[dict[str, str]] = []
        suspect_admins: list[str] = []
        for line in out.splitlines():
            ls = line.strip()
            if not ls or not ls.startswith("{"):
                continue
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            shadow_m = re.search(r'"x_shadow"\s*:\s*"([^"]+)"', ls)
            pwd_m = re.search(r'"x_password"\s*:\s*"([^"]+)"', ls)
            name = name_m.group(1) if name_m else ""
            shadow = shadow_m.group(1) if shadow_m else ""
            pwd = pwd_m.group(1) if pwd_m else ""
            admins.append({"name": name, "x_shadow": shadow, "x_password": pwd})
            # Suspicion rules
            if name.lower() in _DEFAULT_NAMES:
                suspect_admins.append(name)
            if pwd and _SHA1_HEX.match(pwd):
                suspect_admins.append(f"{name} (legacy SHA1 hash)")

        issues = [
            f"admin '{n}' matches default-name / weak-hash heuristic"
            for n in sorted(set(suspect_admins))
        ]
        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed={
                "admin_count": len(admins),
                "admin_names": sorted(a["name"] for a in admins if a["name"]),
                "suspect": sorted(set(suspect_admins)),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _UnifiDefaultCredsCheck()
register_check(CHECK)
