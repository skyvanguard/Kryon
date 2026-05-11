"""FGT-5.3 — FortiOS not exposed to known mass-exploited CVEs.

We map running FortiOS version to a curated list of CVEs known to have
public exploit code AND FortiGuard-grade severity. The list is hardcoded
per Kryon release; pulling live KEV data would break determinism.

Surfaced separately from FGT-5.1 (version-currency) because some patched
FortiOS minors still have *unpatched* CVEs in the wild, especially when
the build is older than the security advisory.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# (CVE_ID, fixed-in-version triple, fixed-in-version-major-only-fallback,
#  affected-version-range-textual). Extend as new advisories drop.
# Format of fixed_in: (major, minor, patch). A running version >= fixed_in
# on the same minor branch is considered patched.
_KNOWN_CVES = [
    {
        "cve": "CVE-2022-42475",
        "title": "SSL VPN heap overflow → unauth RCE",
        "fixed_in": [
            (7, 2, 3), (7, 0, 9), (6, 4, 11), (6, 2, 13), (6, 0, 16),
        ],
        "exploit": "public, mass-exploited",
    },
    {
        "cve": "CVE-2023-27997",
        "title": "SSL VPN heap overflow → unauth RCE (XORtigate)",
        "fixed_in": [
            (7, 2, 5), (7, 0, 12), (6, 4, 13), (6, 2, 15), (6, 0, 17),
        ],
        "exploit": "public",
    },
    {
        "cve": "CVE-2024-21762",
        "title": "SSL VPN out-of-bounds write → unauth RCE",
        "fixed_in": [
            (7, 4, 3), (7, 2, 7), (7, 0, 14), (6, 4, 15), (6, 2, 16),
        ],
        "exploit": "public, KEV",
    },
    {
        "cve": "CVE-2024-23113",
        "title": "fgfmd format string → RCE",
        "fixed_in": [
            (7, 4, 3), (7, 2, 7), (7, 0, 14), (6, 4, 15),
        ],
        "exploit": "public, KEV",
    },
]


def _is_patched(running: tuple[int, int, int], fixes: list[tuple[int, int, int]]) -> bool:
    """A version is patched if its (major,minor) matches a fix-branch and
    the patch-level is >= the fixed-in patch on that branch."""
    rmaj, rmin, rpatch = running
    for fmaj, fmin, fpatch in fixes:
        if rmaj == fmaj and rmin == fmin and rpatch >= fpatch:
            return True
    # If the running branch is newer than ALL fix-branches, treat as patched.
    if all((rmaj, rmin) > (fmaj, fmin) for fmaj, fmin, _ in fixes):
        return True
    return False


class _KnownCveExposureCheck:
    control_id = "FGT-5.3"
    control_title = "FortiOS not exposed to mass-exploited CVEs"
    section = "5"
    severity = "CRITICAL"
    remediation_static = (
        "For each affected CVE, upgrade to the corresponding fixed FortiOS\n"
        "release on your branch. Do NOT skip multiple minors at once — go\n"
        "one minor at a time. Reference: PSIRT advisories at\n"
        "https://www.fortiguard.com/psirt and Fortinet KEV mappings."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "get system status"
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
                evidence_parsed={"reason": "could not read system status"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Version: FortiGate-VM64 v7.4.3,build2573,240314 (GA.M)
        ver_match = re.search(r"Version[^\n]*?v(\d+)\.(\d+)\.(\d+)", out)
        if not ver_match:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not parse Version line"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )
        running = (
            int(ver_match.group(1)),
            int(ver_match.group(2)),
            int(ver_match.group(3)),
        )

        exposed: list[dict[str, str]] = []
        for cve in _KNOWN_CVES:
            if not _is_patched(running, cve["fixed_in"]):
                exposed.append({
                    "cve": cve["cve"],
                    "title": cve["title"],
                    "exploit": cve["exploit"],
                })

        issues = [
            f"{e['cve']} ({e['title']}) — exploit status: {e['exploit']}"
            for e in exposed
        ]
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
                "running_version": ".".join(str(v) for v in running),
                "exposed_cves": [e["cve"] for e in exposed],
                "checked_cve_count": len(_KNOWN_CVES),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _KnownCveExposureCheck()
register_check(CHECK)
