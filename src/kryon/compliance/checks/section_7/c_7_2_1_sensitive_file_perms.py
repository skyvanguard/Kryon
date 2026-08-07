"""PCI-DSS v4 control 7.2.1 — Access is defined and assigned by least privilege.

The OS-level expression of "need to know": credential and privilege files must
not be world-accessible. Checks the permissions of:
  /etc/shadow, /etc/gshadow  (password hashes)
  /etc/sudoers               (privilege grants)

FAIL if any is world-readable/writable or not root-owned. ERROR if none can be
stat'd (host unreachable). Files that don't exist are skipped.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_SENSITIVE_FILES = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers")


class _C721Check:
    control_id = "7.2.1"
    control_title = "Least privilege on sensitive files"
    section = "7"
    severity = "HIGH"
    remediation_static = (
        "Lock down credential/privilege files. `chown root:shadow /etc/shadow && "
        "chmod 640 /etc/shadow` (same for /etc/gshadow); `chown root:root /etc/sudoers "
        "&& chmod 440 /etc/sudoers`. No file here should be world-readable or "
        "world-writable (PCI-DSS 7.2.1 least privilege / need-to-know)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, ["stat", "-c", "%n %a %U", *_SENSITIVE_FILES], timeout_s=5)
        if not out.strip():
            return self._result("ERROR", out, err, {"reason": "stat produced no output"}, t0, ctx)

        per_file: dict[str, dict] = {}
        issues: list[str] = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            name, mode, owner = parts[0], parts[1], parts[2]
            file_issues: list[str] = []
            try:
                other = int(mode[-1])
                if other & 4:
                    file_issues.append("world-readable")
                if other & 2:
                    file_issues.append("world-writable")
            except (ValueError, IndexError):
                pass
            if owner != "root":
                file_issues.append(f"owner {owner} != root")
            per_file[name] = {"mode": mode, "owner": owner, "issues": file_issues}
            if file_issues:
                issues.append(f"{name}: {file_issues}")

        if not per_file:
            return self._result("N/A", out, err, {"reason": "no sensitive files present"}, t0, ctx)

        verdict = "FAIL" if issues else "PASS"
        return self._result(verdict, out, err, {"files": per_file, "issues": sorted(issues)}, t0, ctx)

    def _result(self, verdict, stdout, stderr, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"stat -c '%n %a %U' {' '.join(_SENSITIVE_FILES)}",
            evidence_stdout=stdout[:4096],
            evidence_stderr=stderr[:1024],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C721Check()
register_check(CHECK)
