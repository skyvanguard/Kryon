"""PCI-DSS v4 control 8.2.1 — Unique user IDs.

Every user must have a unique identifier and there must be no shared or
backdoor identities. From /etc/passwd this check flags:

  - **duplicate UIDs** — two usernames sharing one UID (= shared identity)
  - **non-root UID 0** — any account other than `root` with UID 0
    (a hidden-root / backdoor account)

FAIL if either is present. ERROR if /etc/passwd is unreadable.
"""

from __future__ import annotations

import time
from collections import defaultdict

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _C821Check:
    control_id = "8.2.1"
    control_title = "Unique user IDs"
    section = "8"
    severity = "HIGH"
    remediation_static = (
        "Assign every user a unique UID; never share logins. Remove or rename any "
        "non-root account with UID 0 (`usermod -u <new> <user>` or delete it) — only "
        "root may hold UID 0. Merge duplicate UIDs so each identity is distinct "
        "(PCI-DSS 8.2.1)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, ["cat", "/etc/passwd"], timeout_s=5)
        if rc != 0 and not out.strip():
            return self._result("ERROR", out, err, {"reason": "/etc/passwd unreadable"}, t0, ctx)

        uid_to_users: dict[int, list[str]] = defaultdict(list)
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) < 3:
                continue
            user = parts[0]
            try:
                uid = int(parts[2])
            except ValueError:
                continue
            uid_to_users[uid].append(user)

        duplicate_uids = {str(uid): users for uid, users in uid_to_users.items() if len(users) > 1}
        extra_uid0 = [u for u in uid_to_users.get(0, []) if u != "root"]

        issues: list[str] = []
        if duplicate_uids:
            issues.append(f"duplicate UIDs: {duplicate_uids}")
        if extra_uid0:
            issues.append(f"non-root UID 0 accounts: {extra_uid0}")

        return self._result(
            "FAIL" if issues else "PASS",
            out,
            err,
            {"duplicate_uids": duplicate_uids, "non_root_uid0": sorted(extra_uid0), "issues": sorted(issues)},
            t0,
            ctx,
        )

    def _result(self, verdict, stdout, stderr, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="cat /etc/passwd",
            evidence_stdout=stdout[:4096],
            evidence_stderr=stderr[:1024],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C821Check()
register_check(CHECK)
