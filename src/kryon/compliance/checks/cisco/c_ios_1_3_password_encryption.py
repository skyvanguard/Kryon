"""IOS-1.3 — service password-encryption enabled.

CIS Cisco Benchmark: without `service password-encryption`, line and other
passwords are stored in cleartext in the running/startup config — visible to
anyone who can read it (backups, TFTP, shoulder-surfing). It must be enabled.

FAIL if the directive is absent. PASS if present. ERROR if the output isn't
an IOS running-config.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.cisco._common import SHOW_RUN, looks_like_ios, make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_SPE_RE = re.compile(r"^service password-encryption\b", re.IGNORECASE | re.MULTILINE)


class _PasswordEncryptionCheck:
    control_id = "IOS-1.3"
    control_title = "service password-encryption enabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = "Enable it in global config:\n  service password-encryption"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, SHOW_RUN, shell=True, timeout_s=15)
        if not looks_like_ios(out):
            return make_error(
                self, cmd=SHOW_RUN, out=out, err=err, t0=t0, ctx=ctx, reason="not an IOS running-config (Cisco host?)"
            )

        enabled = bool(_SPE_RE.search(out))
        verdict = "PASS" if enabled else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=SHOW_RUN,
            out=out[:1024],
            err=err,
            parsed={"password_encryption": enabled},
            t0=t0,
            ctx=ctx,
        )


CHECK = _PasswordEncryptionCheck()
register_check(CHECK)
