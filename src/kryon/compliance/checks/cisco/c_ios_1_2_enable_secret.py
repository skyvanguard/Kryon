"""IOS-1.2 — Privileged EXEC protected by `enable secret`.

CIS Cisco Benchmark: `enable password` stores the privileged-mode password
with the trivially reversible Vigenère (type 7) scheme or in cleartext.
`enable secret` uses a proper hash and takes precedence. `enable password`
must not be the only protection.

FAIL if `enable password` is configured without `enable secret`. PASS if
`enable secret` is present. ERROR if the output isn't an IOS running-config.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.cisco._common import SHOW_RUN, looks_like_ios, make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_SECRET_RE = re.compile(r"^enable secret ", re.IGNORECASE | re.MULTILINE)
_PASSWORD_RE = re.compile(r"^enable password ", re.IGNORECASE | re.MULTILINE)


class _EnableSecretCheck:
    control_id = "IOS-1.2"
    control_title = "Privileged EXEC protected by enable secret"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Set a hashed enable secret and drop the weak password:\n  enable secret <strong>\n  no enable password"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, SHOW_RUN, shell=True, timeout_s=15)
        if not looks_like_ios(out):
            return make_error(
                self, cmd=SHOW_RUN, out=out, err=err, t0=t0, ctx=ctx, reason="not an IOS running-config (Cisco host?)"
            )

        has_secret = bool(_SECRET_RE.search(out))
        has_password = bool(_PASSWORD_RE.search(out))
        verdict = "FAIL" if (has_password and not has_secret) else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=SHOW_RUN,
            out=out[:1024],
            err=err,
            parsed={"enable_secret": has_secret, "enable_password": has_password},
            t0=t0,
            ctx=ctx,
        )


CHECK = _EnableSecretCheck()
register_check(CHECK)
