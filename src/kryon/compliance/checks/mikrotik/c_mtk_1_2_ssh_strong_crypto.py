"""MTK-1.2 — SSH strong-crypto enabled.

RouterOS SSH defaults to weak ciphers/MACs for backward compatibility.
`/ip ssh set strong-crypto=yes` forces AES-CTR, SHA2 MACs and larger DH
groups, removing the deprecated algorithms.

FAIL if strong-crypto = no. ERROR if the command can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _SshStrongCryptoCheck:
    control_id = "MTK-1.2"
    control_title = "SSH strong-crypto enabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = "Enable strong SSH crypto:\n  /ip ssh set strong-crypto=yes"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "/ip ssh print"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="RouterOS CLI call failed")

        m = re.search(r"strong-crypto:\s*(yes|no)", out, re.IGNORECASE)
        value = m.group(1).lower() if m else None
        verdict = "PASS" if value == "yes" else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"strong_crypto": value}, t0=t0, ctx=ctx
        )


CHECK = _SshStrongCryptoCheck()
register_check(CHECK)
