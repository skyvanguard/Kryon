"""APACHE-1.1 — ServerTokens set to Prod.

CIS Apache Benchmark: the default `ServerTokens Full` advertises the exact
Apache version, OS and module versions in the Server header — a CVE shortlist
for attackers. It must be set to `Prod` (emit only "Apache").

FAIL if ServerTokens is anything other than Prod/ProductOnly, or unset
(default Full). ERROR if Apache is not installed on the host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.apache._common import apache_grep, make_error, make_result, split_probe
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _ServerTokensCheck:
    control_id = "APACHE-1.1"
    control_title = "ServerTokens set to Prod"
    section = "1"
    severity = "LOW"
    remediation_static = "In the global config:\n  ServerTokens Prod\nThen reload Apache."

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = apache_grep(r"^[[:space:]]*ServerTokens[[:space:]]")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        present, lines = split_probe(out)
        if not present:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="Apache config not found (Apache host?)"
            )

        # Apache is last-wins for server-level directives.
        value = lines[-1].split()[1].lower() if lines else "(unset→full)"
        verdict = "PASS" if value in ("prod", "productonly") else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"server_tokens": value}, t0=t0, ctx=ctx
        )


CHECK = _ServerTokensCheck()
register_check(CHECK)
