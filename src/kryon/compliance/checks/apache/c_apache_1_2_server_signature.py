"""APACHE-1.2 — ServerSignature Off.

CIS Apache Benchmark: `ServerSignature On` appends a version/host footer to
server-generated pages (error pages, directory listings), disclosing the
Apache version. It must be Off.

FAIL if ServerSignature is On. PASS if Off or unset (default Off). ERROR if
Apache is not installed on the host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.apache._common import apache_grep, make_error, make_result, split_probe
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _ServerSignatureCheck:
    control_id = "APACHE-1.2"
    control_title = "ServerSignature Off"
    section = "1"
    severity = "LOW"
    remediation_static = "In the global config:\n  ServerSignature Off\nThen reload Apache."

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = apache_grep(r"^[[:space:]]*ServerSignature[[:space:]]")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        present, lines = split_probe(out)
        if not present:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="Apache config not found (Apache host?)"
            )

        value = lines[-1].split()[1].lower() if lines else "off"  # default Off
        verdict = "FAIL" if value == "on" else "PASS"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"server_signature": value}, t0=t0, ctx=ctx
        )


CHECK = _ServerSignatureCheck()
register_check(CHECK)
