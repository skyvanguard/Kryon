"""APACHE-2.1 — Directory listing (Options Indexes) disabled.

CIS Apache Benchmark: `Options Indexes` (or `+Indexes`) makes Apache serve a
browsable listing of directories that lack an index file, leaking file names,
backups and source. Directories must not enable Indexes.

FAIL if any Options directive enables Indexes (`Indexes` / `+Indexes`). PASS
if none do. ERROR if Apache is not installed on the host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.apache._common import apache_grep, make_error, make_result, split_probe
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _enables_indexes(line: str) -> bool:
    # A token "Indexes" or "+Indexes" enables it; "-Indexes" disables it.
    for tok in line.split()[1:]:
        if tok.lower() in ("indexes", "+indexes"):
            return True
    return False


class _IndexesCheck:
    control_id = "APACHE-2.1"
    control_title = "Directory listing (Options Indexes) disabled"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Remove Indexes from the affected Options directives (use `Options -Indexes`\nor omit it), then reload Apache."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = apache_grep(r"^[[:space:]]*Options[[:space:]].*Indexes")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        present, lines = split_probe(out)
        if not present:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="Apache config not found (Apache host?)"
            )

        offenders = [ln for ln in lines if _enables_indexes(ln)]
        verdict = "FAIL" if offenders else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"indexes_enabled_lines": len(offenders)},
            t0=t0,
            ctx=ctx,
        )


CHECK = _IndexesCheck()
register_check(CHECK)
