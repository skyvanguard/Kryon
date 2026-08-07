"""NGX-1.3 — Directory listing (autoindex) disabled.

CIS nginx Benchmark: `autoindex on` makes nginx serve a browsable listing of
any directory without an index file, leaking file names, backups and source.
It must stay off (the default).

FAIL if any `autoindex on` is present. PASS otherwise (default off / explicit
off). ERROR if `nginx -T` can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.nginx._common import NGINX_DUMP, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_AUTOINDEX_ON_RE = re.compile(r"\bautoindex\s+on\b", re.IGNORECASE)


class _AutoindexCheck:
    control_id = "NGX-1.3"
    control_title = "Directory listing (autoindex) disabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = "Remove `autoindex on;` (or set `autoindex off;`) from the affected blocks; reload nginx."

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, NGINX_DUMP, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=NGINX_DUMP, out=out, err=err, t0=t0, ctx=ctx, reason="`nginx -T` failed (nginx host?)"
            )

        hits = len(_AUTOINDEX_ON_RE.findall(uncommented(out)))
        verdict = "FAIL" if hits else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=NGINX_DUMP,
            out=out,
            err=err,
            parsed={"autoindex_on_blocks": hits},
            t0=t0,
            ctx=ctx,
        )


CHECK = _AutoindexCheck()
register_check(CHECK)
