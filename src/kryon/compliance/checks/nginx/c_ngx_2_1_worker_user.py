"""NGX-2.1 — Worker processes do not run as root.

CIS nginx Benchmark: the `user` directive sets the account nginx worker
processes drop to. If it is `root`, a worker compromise (e.g. via a module
bug) is an immediate full-host compromise. Workers must run as an
unprivileged account (nginx / www-data).

FAIL if `user root` is configured. PASS otherwise (default nobody / an
unprivileged account). ERROR if `nginx -T` can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.nginx._common import NGINX_DUMP, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

_USER_ROOT_RE = re.compile(r"^\s*user\s+root\b", re.IGNORECASE | re.MULTILINE)


class _WorkerUserCheck:
    control_id = "NGX-2.1"
    control_title = "Worker processes do not run as root"
    section = "2"
    severity = "HIGH"
    remediation_static = "Set an unprivileged worker user in nginx.conf:\n  user nginx;   # or www-data\nReload nginx."

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, NGINX_DUMP, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=NGINX_DUMP, out=out, err=err, t0=t0, ctx=ctx, reason="`nginx -T` failed (nginx host?)"
            )

        runs_as_root = bool(_USER_ROOT_RE.search(uncommented(out)))
        verdict = "FAIL" if runs_as_root else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=NGINX_DUMP,
            out=out,
            err=err,
            parsed={"worker_user_root": runs_as_root},
            t0=t0,
            ctx=ctx,
        )


CHECK = _WorkerUserCheck()
register_check(CHECK)
