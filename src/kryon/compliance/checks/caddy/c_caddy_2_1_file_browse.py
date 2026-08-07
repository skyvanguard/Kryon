"""CADDY-2.1 — File-server directory browsing disabled.

`file_server browse` makes Caddy serve a navigable listing of directories that
lack an index file, leaking file names, backups and source. It should not be
enabled.

FAIL if file-server browsing is enabled. PASS otherwise. ERROR if the
Caddyfile is unreadable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.caddy._common import CADDYFILE, make_error, make_result, uncommented
from kryon.compliance.runner import register_check, run_cmd

# Inline form `file_server browse`, or a bare `browse` inside a file_server block.
_BROWSE_RE = re.compile(r"file_server\s+browse\b|^\s*browse\s*$", re.IGNORECASE | re.MULTILINE)


class _FileBrowseCheck:
    control_id = "CADDY-2.1"
    control_title = "File-server directory browsing disabled"
    section = "2"
    severity = "MEDIUM"
    remediation_static = "Remove `browse` from the `file_server` directive so directories without an index return 404 instead of a listing."

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(ctx, CADDYFILE, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=CADDYFILE, out=out, err=err, t0=t0, ctx=ctx, reason="Caddyfile unreadable (Caddy host?)"
            )

        enabled = bool(_BROWSE_RE.search(uncommented(out)))
        verdict = "FAIL" if enabled else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=CADDYFILE,
            out=out[:1024],
            err=err,
            parsed={"file_browse_enabled": enabled},
            t0=t0,
            ctx=ctx,
        )


CHECK = _FileBrowseCheck()
register_check(CHECK)
