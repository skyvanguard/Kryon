"""TOMCAT-2.2 — Server header no revela Apache-Coyote / Apache Tomcat.

`Server: Apache-Coyote/1.1` o `Server: Apache Tomcat/X.Y.Z` permite
fingerprinting trivial sin autenticación. Information disclosure
(CWE-200).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.tomcat._common import fingerprint, make_result, na_result, target_port
from kryon.compliance.runner import register_check


class _ServerHeaderDisclosureCheck:
    control_id = "TOMCAT-2.2"
    control_title = "Server header does not disclose Apache Tomcat / Coyote"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Suppress the Server header value in $CATALINA_BASE/conf/server.xml:\n"
        '  <Connector port="8080" protocol="HTTP/1.1"\n'
        '             server=" " ... />\n'
        "(A single space is intentional — empty string falls back to default.)\n"
        "Restart Tomcat. Verify with `curl -sSI http://localhost:8080/`.\n"
        'Optionally also set `xpoweredBy="false"` and remove the\n'
        "`X-Powered-By: JSP/2.x` header via Connector attribute."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        fp = fingerprint(ctx.host, target_port(ctx))

        if not fp.is_tomcat:
            return na_result(self, ctx=ctx, reason="not an Apache Tomcat host", t0=t0)

        header = fp.server_header or ""
        leaks = "tomcat" in header.lower() or "coyote" in header.lower()
        verdict = "FAIL" if leaks else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=f"curl -sSI http://{ctx.host}:{target_port(ctx)}/",
            out=f"Server: {header or '<empty>'}",
            err="",
            parsed={"server_header": header, "leaks_tomcat": leaks},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ServerHeaderDisclosureCheck()
register_check(CHECK)
