"""TOMCAT-2.4 — /examples/ no expuesto en producción.

Tomcat ships con `examples` webapp que incluye servlets de demostración
con XSS conocido (e.g. `/examples/jsp/snp/snoop.jsp`) y endpoints
WebSocket de prueba. Es una pool de hallazgos para cualquier scanner
automatizado.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.tomcat._common import fingerprint, make_result, na_result, target_port
from kryon.compliance.runner import register_check


class _ExamplesAccessibleCheck:
    control_id = "TOMCAT-2.4"
    control_title = "Tomcat examples webapp (/examples/) not deployed in production"
    section = "2"
    severity = "LOW"
    remediation_static = (
        "Undeploy the examples webapp:\n"
        "  rm -rf $CATALINA_BASE/webapps/examples\n"
        "The default examples include known-vulnerable servlets that\n"
        "scanners flag (snoop.jsp, calendar.jsp, etc.). Even when those\n"
        "specific issues are non-exploitable in modern Tomcat, the noise\n"
        "they generate is itself a problem for the security team.\n"
        "Same rule of thumb: production = production webapps only."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        fp = fingerprint(ctx.host, target_port(ctx))

        if not fp.is_tomcat:
            return na_result(self, ctx=ctx, reason="not an Apache Tomcat host", t0=t0)

        status = fp.examples_status
        verdict = "FAIL" if status == 200 else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=f"GET http://{ctx.host}:{target_port(ctx)}/examples/",
            out=f"HTTP {status}",
            err="",
            parsed={"examples_status": status},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ExamplesAccessibleCheck()
register_check(CHECK)
