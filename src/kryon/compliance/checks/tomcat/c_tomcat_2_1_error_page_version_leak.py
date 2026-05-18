"""TOMCAT-2.1 — Error pages no disclose exact Tomcat version.

Tomcat's default error page includes `<title>Apache Tomcat/X.Y.Z -
Error report</title>` in the HTML. That's a CWE-200 information leak
that lets attackers cross-reference the version against public CVE
databases without authentication.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.tomcat._common import fingerprint, make_result, na_result, target_port
from kryon.compliance.runner import register_check


class _ErrorPageVersionLeakCheck:
    control_id = "TOMCAT-2.1"
    control_title = "Tomcat error pages do not disclose exact version"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Configure custom error pages in $CATALINA_BASE/conf/web.xml or\n"
        "per-webapp WEB-INF/web.xml:\n"
        "  <error-page>\n"
        "    <error-code>404</error-code>\n"
        "    <location>/errors/404.html</location>\n"
        "  </error-page>\n"
        "  <error-page>\n"
        "    <error-code>500</error-code>\n"
        "    <location>/errors/500.html</location>\n"
        "  </error-page>\n"
        "Also remove the Server header value via Connector attribute:\n"
        '  <Connector port="8080" server=" " ... />\n'
        "Combined effect: scanners cannot fingerprint the exact Tomcat\n"
        "version, raising the cost of targeted CVE exploitation."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        fp = fingerprint(ctx.host, target_port(ctx))

        if not fp.is_tomcat:
            return na_result(self, ctx=ctx, reason="not an Apache Tomcat host", t0=t0)

        verdict = "FAIL" if fp.error_page_leaks_version else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=f"GET http://{ctx.host}:{target_port(ctx)}/<random-404>",
            out=(
                f"Error page leaked: Apache Tomcat/{fp.version}"
                if fp.error_page_leaks_version
                else "Error page does not leak version"
            ),
            err="",
            parsed={"error_page_leaks_version": fp.error_page_leaks_version, "version": fp.version},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ErrorPageVersionLeakCheck()
register_check(CHECK)
