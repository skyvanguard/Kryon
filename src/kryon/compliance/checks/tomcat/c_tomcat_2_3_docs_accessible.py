"""TOMCAT-2.3 — /docs/ no expuesto en producción.

La webapp `docs` ships con la documentación HTML de Tomcat. Sin riesgo
crítico directo, pero indica que el operador desplegó el ejemplo default
sin filtrar — sugiere otros webapps de ejemplo activos. Info disclosure
+ surface area unnecessary.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.tomcat._common import fingerprint, make_result, na_result, target_port
from kryon.compliance.runner import register_check


class _DocsAccessibleCheck:
    control_id = "TOMCAT-2.3"
    control_title = "Tomcat documentation webapp (/docs/) not deployed in production"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Undeploy the docs webapp:\n"
        "  rm -rf $CATALINA_BASE/webapps/docs\n"
        "Or restrict via Context valve in conf/Catalina/localhost/docs.xml.\n"
        "Same logic applies to ROOT (if you don't have an app at /).\n"
        "CIS Apache Tomcat 9 Benchmark §7.1 recommends removing all\n"
        "default webapps (docs / examples / manager / host-manager) in\n"
        "production unless explicitly required."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        fp = fingerprint(ctx.host, target_port(ctx))

        if not fp.is_tomcat:
            return na_result(self, ctx=ctx, reason="not an Apache Tomcat host", t0=t0)

        status = fp.docs_status
        verdict = "FAIL" if status == 200 else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=f"GET http://{ctx.host}:{target_port(ctx)}/docs/",
            out=f"HTTP {status}",
            err="",
            parsed={"docs_status": status},
            t0=t0,
            ctx=ctx,
        )


CHECK = _DocsAccessibleCheck()
register_check(CHECK)
