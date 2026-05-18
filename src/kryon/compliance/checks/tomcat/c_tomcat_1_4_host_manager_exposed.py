"""TOMCAT-1.4 — /host-manager/html no reachable desde la red de auditoría.

Host Manager es el hermano peligroso de Manager: permite crear /
eliminar virtual hosts en runtime. Default install: misma webapp
group/role que Manager. Mismo riesgo de bruteforce y default creds.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.tomcat._common import fingerprint, make_result, na_result, target_port
from kryon.compliance.runner import register_check


class _HostManagerExposedCheck:
    control_id = "TOMCAT-1.4"
    control_title = "Tomcat Host Manager (/host-manager/html) not reachable from audit network"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Same playbook as Manager (TOMCAT-1.3):\n"
        "  rm -rf $CATALINA_BASE/webapps/host-manager\n"
        "Or restrict by IP via RemoteAddrValve in\n"
        "  conf/Catalina/localhost/host-manager.xml\n"
        "Most installs don't use Host Manager at all — remove the webapp\n"
        "directory entirely instead of trying to harden it."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        fp = fingerprint(ctx.host, target_port(ctx))

        if not fp.is_tomcat:
            return na_result(self, ctx=ctx, reason="not an Apache Tomcat host", t0=t0)

        status = fp.host_manager_status
        if status in (0, 404, 403):
            verdict = "PASS"
        else:
            verdict = "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=f"GET http://{ctx.host}:{target_port(ctx)}/host-manager/html",
            out=f"HTTP {status}",
            err="",
            parsed={"host_manager_status": status},
            t0=t0,
            ctx=ctx,
        )


CHECK = _HostManagerExposedCheck()
register_check(CHECK)
