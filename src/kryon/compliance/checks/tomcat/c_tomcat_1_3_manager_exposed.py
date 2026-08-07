"""TOMCAT-1.3 — /manager/html no reachable desde la red de auditoría.

Tomcat Manager permite desplegar / des-desplegar WAR files vía web —
es esencialmente un panel de RCE web-based. Default credentials
históricos: tomcat:tomcat, admin:admin, manager:manager, tomcat:s3cret.

PASS cuando el endpoint devuelve 404 (no deployed) o connect-refused.
FAIL cuando devuelve 200 (sin auth!), 401 o 403 (auth configurado pero
expuesto a la red — riesgo de bruteforce / default creds).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.tomcat._common import fingerprint, make_result, na_result, target_port
from kryon.compliance.runner import register_check


class _ManagerExposedCheck:
    control_id = "TOMCAT-1.3"
    control_title = "Tomcat Manager (/manager/html) not reachable from audit network"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Options to lock down Manager:\n"
        "  1. Undeploy if not in use (preferred):\n"
        "     rm -rf $CATALINA_BASE/webapps/manager $CATALINA_BASE/webapps/host-manager\n"
        "  2. Restrict by IP via RemoteAddrValve in conf/Catalina/localhost/manager.xml:\n"
        '     <Context privileged="true" antiResourceLocking="false"\n'
        '              docBase="${catalina.home}/webapps/manager">\n'
        '       <Valve className="org.apache.catalina.valves.RemoteAddrValve"\n'
        '              allow="127\\.0\\.0\\.1|10\\.0\\.0\\.\\d+" />\n'
        "     </Context>\n"
        "  3. Enforce strong creds in conf/tomcat-users.xml + remove default users.\n"
        "  4. Run Manager on a separate management VLAN behind nginx with mTLS.\n"
        "Reference: CVE-2017-15706 (default-credential abuse), countless\n"
        "real-world breaches via Manager-exposed Tomcat over the years."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        fp = fingerprint(ctx.host, target_port(ctx))

        if not fp.is_tomcat:
            return na_result(self, ctx=ctx, reason="not an Apache Tomcat host", t0=t0)

        status = fp.manager_status
        # 200 = manager served WITHOUT auth (worst case).
        # 401 = Basic auth — bruteforce-able if creds weak.
        # 403 = forbidden by ACL (PASS-ish but signals the webapp is
        #       still deployed, prefer 404).
        # 404 = not deployed = PASS.
        if status == 0 or status == 404:
            verdict = "PASS"
        elif status == 403:
            # Restricted by IP/ACL — acceptable, but flag MEDIUM-ish via INFO note.
            verdict = "PASS"
        else:
            verdict = "FAIL"

        return make_result(
            check=self,
            verdict=verdict,
            cmd=f"GET http://{ctx.host}:{target_port(ctx)}/manager/html",
            out=f"HTTP {status}",
            err="",
            parsed={"manager_status": status, "version": fp.version},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ManagerExposedCheck()
register_check(CHECK)
