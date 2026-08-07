"""TOMCAT-1.2 — AJP/1.3 connector (TCP 8009) not exposed (Ghostcat).

CVE-2020-1938 "Ghostcat" — an unauthenticated remote attacker reaches
the AJP connector and uses crafted AJP requests to read or include
arbitrary files inside the webapp directory (web.xml, db.properties,
admin credentials, etc.). On Tomcat installs that allow JSP file
uploads (e.g. a logging webapp dropping files into /var/tmp), this
escalates to remote code execution.

Tomcat 7/8/9 patched the AJP secret default behaviour in
7.0.100 / 8.5.51 / 9.0.31 (2020-02-24). Earlier versions are
vulnerable as long as AJP is bound to a network-reachable interface.

Mitigation: bind AJP to localhost OR set a strong secret OR — best —
disable the AJP connector entirely if you don't use it (most installs
behind nginx/Apache reverse-proxy via HTTP).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.tomcat._common import fingerprint, make_result, na_result, target_port
from kryon.compliance.runner import register_check


class _AjpGhostcatCheck:
    control_id = "TOMCAT-1.2"
    control_title = "AJP/1.3 connector (TCP 8009) not exposed (CVE-2020-1938 Ghostcat)"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Edit /etc/tomcat?/server.xml or $CATALINA_BASE/conf/server.xml:\n"
        "Option A — disable AJP entirely (preferred):\n"
        '  <!-- <Connector port="8009" protocol="AJP/1.3" ... /> -->\n'
        "Option B — bind to localhost only:\n"
        '  <Connector port="8009" protocol="AJP/1.3"\n'
        '             address="127.0.0.1"\n'
        '             secretRequired="true"\n'
        '             secret="<STRONG_RANDOM_64>" />\n'
        "Option C — block TCP 8009 at the host firewall:\n"
        "  ufw deny 8009/tcp   (or iptables/firewalld equivalent)\n"
        "After applying, validate from a remote box:\n"
        "  nc -zv <tomcat-ip> 8009    # must report 'refused' or timeout\n"
        "References: CVE-2020-1938, Apache advisory 2020-02-24."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        fp = fingerprint(ctx.host, target_port(ctx))

        if not fp.is_tomcat:
            return na_result(self, ctx=ctx, reason="not an Apache Tomcat host", t0=t0)

        verdict = "FAIL" if fp.ajp_open else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=f"tcp_probe {ctx.host}:8009",
            out=f"AJP 8009: {'OPEN' if fp.ajp_open else 'closed/filtered'}",
            err="",
            parsed={"ajp_open": fp.ajp_open, "version": fp.version},
            t0=t0,
            ctx=ctx,
        )


CHECK = _AjpGhostcatCheck()
register_check(CHECK)
