"""TOMCAT-1.1 — Apache Tomcat major version is supported (not EOL).

End-of-life table (as of 2026-05):
  - Tomcat 6  EOL Dec 2016 → DEAD
  - Tomcat 7  EOL Mar 2021 → DEAD
  - Tomcat 8  EOL Mar 2024 → DEAD (8.5.x also out)
  - Tomcat 9  active LTS  (EOL ~Q4 2027)
  - Tomcat 10 active     (LTS for Jakarta EE 9+)
  - Tomcat 11 current

Hosts on EOL Tomcat are exposed to dozens of public CVEs without
vendor patches. A tested host (Tomcat 7.0.34, March 2013) was the
trigger case for this check.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.tomcat._common import fingerprint, make_result, na_result, target_port
from kryon.compliance.runner import register_check

_MIN_SUPPORTED_MAJOR = 9
_DEAD_MAJORS = {3, 4, 5, 6, 7, 8}


class _VersionEolCheck:
    control_id = "TOMCAT-1.1"
    control_title = "Apache Tomcat major version is supported (not EOL)"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Migrate to a supported Tomcat LTS:\n"
        "  - Tomcat 9.x (EOL ~Q4 2027) for legacy Java EE 8 apps.\n"
        "  - Tomcat 10.x or 11.x for Jakarta EE 9+ apps.\n"
        "Tomcat 7 (EOL March 2021) and 8 (EOL March 2024) receive zero\n"
        "security updates. Public exploits exist for Ghostcat (CVE-2020-1938),\n"
        "CVE-2017-12617 PUT RCE, CVE-2016-8735 JMX RCE, and others.\n"
        "Migration steps:\n"
        "  1. Test the webapp against Tomcat 9 in staging.\n"
        "  2. Update server.xml for new connector defaults.\n"
        "  3. Switch JDK to a supported version (Tomcat 10+ needs Java 11+,\n"
        "     Tomcat 11 needs Java 17+).\n"
        "  4. Apply harden-tomcat script (CIS Apache Tomcat Benchmark)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        fp = fingerprint(ctx.host, target_port(ctx))

        if not fp.is_tomcat:
            return na_result(self, ctx=ctx, reason="not an Apache Tomcat host", t0=t0)

        if not fp.version:
            return make_result(
                check=self,
                verdict="ERROR",
                cmd="tomcat_recon",
                out=fp.server_header,
                err="",
                parsed={"reason": "Tomcat detected but version could not be extracted from error page or banner"},
                t0=t0,
                ctx=ctx,
            )

        major = int(fp.version.split(".")[0])
        if major in _DEAD_MAJORS or major < _MIN_SUPPORTED_MAJOR:
            verdict, parsed = "FAIL", {"version": fp.version, "major": major, "min_supported": _MIN_SUPPORTED_MAJOR}
        else:
            verdict, parsed = "PASS", {"version": fp.version, "major": major}
        return make_result(
            check=self,
            verdict=verdict,
            cmd=f"tomcat_recon http://{ctx.host}:{target_port(ctx)}",
            out=f"Apache Tomcat/{fp.version}",
            err="",
            parsed=parsed,
            t0=t0,
            ctx=ctx,
        )


CHECK = _VersionEolCheck()
register_check(CHECK)
