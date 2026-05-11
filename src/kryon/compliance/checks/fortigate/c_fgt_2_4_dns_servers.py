"""FGT-2.4 — DNS resolvers are internal / vetted, not arbitrary public.

Public resolvers (8.8.8.8, 1.1.1.1) leak query metadata about internal
hostnames being looked up by the FortiGate's own services (FortiGuard
update checks, syslog DNS resolution, etc.). For corporate scope, DNS
should be the corporate resolver (or FortiGuard, accepted vendor exception).

This is LOW severity but worth surfacing for banking/regulated audits.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# Allowed public DNS that FortiGate uses by design (FortiGuard servers).
_VENDOR_DNS = {
    "208.91.112.53",
    "208.91.112.52",  # FortiGuard
    "96.45.45.45",
    "96.45.46.46",  # FortiGuard
}
_ARBITRARY_PUBLIC_DNS = {
    "8.8.8.8",
    "8.8.4.4",  # Google
    "1.1.1.1",
    "1.0.0.1",  # Cloudflare
    "9.9.9.9",
    "149.112.112.112",  # Quad9
    "208.67.222.222",
    "208.67.220.220",  # OpenDNS
}


class _DnsServersCheck:
    control_id = "FGT-2.4"
    control_title = "DNS resolvers are internal/vendor, not arbitrary public"
    section = "2"
    severity = "LOW"
    remediation_static = (
        "Use the corporate resolver:\n"
        "  config system dns\n"
        "    set primary <CORPORATE_DNS_PRIMARY>\n"
        "    set secondary <CORPORATE_DNS_SECONDARY>\n"
        "  end\n"
        "FortiGuard's own servers (208.91.112.53 etc.) are an accepted\n"
        "exception. Public resolvers (8.8.8.8 etc.) leak metadata about\n"
        "what the FortiGate is resolving."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show system dns"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read dns config"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        primary = re.search(r"^\s*set\s+primary\s+(\S+)", out, re.M)
        secondary = re.search(r"^\s*set\s+secondary\s+(\S+)", out, re.M)
        ips = [m.group(1).strip() for m in (primary, secondary) if m]

        issues: list[str] = []
        for ip in ips:
            if ip in _ARBITRARY_PUBLIC_DNS:
                issues.append(f"DNS resolver {ip} is an arbitrary public service")

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:512],
            evidence_parsed={
                "primary": primary.group(1) if primary else "",
                "secondary": secondary.group(1) if secondary else "",
                "vendor_dns_allowed": sorted(_VENDOR_DNS),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _DnsServersCheck()
register_check(CHECK)
