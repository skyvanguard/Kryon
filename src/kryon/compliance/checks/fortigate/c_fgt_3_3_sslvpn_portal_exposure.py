"""FGT-3.3 — SSL VPN portal not on default port AND/OR geo-restricted.

The default SSL VPN port (10443 or 443) on the WAN interface is the
single most-attacked surface on FortiGate. Even with patched FortiOS:
  - Move to a non-default port (light obfuscation, reduces opportunistic scan)
  - Apply geo-blocking on the VPN policy (`config firewall policy` with
    geographic source restrictions) — most clients have a known country list
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_DEFAULT_PORTS = {"443", "10443"}


class _SslVpnPortalExposureCheck:
    control_id = "FGT-3.3"
    control_title = "SSL VPN portal not on default port; geo-restriction recommended"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Move SSL VPN to a non-default port:\n"
        "  config vpn ssl settings\n"
        "    set port 22443             # or any 4-5 digit non-standard\n"
        "  end\n"
        "Add geographic source restriction to the SSL VPN policy:\n"
        "  config firewall policy\n"
        "    edit <policy_id_for_sslvpn>\n"
        "      set srcaddr GEO_PY GEO_ALLOWLIST     # named geo objects\n"
        "    next\n"
        "  end\n"
        "Geo-block alone is not security; pair with MFA (FGT-3.2)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show full-configuration vpn ssl settings"
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
                evidence_parsed={"reason": "could not read sslvpn settings"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        port_match = re.search(r"^\s*set\s+port\s+(\d+)", out, re.M)
        port = port_match.group(1) if port_match else "10443"  # FortiOS default

        # Source interface / source addresses for the SSL VPN listener
        src_intf = re.findall(r'set\s+source-interface\s+(.+)', out)
        src_addr = re.findall(r'set\s+source-address\s+(.+)', out)
        src_addr_neg = re.findall(r'set\s+source-address-negate\s+(\S+)', out)

        issues: list[str] = []
        if port in _DEFAULT_PORTS:
            issues.append(f"SSL VPN listening on default port {port}")
        if not src_addr:
            issues.append("SSL VPN has no source-address allowlist (any source IP allowed)")

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed={
                "port": port,
                "default_ports_set": sorted(_DEFAULT_PORTS),
                "source_interface": src_intf,
                "source_address": src_addr,
                "source_address_negate": src_addr_neg,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SslVpnPortalExposureCheck()
register_check(CHECK)
