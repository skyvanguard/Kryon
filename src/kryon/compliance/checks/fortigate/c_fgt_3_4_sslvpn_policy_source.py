"""FGT-3.4 — SSL VPN firewall policy uses scoped source, not `all`.

The firewall policy mapping `ssl.root` (the SSL VPN tunnel pseudo-interface)
to internal subnets must NOT use `set srcaddr all` — that allows any VPN
user to reach any internal resource. Zero Trust requires scoping.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _SslVpnPolicySourceCheck:
    control_id = "FGT-3.4"
    control_title = "SSL VPN firewall policy uses scoped source, not 'all'"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Replace `set srcaddr all` on SSL VPN policies with scoped objects:\n"
        "  config firewall address\n"
        "    edit \"sslvpn_pool\"\n"
        "      set subnet 10.212.134.0 255.255.255.0\n"
        "    next\n"
        "  end\n"
        "  config firewall policy\n"
        "    edit <id>\n"
        "      set srcintf \"ssl.root\"\n"
        "      set srcaddr \"sslvpn_pool\"           # NOT all\n"
        "      set dstaddr \"corp_internal_subnet\"\n"
        "      set service \"RDP\" \"HTTPS\"           # NOT ALL\n"
        "      set groups \"sslvpn_users\"\n"
        "    next\n"
        "  end"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show firewall policy"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read firewall policies"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        bad_policies: list[dict[str, str]] = []
        sslvpn_policy_count = 0
        for m in re.finditer(r'edit\s+(\d+)\s*(.*?)\bnext\b', out, re.S):
            pol_id = m.group(1)
            body = m.group(2)
            srcintf = re.search(r'set\s+srcintf\s+"([^"]+)"', body)
            if not srcintf or "ssl.root" not in srcintf.group(1).lower():
                continue
            sslvpn_policy_count += 1
            srcaddr = re.search(r'set\s+srcaddr\s+(.+)', body)
            service = re.search(r'set\s+service\s+(.+)', body)
            srcaddr_val = (srcaddr.group(1).strip() if srcaddr else "(default-all)")
            service_val = (service.group(1).strip() if service else "(default-ALL)")
            uses_all_src = '"all"' in srcaddr_val.lower() or srcaddr_val.lower() == "all"
            uses_all_svc = '"all"' in service_val.lower() or service_val.lower() == "all"
            if uses_all_src or uses_all_svc:
                bad_policies.append({
                    "policy_id": pol_id,
                    "srcaddr": srcaddr_val,
                    "service": service_val,
                })

        issues: list[str] = []
        for bp in bad_policies:
            issues.append(
                f"SSL VPN policy {bp['policy_id']}: "
                f"srcaddr={bp['srcaddr']}, service={bp['service']}"
            )

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:3072],
            evidence_stderr=err[:512],
            evidence_parsed={
                "sslvpn_policy_count": sslvpn_policy_count,
                "policies_with_all_scope": [b["policy_id"] for b in bad_policies],
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SslVpnPolicySourceCheck()
register_check(CHECK)
