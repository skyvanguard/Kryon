"""FGT-2.2 — SNMP communities are not trivial (public/private/empty).

SNMP v1/v2c uses a clear-text shared community string. Any interface that
exposes `snmp` in allowaccess + a trivial community = full read of FortiOS
config trees. Standard ops mistake.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_TRIVIAL_COMMUNITIES = {"public", "private", "fortinet", "snmp", "community", ""}


class _SnmpCommunityCheck:
    control_id = "FGT-2.2"
    control_title = "SNMP v1/v2c communities are not trivial"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "Either disable SNMP entirely or move to v3 with auth+priv:\n"
        "  config system snmp sysinfo\n"
        "    set status disable        # if not actually used\n"
        "  end\n"
        "If SNMP is required, prefer v3:\n"
        "  config system snmp user\n"
        "    edit \"monitor\"\n"
        "      set security-level auth-priv\n"
        "      set auth-proto sha256\n"
        "      set auth-pwd <STRONG>\n"
        "      set priv-proto aes256\n"
        "      set priv-pwd <STRONG>\n"
        "    next\n"
        "  end\n"
        "  config system snmp community\n"
        "    delete <id>      # remove v1/v2c communities\n"
        "  end"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show system snmp community"
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
                evidence_parsed={"reason": "could not read snmp config"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Empty output (no `edit` blocks) means no v1/v2c communities defined.
        if "edit" not in out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="PASS",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={
                    "communities_defined": 0,
                    "issues": [],
                },
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        issues: list[str] = []
        community_names: list[str] = []
        for m in re.finditer(r'edit\s+\d+\s*(.*?)\bnext\b', out, re.S):
            body = m.group(1)
            name_match = re.search(r'set\s+name\s+"([^"]*)"', body)
            status_match = re.search(r"set\s+status\s+(\S+)", body)
            if not name_match:
                continue
            name = name_match.group(1)
            community_names.append(name)
            status = status_match.group(1) if status_match else "enable"
            if status == "disable":
                continue
            if name.lower() in _TRIVIAL_COMMUNITIES:
                issues.append(f"SNMP community '{name}' is trivial / default")

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
                "communities_defined": len(community_names),
                "community_names": sorted(community_names),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SnmpCommunityCheck()
register_check(CHECK)
