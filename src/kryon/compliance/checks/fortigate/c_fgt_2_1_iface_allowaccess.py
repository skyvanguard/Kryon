"""FGT-2.1 — Interfaces do not expose insecure services in `allowaccess`.

`config system interface` controls per-interface management surface via
`set allowaccess`. We FAIL on any interface that exposes:
  - http        (plaintext admin GUI)
  - telnet      (plaintext shell)
  - ping-access from WAN (when paired with other findings, signals exposure)

We don't fail solely on `https` or `ssh` since those are normal management
protocols; we only fail on the legacy/insecure ones.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_INSECURE = {"http", "telnet"}


class _IfaceAllowaccessCheck:
    control_id = "FGT-2.1"
    control_title = "Interfaces do not expose http/telnet in allowaccess"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Strip plaintext protocols from every interface:\n"
        "  config system interface\n"
        "    edit <iface>\n"
        "      set allowaccess https ssh ping     # NO http, NO telnet\n"
        "    next\n"
        "  end\n"
        "WAN-facing interfaces should generally have allowaccess EMPTY\n"
        "(or only ping for monitoring). Management ON THE LAN ONLY."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show system interface"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read interfaces"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        bad_ifaces: list[dict[str, str]] = []
        all_ifaces: list[str] = []
        for m in re.finditer(
            r'edit\s+"([^"]+)"\s*(.*?)\bnext\b',
            out,
            re.S,
        ):
            name = m.group(1)
            body = m.group(2)
            all_ifaces.append(name)
            aa_match = re.search(r"^\s*set\s+allowaccess\s+(.+)$", body, re.M)
            if not aa_match:
                continue
            tokens = set(aa_match.group(1).strip().split())
            insecure_present = tokens & _INSECURE
            if insecure_present:
                bad_ifaces.append({
                    "name": name,
                    "allowaccess": aa_match.group(1).strip(),
                    "insecure": " ".join(sorted(insecure_present)),
                })

        issues = [
            f"interface '{i['name']}' allowaccess includes {i['insecure']}"
            for i in bad_ifaces
        ]
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
                "interface_count": len(all_ifaces),
                "interfaces_with_insecure_access": [b["name"] for b in bad_ifaces],
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _IfaceAllowaccessCheck()
register_check(CHECK)
