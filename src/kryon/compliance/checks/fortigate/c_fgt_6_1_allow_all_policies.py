"""FGT-6.1 — No overly-permissive "allow-all" firewall policies.

`config firewall policy` — a policy with action=accept, srcaddr=all,
dstaddr=all AND service=ALL is an any/any/any allow rule that defeats the
firewall's purpose. This is the #1 finding in FortiGate audits and is
absent from the admin/VPN/logging checks (1.x–5.x).

FAIL on any accept policy that is all-of: srcaddr includes "all",
dstaddr includes "all", and service includes "ALL". ERROR if the policy
table can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_POLICY_RE = re.compile(r"edit\s+(\d+)\s*(.*?)\bnext\b", re.S)


def _set_tokens(body: str, key: str) -> set[str]:
    m = re.search(rf"^\s*set\s+{re.escape(key)}\s+(.+)$", body, re.M)
    if not m:
        return set()
    # values are space-separated, optionally quoted: "all" "LAN" -> {all, LAN}
    return {t.strip('"') for t in m.group(1).split()}


class _AllowAllPoliciesCheck:
    control_id = "FGT-6.1"
    control_title = "No overly-permissive allow-all firewall policies"
    section = "6"
    severity = "CRITICAL"
    remediation_static = (
        "Replace any/any/any accept rules with least-privilege policies:\n"
        "  config firewall policy\n"
        "    edit <id>\n"
        "      set srcaddr <specific-subnets>   # NOT all\n"
        "      set dstaddr <specific-hosts>      # NOT all\n"
        "      set service <specific-services>   # NOT ALL\n"
        "    next\n"
        "  end\n"
        "Segment by need-to-communicate; a broad accept rule defeats the firewall."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show firewall policy"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)

        if rc != 0 and not out:
            return self._result("ERROR", cmd, out, err, {"reason": "could not read firewall policy table"}, t0, ctx)

        allow_all: list[dict] = []
        total = 0
        for m in _POLICY_RE.finditer(out):
            pid, body = m.group(1), m.group(2)
            total += 1
            action = _set_tokens(body, "action")
            # FortiOS default action is deny; only "set action accept" opens it.
            if "accept" not in action:
                continue
            src = _set_tokens(body, "srcaddr")
            dst = _set_tokens(body, "dstaddr")
            svc = _set_tokens(body, "service")
            if "all" in src and "all" in dst and "ALL" in svc:
                name_m = re.search(r'^\s*set\s+name\s+"([^"]*)"', body, re.M)
                allow_all.append({"id": pid, "name": name_m.group(1) if name_m else ""})

        issues = [f"policy {p['id']} '{p['name']}' is any/any/ALL accept" for p in allow_all]
        verdict = "PASS" if not issues else "FAIL"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"policy_count": total, "allow_all_policies": [p["id"] for p in allow_all], "issues": sorted(issues)},
            t0,
            ctx,
        )

    def _result(self, verdict, cmd, out, err, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:3072],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AllowAllPoliciesCheck()
register_check(CHECK)
