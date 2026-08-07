"""FGT-6.3 — Accept firewall policies apply UTM security profiles.

Defense-in-depth: an accept policy should apply at least one security
profile — av-profile, ips-sensor, webfilter-profile, application-list,
dnsfilter-profile or ssl-ssh-profile. A permit rule with no inspection is
just a router ACL.

FAIL lists accept policies with NO UTM profile at all (the operator
documents the justified exceptions — e.g. internal-only flows). MEDIUM
severity since some flows legitimately need no inspection.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_POLICY_RE = re.compile(r"edit\s+(\d+)\s*(.*?)\bnext\b", re.S)
_UTM_KEYS = (
    "av-profile",
    "ips-sensor",
    "webfilter-profile",
    "application-list",
    "dnsfilter-profile",
    "ssl-ssh-profile",
    "file-filter-profile",
)


def _has_key(body: str, key: str) -> bool:
    return bool(re.search(rf"^\s*set\s+{re.escape(key)}\s+\S", body, re.M))


def _action(body: str) -> set[str]:
    m = re.search(r"^\s*set\s+action\s+(.+)$", body, re.M)
    return {t.strip('"') for t in m.group(1).split()} if m else set()


class _PolicyUtmCheck:
    control_id = "FGT-6.3"
    control_title = "Accept firewall policies apply UTM security profiles"
    section = "6"
    severity = "MEDIUM"
    remediation_static = (
        "Apply security profiles to accept policies that carry untrusted traffic:\n"
        "  config firewall policy\n"
        "    edit <id>\n"
        "      set utm-status enable\n"
        "      set av-profile <p>  set ips-sensor <p>  set webfilter-profile <p>\n"
        "      set ssl-ssh-profile <p>\n"
        "    next\n"
        "  end\n"
        "Document any policy that legitimately needs no inspection."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show firewall policy"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out:
            return self._result("ERROR", cmd, out, err, {"reason": "could not read firewall policy table"}, t0, ctx)

        no_utm: list[str] = []
        accept_total = 0
        for m in _POLICY_RE.finditer(out):
            pid, body = m.group(1), m.group(2)
            if "accept" not in _action(body):
                continue
            accept_total += 1
            if not any(_has_key(body, k) for k in _UTM_KEYS):
                no_utm.append(pid)

        issues = [f"accept policy {pid} applies no UTM profile" for pid in no_utm]
        verdict = "PASS" if not issues else "FAIL"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"accept_policy_count": accept_total, "policies_without_utm": no_utm, "issues": sorted(issues)},
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


CHECK = _PolicyUtmCheck()
register_check(CHECK)
