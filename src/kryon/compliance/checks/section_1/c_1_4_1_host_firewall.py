"""PCI-DSS v4 control 1.4.1 — Network security controls between trusted and
untrusted networks (host-based firewall).

Verifies an active host firewall with rules. Probes, in order, whichever
tooling responds:
  - ufw:       `ufw status`          → "Status: active"
  - firewalld: `firewall-cmd --state`→ "running"
  - nftables:  `nft list ruleset`    → a non-empty ruleset with a chain
  - iptables:  `iptables -S`         → a default DROP policy or explicit rules

PASS if any firewall is active. FAIL if every probe runs but none is active
(i.e. no host firewall protecting the box). ERROR if the host is unreachable.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _ufw_active(ctx: CheckContext) -> tuple[bool, bool]:
    """Returns (ran, active)."""
    out, _, rc = run_cmd(ctx, ["ufw", "status"], timeout_s=4)
    if rc != 0 and not out.strip():
        return False, False
    return True, "status: active" in out.lower()


def _firewalld_active(ctx: CheckContext) -> tuple[bool, bool]:
    out, _, rc = run_cmd(ctx, ["firewall-cmd", "--state"], timeout_s=4)
    if rc != 0 and not out.strip():
        return False, False
    return True, "running" in out.lower()


def _nft_active(ctx: CheckContext) -> tuple[bool, bool]:
    out, _, rc = run_cmd(ctx, ["nft", "list", "ruleset"], timeout_s=4)
    if rc != 0 and not out.strip():
        return False, False
    # A configured nftables has at least one chain with a policy/rule.
    return True, "chain" in out.lower()


def _iptables_active(ctx: CheckContext) -> tuple[bool, bool]:
    out, _, rc = run_cmd(ctx, ["iptables", "-S"], timeout_s=4)
    if rc != 0 and not out.strip():
        return False, False
    low = out.lower()
    # Default DROP policy on INPUT, or explicit non-trivial rules beyond the
    # 3 default `-P ... ACCEPT` lines.
    has_drop_policy = "-p input drop" in low or "-p forward drop" in low
    rule_lines = [ln for ln in out.splitlines() if ln.startswith("-A")]
    return True, has_drop_policy or len(rule_lines) > 0


class _C141Check:
    control_id = "1.4.1"
    control_title = "Host-based firewall / network security controls"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Enable a host firewall with a default-deny inbound policy. "
        "ufw: `ufw default deny incoming && ufw enable`. "
        "nftables/firewalld equivalents. Allow only the ports required for the "
        "service's role (PCI-DSS 1.4.1)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        probes = {
            "ufw": _ufw_active(ctx),
            "firewalld": _firewalld_active(ctx),
            "nftables": _nft_active(ctx),
            "iptables": _iptables_active(ctx),
        }
        active = {name: act for name, (ran, act) in probes.items() if act}
        any_ran = any(ran for ran, _ in probes.values())

        if not any_ran:
            verdict = "ERROR"
        elif active:
            verdict = "PASS"
        else:
            verdict = "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="ufw status ; firewall-cmd --state ; nft list ruleset ; iptables -S",
            evidence_stdout=f"active_firewalls={sorted(active)}"[:4096],
            evidence_stderr="",
            evidence_parsed={
                "active_firewalls": sorted(active),
                "probed": {name: {"ran": ran, "active": act} for name, (ran, act) in probes.items()},
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C141Check()
register_check(CHECK)
