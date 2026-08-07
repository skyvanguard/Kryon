"""VOIP-2.3 — AMI/ARI not bound to public interface.

If `manager.conf` `bindaddr=0.0.0.0` (default) AND the host has a
public interface, AMI is reachable from the internet — a critical
exposure once you combine it with VOIP-1.2 (default secret).
This check parses `bindaddr` from manager.conf and lists the host's
network interfaces (`ip -4 -o addr show`) to flag when AMI listens on
a non-private address.
"""

from __future__ import annotations

import ipaddress
import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _is_public_ip(addr: str) -> bool:
    """True when `addr` is a routable, non-RFC-1918 IPv4."""
    try:
        ip = ipaddress.ip_address(addr)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


class _AmiWanExposureCheck:
    control_id = "VOIP-2.3"
    control_title = "AMI/ARI not bound to a public interface"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "In /etc/asterisk/manager.conf `[general]`:\n"
        "  enabled=yes\n"
        "  bindaddr=127.0.0.1     ; or the internal management IP\n"
        "Add per-user ACL:\n"
        "  permit=127.0.0.1/255.255.255.255\n"
        "  deny=0.0.0.0/0.0.0.0\n"
        "Block port 5038/tcp at the perimeter firewall."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "echo '--manager.conf--' && cat /etc/asterisk/manager.conf 2>/dev/null; "
            "echo '--interfaces--' && ip -4 -o addr show 2>/dev/null"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if rc != 0 and not out:
            return _err(self, cmd, out, err, t0, ctx, "could not collect bindaddr / interfaces")

        manager_section = out.split("--interfaces--")[0] if "--interfaces--" in out else out
        iface_section = out.split("--interfaces--")[1] if "--interfaces--" in out else ""

        bind_match = re.search(r"^\s*bindaddr\s*=\s*([\d.]+)", manager_section, re.MULTILINE)
        bindaddr = bind_match.group(1) if bind_match else "0.0.0.0 (default)"

        # Pull v4 addresses from `ip -o addr show`
        host_ips = re.findall(r"inet\s+([\d.]+)/", iface_section)
        public_ips = sorted({ip for ip in host_ips if _is_public_ip(ip)})

        verdict = "PASS"
        if bindaddr.startswith("0.0.0.0") and public_ips:
            verdict = "FAIL"
        elif bindaddr in host_ips and _is_public_ip(bindaddr):
            verdict = "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:256],
            evidence_parsed={
                "bindaddr": bindaddr,
                "host_public_ips": public_ips,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


def _err(check, cmd, out, err, t0, ctx, reason):
    return CheckResult(
        control_id=check.control_id,
        control_title=check.control_title,
        section=check.section,
        verdict="ERROR",
        evidence_command=cmd,
        evidence_stdout=out[:512],
        evidence_stderr=err[:512],
        evidence_parsed={"reason": reason},
        remediation_static=check.remediation_static,
        severity=check.severity,
        duration_ms=int((time.time() - t0) * 1000),
        host=ctx.host,
        run_id="",
    )


CHECK = _AmiWanExposureCheck()
register_check(CHECK)
