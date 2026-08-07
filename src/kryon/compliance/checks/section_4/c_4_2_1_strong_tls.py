"""PCI-DSS v4 control 4.2.1 — Strong cryptography and security protocols for
PAN transmission over open, public networks.

For each exposed TLS service, verifies that weak protocols are NOT accepted:
SSLv3, TLS 1.0 and TLS 1.1 must be disabled (TLS 1.2+ required). Probes each
weak protocol with `openssl s_client`; a successful handshake on any of them
is a FAIL.

N/A when no TLS port is exposed. ERROR if the host name is unsafe to shell out.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_TLS_PORTS = {443, 8443, 993, 995, 465, 636, 990}
# openssl prints "New, TLSv1.1, Cipher is XXXX" on a successful handshake.
_HANDSHAKE_RE = re.compile(r"New,\s*(SSLv3|TLSv1|TLSv1\.1),\s*Cipher is\s+(\S+)", re.IGNORECASE)
_WEAK_FLAGS = (("-ssl3", "SSLv3"), ("-tls1", "TLS1.0"), ("-tls1_1", "TLS1.1"))
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


def _listening_tls_ports(ctx: CheckContext) -> list[int]:
    stdout, _, rc = run_cmd(ctx, ["ss", "-tln"], timeout_s=4)
    if rc != 0:
        return []
    ports: set[int] = set()
    for line in stdout.splitlines():
        for m in re.finditer(r":(\d+)\s", line):
            try:
                p = int(m.group(1))
                if p in _TLS_PORTS:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)


def _weak_protocol_accepted(ctx: CheckContext, host: str, port: int, flag: str) -> bool:
    # `echo |` closes stdin so openssl doesn't hang waiting for input.
    cmd = f"echo | openssl s_client {flag} -connect {host}:{port} 2>&1"
    out, _, _ = run_cmd(ctx, cmd, timeout_s=8, shell=True)
    m = _HANDSHAKE_RE.search(out)
    return bool(m and m.group(2) not in ("(NONE)", "0000", ""))


class _C421Check:
    control_id = "4.2.1"
    control_title = "Strong cryptography for data in transit"
    section = "4"
    severity = "HIGH"
    remediation_static = (
        "Disable SSLv3, TLS 1.0 and TLS 1.1 on every TLS endpoint; require TLS 1.2+ "
        "with strong ciphers. nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Apache: "
        "`SSLProtocol -all +TLSv1.2 +TLSv1.3`. (PCI-DSS 4.2.1)"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        host = ctx.host if ctx.host != "localhost" else "127.0.0.1"
        if not _SAFE_HOST_RE.match(host):
            return self._result("ERROR", f"unsafe host: {host!r}", {"reason": "unsafe host name"}, t0, ctx)

        ports = _listening_tls_ports(ctx)
        if not ports:
            return self._result("N/A", "ss -tln", {"exposed_tls_ports": []}, t0, ctx)

        per_port: dict[str, dict] = {}
        any_fail = False
        for port in ports:
            weak = [label for flag, label in _WEAK_FLAGS if _weak_protocol_accepted(ctx, host, port, flag)]
            per_port[str(port)] = {"weak_protocols_accepted": weak}
            if weak:
                any_fail = True

        return self._result(
            "FAIL" if any_fail else "PASS",
            f"openssl s_client -ssl3/-tls1/-tls1_1 (each of ports {ports})",
            {"exposed_tls_ports": ports, "per_port": per_port},
            t0,
            ctx,
        )

    def _result(self, verdict, cmd, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=str(parsed)[:4096],
            evidence_stderr="",
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C421Check()
register_check(CHECK)
