"""FGT-3.1 — SSL VPN refuses TLS 1.0 / TLS 1.1.

`config vpn ssl settings` exposes legacy TLS toggles. Any SSL VPN endpoint
that accepts TLSv1.0 or TLSv1.1 violates PCI-DSS 4.2.1 and is subject to
known cipher downgrade attacks (POODLE-class).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _SslVpnTlsMinCheck:
    control_id = "FGT-3.1"
    control_title = "SSL VPN refuses TLS 1.0 and TLS 1.1"
    section = "3"
    severity = "CRITICAL"
    remediation_static = (
        "config vpn ssl settings\n"
        "  set tlsv1-0 disable\n"
        "  set tlsv1-1 disable\n"
        "  set tlsv1-2 enable\n"
        "  set tlsv1-3 enable\n"
        "  set algorithm high          # forbid weak cipher suites\n"
        "  set banned-cipher RSA       # if RSA key-exchange not needed\n"
        "end\n"
        "Confirm with `diagnose vpn ssl info` after restart."
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

        def directive(name: str) -> str:
            m = re.search(rf"^\s*set\s+{re.escape(name)}\s+(\S+)", out, re.M)
            return m.group(1).strip().lower() if m else ""

        tls10 = directive("tlsv1-0")
        tls11 = directive("tlsv1-1")
        tls12 = directive("tlsv1-2")
        tls13 = directive("tlsv1-3")
        algorithm = directive("algorithm")

        issues: list[str] = []
        # FortiOS default for tlsv1-0/1.1 is `disable` on FortiOS 7+, but old
        # configs may still have it explicitly enabled.
        if tls10 == "enable":
            issues.append("TLS 1.0 is explicitly enabled (CVE class)")
        if tls11 == "enable":
            issues.append("TLS 1.1 is explicitly enabled (CVE class)")
        if tls12 == "disable" and tls13 == "disable":
            issues.append("Both TLS 1.2 and 1.3 are disabled (no modern TLS)")
        if algorithm and algorithm not in ("high", "high-and-medium"):
            # 'low' or 'medium' permits known-weak ciphers
            if algorithm in ("low", "medium"):
                issues.append(f"cipher algorithm policy = '{algorithm}' (allows weak)")

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
                "tlsv1-0": tls10 or "(absent)",
                "tlsv1-1": tls11 or "(absent)",
                "tlsv1-2": tls12 or "(absent)",
                "tlsv1-3": tls13 or "(absent)",
                "algorithm": algorithm or "(default)",
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SslVpnTlsMinCheck()
register_check(CHECK)
