"""WIN-2.4 — LLMNR / NetBIOS-NS disabled (mitigates Responder MITM)."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _LlmnrCheck:
    control_id = "WIN-2.4"
    control_title = "LLMNR (and NetBIOS-NS) disabled — Responder MITM mitigation"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Disable LLMNR via registry / GPO:\n"
        "  reg add HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient \\\n"
        "    /v EnableMulticast /t REG_DWORD /d 0 /f\n"
        "GPO path:\n"
        "  Computer Config → Admin Templates → Network → DNS Client →\n"
        "    Turn off multicast name resolution: Enabled\n"
        "Also disable NetBIOS-NS on every interface (per-NIC):\n"
        '  Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" | '
        "  ForEach-Object { $_.SetTcpipNetbios(2) }   # 2 = Disabled\n"
        "Without these settings, internal attackers can use Responder to\n"
        "answer broadcast name queries with their own IP and capture\n"
        "NetNTLMv2 hashes from clients trying to reach a mistyped share."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "(Get-ItemProperty '
            "-Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient' "
            '-Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out and "ItemNotFound" not in err:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        value = out.strip()
        if value == "0":
            verdict, parsed = "PASS", {"EnableMulticast": 0}
        else:
            # Missing key or 1 = LLMNR active.
            verdict, parsed = "FAIL", {"EnableMulticast": value or "absent (default=enabled)"}
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _LlmnrCheck()
register_check(CHECK)
