"""WIN-3.2 — LAPS (Local Administrator Password Solution) deployed."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _LapsCheck:
    control_id = "WIN-3.2"
    control_title = "LAPS deployed (local administrator password randomization)"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Deploy Windows LAPS (built-in on Win11/Server 2022+, or download\n"
        "the legacy AdmPwd.PS module for older OS):\n"
        "  - Configure via GPO: Computer Config → Admin Templates → System →\n"
        "    LAPS → Configure password backup directory: AD or AzureAD\n"
        "  - Schedule rotation every 30 days max.\n"
        "Without LAPS the same local admin password tends to be reused\n"
        "across the entire fleet — once one machine is compromised the\n"
        "attacker can pivot laterally to all the others (pass-the-hash)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        # Win11/Server2022+ built-in LAPS module is `LAPS`. Legacy module is AdmPwd.PS.
        cmd = (
            'powershell -nop -c "'
            "$builtin = (Get-Module -ListAvailable -Name LAPS -ErrorAction SilentlyContinue) -ne $null;"
            "$legacy = (Get-Module -ListAvailable -Name AdmPwd.PS -ErrorAction SilentlyContinue) -ne $null;"
            "$svc = (Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config' "
            "-ErrorAction SilentlyContinue);"
            'Write-Output "builtin=$builtin legacy=$legacy svcConfig=$($svc -ne $null)"'
            '"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        text = out.strip()
        builtin = "builtin=True" in text
        legacy = "legacy=True" in text
        configured = "svcConfig=True" in text

        verdict = "PASS" if (builtin and configured) or legacy else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"builtin_laps": builtin, "legacy_admpwd": legacy, "service_configured": configured},
            t0=t0,
            ctx=ctx,
        )


CHECK = _LapsCheck()
register_check(CHECK)
