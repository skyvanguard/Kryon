"""WIN-4.2 — EDR / next-gen AV agent present and running."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

# Common EDR / next-gen AV service names. The check INFOs the user about which
# (if any) is present. Lack of EDR is not necessarily a critical fail in every
# environment, but it should always be visible in the audit report.
_EDR_SERVICES = {
    "Sense": "Microsoft Defender for Endpoint",
    "WdNisSvc": "Microsoft Defender Network Inspection",
    "CSFalconService": "CrowdStrike Falcon",
    "SentinelAgent": "SentinelOne",
    "TaniumClient": "Tanium",
    "QualysAgent": "Qualys Cloud Agent",
    "CarbonBlack": "VMware Carbon Black",
    "cbservice": "Carbon Black legacy",
    "ESETService": "ESET Endpoint Security",
    "TmCCSF": "Trend Micro Apex One",
    "ekrn": "ESET Kernel Service",
    "McAfeeFramework": "McAfee Agent",
    "McShield": "McAfee VirusScan",
    "BdAgent": "Bitdefender GravityZone",
}


class _EdrDetectionCheck:
    control_id = "WIN-4.2"
    control_title = "EDR / next-gen AV agent detected and running"
    section = "4"
    severity = "MEDIUM"
    remediation_static = (
        "Deploy and enforce an EDR on every workstation and server. If\n"
        "Microsoft Defender is the chosen solution, ensure it's onboarded\n"
        "to Defender for Endpoint and the Sense service is running:\n"
        "  Get-Service Sense\n"
        "Pure Microsoft Defender ASR (without onboarding) does NOT count\n"
        "as EDR — only as basic AV.\n"
        "Most regulated environments (PCI-DSS 5.x, ISO 27001 A.8.7,\n"
        "BCP Res. 06/2020) now expect EDR with active tamper protection."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        svc_names = ",".join(f"'{s}'" for s in _EDR_SERVICES)
        cmd = (
            'powershell -nop -c "'
            f"Get-Service -Name @({svc_names}) -ErrorAction SilentlyContinue | "
            'ForEach-Object { Write-Output "$($_.Name)=$($_.Status)" }'
            '"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=20)
        if rc != 0 and not out:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        running: list[str] = []
        installed_not_running: list[str] = []
        for line in (out or "").splitlines():
            line = line.strip()
            if "=" not in line:
                continue
            name, status = line.split("=", 1)
            name = name.strip()
            status = status.strip().lower()
            label = _EDR_SERVICES.get(name, name)
            if status == "running":
                running.append(f"{name} ({label})")
            else:
                installed_not_running.append(f"{name} ({label}) [{status}]")

        if running:
            verdict, parsed = "PASS", {"running_edrs": running, "stopped_edrs": installed_not_running}
        elif installed_not_running:
            verdict, parsed = "FAIL", {"reason": "EDR installed but not running", "stopped_edrs": installed_not_running}
        else:
            verdict, parsed = "FAIL", {"reason": "no recognised EDR / next-gen AV agent found"}
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _EdrDetectionCheck()
register_check(CHECK)
