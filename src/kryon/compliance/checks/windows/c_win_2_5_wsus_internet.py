"""WIN-2.5 — WSUS configured to a non-public update server (or unset → MS default)."""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _WsusInternetCheck:
    control_id = "WIN-2.5"
    control_title = "WSUS configured to a non-public update server (or unset = MS default)"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Either:\n"
        "  (a) Point WSUS to an internal upstream server. GPO:\n"
        "      Computer Config → Admin Templates → Windows Components →\n"
        "        Windows Update → Specify intranet Microsoft update service location\n"
        "        Set both `Set the intranet update service` and `Set the intranet\n"
        "        statistics server` to e.g. http://wsus.empresa.local:8530\n"
        "  (b) Or clear the WUServer / WUStatusServer registry keys to let\n"
        "      Windows pull directly from Microsoft Update.\n"
        "The failure mode this check catches: WUServer pointing to a public IP\n"
        "or to an externally-resolvable hostname — that's a supply-chain risk."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "(Get-ItemProperty '
            "-Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate' "
            '-Name WUServer -ErrorAction SilentlyContinue).WUServer"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out and "ItemNotFound" not in err:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        value = out.strip()
        if not value:
            # Key not set → Windows uses Microsoft Update. Acceptable.
            return make_result(
                check=self,
                verdict="PASS",
                cmd=cmd,
                out=out,
                err=err,
                parsed={"WUServer": "not configured — using Microsoft Update directly"},
                t0=t0,
                ctx=ctx,
            )

        # Inspect WUServer value: must NOT be a public hostname.
        m = re.match(r"https?://([^/:]+)", value)
        host = m.group(1) if m else value
        is_private = (
            host.endswith((".local", ".lan", ".internal", ".corp", ".intranet"))
            or host.startswith(("10.", "127.", "192.168."))
            or re.match(r"^172\.(1[6-9]|2[0-9]|3[01])\.", host)
        )
        if is_private:
            verdict, parsed = "PASS", {"WUServer": value, "host": host, "is_private": True}
        else:
            verdict, parsed = "FAIL", {"WUServer": value, "host": host, "is_private": False}
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _WsusInternetCheck()
register_check(CHECK)
