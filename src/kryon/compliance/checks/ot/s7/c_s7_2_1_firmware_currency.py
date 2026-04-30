"""F84.3 — S7 check 2.1: PLC firmware currency vs known CVE bands.

A PLC running an end-of-life firmware version is exposed to known CVEs.
This check parses the firmware string from SZL 0x0011 and flags versions
known to be vulnerable per Siemens Security Advisory ranges.

Note: this is NOT a substitute for `search_vulnerabilities` against a
fresh CVE feed; it's a deterministic baseline that fires for the most
common publicly-known issues. CVE-specific exploitation testing is the
LLM's job in fase 3 of the playbook.

Known vulnerable firmware bands (compiled 2024):
  S7-1500 V < 2.5    — CVE-2018-13815, CVE-2019-10923 cluster
  S7-1200 V < 4.5    — CVE-2020-15782 (memory protection bypass)
  S7-300  V < 3.4    — CVE-2016-9159 (DoS), CVE-2017-2682 (RCE)
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.s7_enum import s7_enum


# Tuples of (order_code_prefix, min_safe_version_tuple).
# A firmware below the second entry is flagged FAIL.
_VULN_BANDS = (
    # S7-1500 series (order code 6ES7 5xx-x)
    (re.compile(r"^6ES7\s*5\d{2}-"), (2, 5, 0)),
    # S7-1200 series (6ES7 2xx-x)
    (re.compile(r"^6ES7\s*2\d{2}-"), (4, 5, 0)),
    # S7-300 series (6ES7 3xx-x)
    (re.compile(r"^6ES7\s*3\d{2}-"), (3, 4, 0)),
    # S7-400 series (6ES7 4xx-x) — firmware floor 6.0.x
    (re.compile(r"^6ES7\s*4\d{2}-"), (6, 0, 0)),
)


def _parse_firmware_tuple(version_str: str) -> tuple[int, int, int] | None:
    """Extract (major, minor, patch) from strings like 'V 4.1.3' or
    'V4.1' or 'V 3.2.6'. Returns None if unparseable."""
    m = re.search(r"V\s*(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if not m:
        return None
    major, minor, patch = m.group(1), m.group(2), m.group(3) or "0"
    return (int(major), int(minor), int(patch))


def _matching_band(order_code: str) -> tuple[int, int, int] | None:
    for pattern, floor in _VULN_BANDS:
        if pattern.match(order_code):
            return floor
    return None


class _S7_21Check:
    control_id = "S7-2.1"
    control_title = "Siemens PLC firmware currency vs known CVE bands"
    section = "S7-2"
    severity = "HIGH"
    remediation_static = (
        "Upgrade the PLC firmware to the safe floor for its CPU family. "
        "Plan a maintenance window — Siemens firmware upgrades require "
        "rebooting the CPU which interrupts the controlled process. "
        "Coordinate with the plant operator. Subscribe to Siemens "
        "ProductCERT advisories (https://cert-portal.siemens.com/) for "
        "ongoing visibility."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = s7_enum(ctx.host, port=102)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable or not result.s7_session_established:
            verdict = "N/A"
            stdout = (
                f"Cannot evaluate firmware currency — S7 session not "
                f"established on {ctx.host}:102."
            )
            parsed = {"reachable": result.reachable}
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict=verdict,
                evidence_command="s7_enum(host).module_identification",
                evidence_stdout=stdout,
                evidence_stderr="",
                evidence_parsed=parsed,
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=elapsed_ms,
                host=ctx.host,
                run_id="",
            )

        order_code = result.module_identification.get("order_code", "")
        firmware = result.plc_firmware_version

        if not order_code or not firmware:
            verdict = "N/A"
            stdout = (
                f"Could not determine firmware version on {ctx.host}: "
                f"order_code={order_code!r}, firmware={firmware!r}. "
                "Try a different rack/slot."
            )
        else:
            actual = _parse_firmware_tuple(firmware)
            floor = _matching_band(order_code)
            if actual is None or floor is None:
                verdict = "N/A"
                stdout = (
                    f"PLC at {ctx.host} ({order_code}, fw {firmware}) does "
                    "not match any tracked vulnerability band. Run "
                    "`search_vulnerabilities` against the order code "
                    "for a fresh check."
                )
            elif actual < floor:
                verdict = "FAIL"
                floor_str = ".".join(str(p) for p in floor)
                stdout = (
                    f"PLC at {ctx.host} ({order_code}) running firmware "
                    f"{firmware} is BELOW the safe floor ({floor_str}). "
                    "Multiple CVEs apply to this band; upgrade required."
                )
            else:
                verdict = "PASS"
                stdout = (
                    f"PLC at {ctx.host} ({order_code}) running firmware "
                    f"{firmware} is at or above the safe floor for its "
                    f"CPU family."
                )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="s7_enum(host).module_identification",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "reachable": result.reachable,
                "order_code": order_code,
                "firmware": firmware,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _S7_21Check()
register_check(CHECK)
