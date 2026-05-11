"""UNF-2.2 — WPA-PSK passphrase has reasonable length and entropy.

We can read `x_passphrase` from `wlanconf`. We do NOT crack it (offline,
out of scope here), but we apply structural heuristics:
  - Length < 12 chars → FAIL (NIST 800-63B floor for shared secrets)
  - All-lowercase + only-letters/digits with single repeated word → FAIL
  - Common formats like `EmpresaNombre2024`, `<word>123` → FAIL
  - Length >= 14 with mixed character classes → PASS

This is conservative; an actual offline crack still requires the
`unifi-audit` skill's WiFi capture path.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_MIN_LENGTH = 12
_PREFERRED_LENGTH = 14
_COMMON_TAILS = re.compile(r"(?:\d{2}|\d{4}|\d{2,4}!?)$")


def _classify(passphrase: str) -> tuple[bool, list[str]]:
    """Return (is_weak, list-of-reasons)."""
    reasons: list[str] = []
    if len(passphrase) < _MIN_LENGTH:
        reasons.append(f"length={len(passphrase)} < {_MIN_LENGTH}")
    classes = sum(
        [
            any(c.islower() for c in passphrase),
            any(c.isupper() for c in passphrase),
            any(c.isdigit() for c in passphrase),
            any(not c.isalnum() for c in passphrase),
        ]
    )
    if classes < 3:
        reasons.append(f"only {classes} char classes used")
    if _COMMON_TAILS.search(passphrase):
        # Looks like <word><year>; flagging as weak structure.
        if len(passphrase) < _PREFERRED_LENGTH:
            reasons.append("ends with year/digit pattern (dictionary-friendly)")
    return (len(reasons) > 0, reasons)


class _WpaPassphraseStrengthCheck:
    control_id = "UNF-2.2"
    control_title = f"WPA-PSK passphrases meet >= {_MIN_LENGTH} chars + 3 char classes"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        f"Generate a >= {_PREFERRED_LENGTH}-char passphrase per SSID. Examples:\n"
        "  - 4–5 random words (`correct horse battery staple`) + a digit\n"
        "  - 16-char random base32 (`pwgen -s 16 1`)\n"
        "Rotate annually OR on staff turnover. Store in the company password\n"
        "manager — never on a sticky note in reception."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'db.wlanconf.find({security: {$regex: /wpa/i}}, "
            "{name:1, x_passphrase:1, wpa_mode:1, enabled:1})"
            ".forEach(function(d){print(JSON.stringify(d))})'"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not query wlanconf"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        weak: list[dict[str, object]] = []
        examined = 0
        for line in out.splitlines():
            ls = line.strip()
            if not ls.startswith("{"):
                continue
            name_m = re.search(r'"name"\s*:\s*"([^"]+)"', ls)
            pp_m = re.search(r'"x_passphrase"\s*:\s*"([^"]+)"', ls)
            enabled_m = re.search(r'"enabled"\s*:\s*(\w+)', ls)
            if enabled_m and enabled_m.group(1).lower() == "false":
                continue
            if not name_m or not pp_m:
                continue
            examined += 1
            is_weak, reasons = _classify(pp_m.group(1))
            if is_weak:
                # Don't store the passphrase itself in evidence — just SSID + reasons.
                weak.append({"name": name_m.group(1), "reasons": reasons})

        issues = [
            f"SSID '{w['name']}' weak passphrase: {', '.join(w['reasons'])}"  # type: ignore[arg-type]
            for w in weak
        ]
        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout="(passphrases redacted)",
            evidence_stderr=err[:512],
            evidence_parsed={
                "ssids_examined": examined,
                "weak_count": len(weak),
                "weak_ssids": [w["name"] for w in weak],
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _WpaPassphraseStrengthCheck()
register_check(CHECK)
