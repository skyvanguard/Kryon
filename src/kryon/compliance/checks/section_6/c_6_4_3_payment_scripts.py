"""PCI-DSS v4.0.1 control 6.4.3 — Payment page script management.

Mandatory since 2025-03-31. Scripts loaded and executed in the consumer's
browser must be *managed* — this check verifies the two technically
observable pieces:

  - **Integrity**: every EXTERNAL ``<script>`` carries a Subresource
    Integrity (``integrity=``) attribute.
  - **Authorization**: a Content-Security-Policy with a ``script-src``
    directive restricts which scripts may load.

Verdict FAIL if any external script lacks SRI, or no CSP ``script-src`` is
present, on a responding web service. N/A when no web service is exposed.
(The inventory + written justification part of 6.4.3 is process/manual.)
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_SRC_RE = re.compile(r"""\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_INTEGRITY_RE = re.compile(r"\bintegrity\s*=", re.IGNORECASE)


def _listening_web_ports(ctx: CheckContext) -> list[int]:
    stdout, _, rc = run_cmd(ctx, ["ss", "-tln"], timeout_s=4)
    if rc != 0:
        return []
    ports: set[int] = set()
    for line in stdout.splitlines():
        m = re.search(r":(\d+)\s", line)
        if m:
            try:
                p = int(m.group(1))
                if p in _WEB_PORTS:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)


def _is_external(src: str) -> bool:
    s = src.strip().lower()
    return s.startswith(("http://", "https://", "//"))


def _external_scripts_without_sri(body: str) -> list[str]:
    missing: list[str] = []
    for m in _SCRIPT_TAG_RE.finditer(body):
        tag = m.group(0)
        srcm = _SRC_RE.search(tag)
        if srcm and _is_external(srcm.group(1)) and not _INTEGRITY_RE.search(tag):
            missing.append(srcm.group(1))
    return missing


class _C643Check:
    control_id = "6.4.3"
    control_title = "Payment page script management (SRI + CSP)"
    section = "6"
    # CRITICAL: 4.0.1 mandatorio guarding payment-page tampering (Magecart via
    # compromised TPSP) — high-impact CDE attack surface.
    severity = "CRITICAL"
    remediation_static = (
        'Add Subresource Integrity to every external <script> (integrity="sha384-..." '
        'crossorigin="anonymous") and set a Content-Security-Policy with an explicit '
        "script-src allowlist. Maintain an inventory + written justification of every "
        "payment-page script (PCI-DSS v4.0.1 6.4.3, mandatory since 2025-03-31)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        ports = _listening_web_ports(ctx)
        if not ports:
            return self._result("N/A", "ss -tln", "no listening web ports detected", {"exposed_web_ports": []}, t0, ctx)

        per_port: dict[str, dict] = {}
        combined: list[str] = []
        any_fail = False
        for port in ports:
            is_tls = port in (443, 8443)
            scheme = "https" if is_tls else "http"
            host = ctx.host if ctx.host != "localhost" else "127.0.0.1"
            url = f"{scheme}://{host}:{port}/"
            stdout, _, rc = run_cmd(ctx, ["curl", "-s", "-i", "--max-time", "6", "-k", url], timeout_s=10)
            if rc != 0 and not stdout.strip():
                per_port[str(port)] = {"scheme": scheme, "error": "no response"}
                continue
            sep = "\r\n\r\n" if "\r\n\r\n" in stdout else "\n\n"
            head, _, body = stdout.partition(sep)
            headers_blob = head.lower()
            has_csp_script_src = "content-security-policy" in headers_blob and "script-src" in headers_blob
            ext_no_sri = _external_scripts_without_sri(body)

            issues: list[str] = []
            if ext_no_sri:
                issues.append(f"{len(ext_no_sri)} external script(s) without SRI")
            if not has_csp_script_src:
                issues.append("no CSP script-src directive")
            per_port[str(port)] = {
                "scheme": scheme,
                "csp_script_src": has_csp_script_src,
                "external_scripts_without_sri": ext_no_sri[:20],
                "issues": issues,
            }
            combined.append(
                f"=== :{port} {scheme} === csp_script_src={has_csp_script_src}, ext_no_sri={len(ext_no_sri)}"
            )
            if issues:
                any_fail = True

        return self._result(
            "FAIL" if any_fail else "PASS",
            f"curl -s -i (each of ports {ports})",
            "\n".join(combined)[:4096],
            {"exposed_web_ports": ports, "per_port": per_port},
            t0,
            ctx,
        )

    def _result(self, verdict, cmd, stdout, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C643Check()
register_check(CHECK)
