"""PCI-DSS v4 control 6.4.1 — Public-facing web application protection.

Checks HTTP response headers of any exposed web service on the host.

Required headers (verdict FAIL if any missing on a responding service):
  - Strict-Transport-Security (HSTS) — TLS endpoints only
  - Content-Security-Policy
  - X-Frame-Options (or CSP `frame-ancestors`)
  - X-Content-Type-Options: nosniff

Web exposure detected via `ss -tln` (listening TCP ports in the web range).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

_REQUIRED_HEADERS_HTTP = ("content-security-policy", "x-frame-options", "x-content-type-options")
_REQUIRED_HEADERS_TLS = _REQUIRED_HEADERS_HTTP + ("strict-transport-security",)


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


def _fetch_headers(ctx: CheckContext, port: int, is_tls: bool) -> tuple[dict, str]:
    scheme = "https" if is_tls else "http"
    host = ctx.host if ctx.host != "localhost" else "127.0.0.1"
    url = f"{scheme}://{host}:{port}/"
    stdout, _, rc = run_cmd(
        ctx,
        ["curl", "-sI", "--max-time", "5", "-k", url],
        timeout_s=8,
    )
    if rc != 0 and not stdout.strip():
        return {}, f"no response from {url}"
    headers: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers, stdout


class _C641Check:
    control_id = "6.4.1"
    control_title = "Public-facing web application protection"
    section = "6"
    severity = "HIGH"
    remediation_static = (
        "Add security response headers at the reverse proxy / web server: "
        "Strict-Transport-Security (TLS only), Content-Security-Policy, "
        "X-Frame-Options: DENY, X-Content-Type-Options: nosniff. "
        "For nginx see /etc/nginx/conf.d/*.conf `add_header` directives."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        ports = _listening_web_ports(ctx)
        if not ports:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command="ss -tln",
                evidence_stdout="no listening web ports detected",
                evidence_stderr="",
                evidence_parsed={"exposed_web_ports": []},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        per_port_results: dict[str, dict] = {}
        combined_stdout: list[str] = []
        any_fail = False
        for port in ports:
            is_tls = port in (443, 8443)
            required = _REQUIRED_HEADERS_TLS if is_tls else _REQUIRED_HEADERS_HTTP
            headers, raw = _fetch_headers(ctx, port, is_tls)
            combined_stdout.append(f"=== :{port} {'https' if is_tls else 'http'} ===\n{raw}")
            missing = sorted([h for h in required if h not in headers])
            per_port_results[str(port)] = {
                "scheme": "https" if is_tls else "http",
                "missing_headers": missing,
                "present_headers": sorted([h for h in headers if h in set(required)]),
            }
            if missing:
                any_fail = True

        verdict = "FAIL" if any_fail else "PASS"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"curl -sI (each of ports {ports})",
            evidence_stdout="\n\n".join(combined_stdout)[:4096],
            evidence_stderr="",
            evidence_parsed={
                "exposed_web_ports": ports,
                "per_port": per_port_results,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C641Check()
register_check(CHECK)
