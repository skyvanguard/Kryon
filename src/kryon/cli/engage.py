"""F12.7 / F77.A — `kryon engage` end-to-end orchestrator.

Single command that takes a target (host / CIDR / domain) and produces:

  Phase 1  discovery (nmap with live_progress)
  Phase 2  service-specific assessment (SSH config check, HTTP probe,
           DB banner grab)
  Phase 2b optional compliance audit (F77.A — when --framework given)
  Phase 3  findings summary + rule-based remediation proposals
  Phase 4  optional approval prompt + apply (when --ssh provided)
  Phase 5  re-audit
  Phase 6  HTML + PDF report. When --framework is used the consolidated
           multi-framework PDF is produced; otherwise the demo_report.

F77.A wires engage into the rest of the stack:
- `--framework FW[,FW2,...]` runs the compliance runner and consolidates
  findings into the multi-framework PDF (F44).
- `--use-agent` / KRYON_ENGAGE_AGENT=true bolts the unified Kryon agent
  onto the tail of Phase 2 for LLM-driven deepening of the findings
  surface. Off by default to preserve demo determinism.

Usage:

    kryon engage 127.0.0.1 \\
        --scope 127.0.0.1 \\
        --ssh admin@127.0.0.1:2222 \\
        --ssh-password demo-only-password \\
        --out /tmp/kryon-reports \\
        --client britimp \\
        --engagement-id britimp-demo-2026-04-15

    kryon engage 127.0.0.1 --dry-run-only        # no apply, just report
    kryon engage 127.0.0.1 --auto-approve        # lab/demo only
    kryon engage 127.0.0.1 --framework pci_dss,bcp_py  # compliance sweep
    kryon engage 127.0.0.1 --use-agent           # agent-driven deepening
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    cwe: str
    severity: str
    host: str
    rule_id: str
    message: str
    evidence: str = ""
    remediation: str = ""
    remediation_command: str = ""  # exact shell command for Fase 3
    target_host: str = ""  # admin@host for SSH exec
    severity_rank: int = field(default=99)
    # F134 — confidence score in [0.0, 1.0]. Default 1.0 because most
    # callers construct Finding from deterministic checks; the LLM
    # parser knocks this down before the orchestrator returns.
    confidence: float = 1.0
    needs_verification: bool = False


_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# -----------------------------------------------------------------------------
# Phase 1 — discovery
# -----------------------------------------------------------------------------


def _build_engage_nmap_cmd(target: str, ports: str = "") -> list[str]:
    """Build the Phase 1 nmap command honoring F196 throttle env.

    F202.S security hardening: returns argv list (not string) so the
    caller can run with `shell=False`, eliminating command-injection
    risk when env vars (KRYON_NMAP_TIMING etc.) are operator-controlled
    via CI/CD pipelines or wrapper scripts.

    F202.S.C Windows fix: resolve nmap to absolute path via shutil.which
    because shell=False on Windows doesn't resolve `nmap` (without .exe
    suffix) from PATH.

    F202.T: optional `ports` arg replaces `--top-ports 100` with an
    explicit port list (e.g. "22,80,2222,8080,33060"). Useful for
    focused scans against hosts with non-canonical ports OR to avoid
    FPs when scanning localhost with mixed targets.
    """
    # -Pn: skip host discovery. Required when the target firewall
    # filters ICMP (typical for hardened hosts and PVE behind FortiGate).
    # -sT: TCP connect scan. Default -sV picks -sS (raw SYN) which needs
    # Npcap/raw sockets — unavailable on Windows hosts without admin
    # install. -sT works as a non-privileged user on every platform.
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd: list[str] = [nmap_bin, "-Pn", "-sT", "-sV"]

    timing_env = os.environ.get("KRYON_NMAP_TIMING", "").strip()
    timing_flag = f"-T{timing_env.lstrip('T')}" if timing_env else "-T4"
    cmd.append(timing_flag)

    # F202.T: --ports overrides --top-ports 100 when provided
    if ports.strip():
        # Sanitize: only digits + comma + dash (port ranges 80-100)
        # to avoid argv injection via the operator-controlled flag.
        sanitized = re.sub(r"[^0-9,\-]", "", ports.strip())
        if sanitized:
            cmd.extend(["-p", sanitized])
        else:
            cmd.extend(["--top-ports", "100"])  # fallback
    else:
        cmd.extend(["--top-ports", "100"])

    min_rate_env = os.environ.get("KRYON_NMAP_MIN_RATE", "").strip()
    if min_rate_env:
        cmd.extend(["--min-rate", min_rate_env])

    max_par_env = os.environ.get("KRYON_NMAP_MAX_PARALLELISM", "").strip()
    if max_par_env:
        cmd.extend(["--max-parallelism", max_par_env])

    cmd.extend(["-oX", "-", target])
    return cmd


def _extend_timeout_for_throttle(timeout_s: int) -> int:
    """F199.M — Stretch the nmap timeout when throttle env makes the
    scan slower.

    Surfaced by the Britimp POC pilot 2026-05-18 against .106:
    `nmap -T2 --top-ports 100 --min-rate 50 --max-parallelism 10`
    took 355s wall-clock on a real host with only 2 open ports —
    well over the 180s default `--nmap-timeout`. Result: engage
    silently lost both ports (timeout → empty stdout → 0 puertos).

    Multipliers (conservative, can be tuned):
      KRYON_NMAP_TIMING T0/T1 → ×4
      KRYON_NMAP_TIMING T2    → ×3
      KRYON_NMAP_MIN_RATE ≤ 50 → ×2 (on top of timing multiplier)
      KRYON_NMAP_MAX_PARALLELISM ≤ 10 → +30 seconds
    """
    timing = os.environ.get("KRYON_NMAP_TIMING", "").strip().upper().lstrip("T")
    min_rate = os.environ.get("KRYON_NMAP_MIN_RATE", "").strip()
    max_par = os.environ.get("KRYON_NMAP_MAX_PARALLELISM", "").strip()

    multiplier = 1.0
    if timing in ("0", "1"):
        multiplier = 4.0
    elif timing == "2":
        multiplier = 3.0

    try:
        if min_rate and int(min_rate) <= 50:
            multiplier *= 2.0
    except ValueError:
        pass

    extra_s = 0
    try:
        if max_par and int(max_par) <= 10:
            extra_s = 30
    except ValueError:
        pass

    if multiplier == 1.0 and extra_s == 0:
        return timeout_s

    return int(timeout_s * multiplier + extra_s)


def _run_nmap(target: str, *, timeout_s: int = 600, ports: str = "") -> str:
    """Run a fast service-detection nmap against the target.

    Uses live_progress when KRYON_LIVE_PROGRESS=true; otherwise falls
    back to plain subprocess so CI benches don't render Live panels.

    F199.M — Auto-extends the timeout when throttle env vars are set
    so banca-safe scans (T2 + min-rate 50) actually have time to finish.
    """
    use_live = os.environ.get("KRYON_LIVE_PROGRESS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    cmd = _build_engage_nmap_cmd(target, ports=ports)
    timeout_s = _extend_timeout_for_throttle(timeout_s)
    if use_live:
        try:
            from kryon.repl.ui.live_progress import run_with_progress

            # F202.S: run_with_progress accepts only string; build it
            # via shlex.join (safe quoting) instead of f-string interpolation.
            cmd_str = shlex.join(cmd)
            r = run_with_progress(cmd_str, timeout_s=timeout_s)
            return r.stdout
        except Exception as exc:
            logger.warning("live_progress fell back: %s", exc)
    try:
        # F202.S security hardening: shell=False with argv list
        # eliminates command-injection via env vars (KRYON_NMAP_*).
        out = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return out.stdout
    except subprocess.TimeoutExpired:
        return ""


# F199.F — the previous regex made <service> optional and non-greedy `.*?`
# made the engine drop it most of the time, returning name/product/version
# = None for every host. That silently broke every banner-based family
# detection (proxmox/fortigate/asterisk/bmc). Splitting into TWO passes:
# first capture the `<port>` block as a whole, then extract service
# attributes from that block. Reliable + easy to extend.
_PORT_BLOCK_RE = re.compile(
    r'<port protocol="tcp" portid="(\d+)">(.*?)</port>',
    re.DOTALL,
)
_STATE_RE = re.compile(r'<state state="(\w+)"')
_SERVICE_NAME_RE = re.compile(r'<service\b[^>]*\bname="([^"]+)"')
_SERVICE_PRODUCT_RE = re.compile(r'<service\b[^>]*\bproduct="([^"]+)"')
_SERVICE_VERSION_RE = re.compile(r'<service\b[^>]*\bversion="([^"]+)"')


@dataclass
class DiscoveredService:
    host: str
    port: int
    state: str
    service: str
    product: str = ""
    version: str = ""


def _parse_nmap_xml(xml: str, host: str) -> list[DiscoveredService]:
    """F199.F — Two-pass parser: capture each <port>...</port> block, then
    extract service attributes from inside. Replaces the single regex that
    silently dropped product/version on every match (DOTALL+non-greedy
    plus optional service group made the engine skip <service> attrs).
    """
    out: list[DiscoveredService] = []
    for m in _PORT_BLOCK_RE.finditer(xml):
        port = int(m.group(1))
        body = m.group(2)
        state_m = _STATE_RE.search(body)
        state = state_m.group(1) if state_m else ""
        svc_name_m = _SERVICE_NAME_RE.search(body)
        svc_product_m = _SERVICE_PRODUCT_RE.search(body)
        svc_version_m = _SERVICE_VERSION_RE.search(body)
        out.append(
            DiscoveredService(
                host=host,
                port=port,
                state=state,
                service=(svc_name_m.group(1) if svc_name_m else "").lower(),
                product=svc_product_m.group(1) if svc_product_m else "",
                version=svc_version_m.group(1) if svc_version_m else "",
            )
        )
    return out


# -----------------------------------------------------------------------------
# Phase 2 — service-specific checks
# -----------------------------------------------------------------------------


_HTTP_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})", re.MULTILINE)
_HTTP_LOCATION_RE = re.compile(r"^Location:\s*([^\r\n]+)", re.MULTILINE | re.IGNORECASE)


def _is_tls_redirect(headers: str) -> bool:
    """F199.G — Return True when the HTTP response is a 301/302 redirect
    pointing to an https:// URL. That's the recommended mitigation, not
    a vulnerability — Kryon shouldn't flag it as HIGH plaintext.
    """
    status_m = _HTTP_STATUS_RE.search(headers)
    if not status_m:
        return False
    if status_m.group(1) not in ("301", "302", "307", "308"):
        return False
    loc_m = _HTTP_LOCATION_RE.search(headers)
    if not loc_m:
        return False
    return loc_m.group(1).strip().lower().startswith("https://")


def _check_http(svc: DiscoveredService) -> list[Finding]:
    """HTTP plaintext + server-token leak + /admin open.

    F199.G — Distinguishes between three states on a non-TLS port:
      1. 301/302 redirect to https:// → no plaintext finding (PASS via
         TLS enforcement, just informative if anything).
      2. 2xx/4xx response served directly over HTTP → flag HIGH plaintext.
      3. Connect refused / curl failed → flag HIGH (conservative).
    """
    findings: list[Finding] = []
    try:
        headers = subprocess.run(
            ["curl", "-sSI", "--max-time", "5", f"http://{svc.host}:{svc.port}/"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout
    except Exception:
        headers = ""

    # CWE-319: HTTP plaintext (no TLS on this port).
    # Skip the flag when port is one of the canonical TLS ports — they
    # mean the operator already deployed HTTPS, this scan probably hit
    # the TLS-on-non-https-port edge case (uncommon but defensible).
    is_tls_port = svc.port in (443, 8443, 4443, 9443)
    if not is_tls_port:
        if _is_tls_redirect(headers):
            # The server enforces TLS via 301/302 — that's the correct
            # behaviour. No plaintext finding.
            pass
        else:
            findings.append(
                Finding(
                    cwe="CWE-319",
                    severity="HIGH",
                    host=f"{svc.host}:{svc.port}",
                    rule_id="http-plaintext",
                    message=f"Servicio HTTP en {svc.host}:{svc.port} sin TLS y sin redirect a HTTPS.",
                    evidence=headers[:400] if headers else f"puerto {svc.port} abierto, servicio http",
                    remediation="Habilitar HTTPS y redirigir HTTP->HTTPS (301/302) o cerrar el puerto plano.",
                    severity_rank=_SEV_RANK["HIGH"],
                )
            )

    # CWE-200: Server header leaks version
    m = re.search(r"^Server:\s*([^\r\n]+)", headers, re.MULTILINE | re.IGNORECASE)
    if m and re.search(r"/\d", m.group(1)):
        findings.append(
            Finding(
                cwe="CWE-200",
                severity="MEDIUM",
                host=f"{svc.host}:{svc.port}",
                rule_id="http-server-token",
                message="Header Server expone versión del servidor.",
                evidence=f"Server: {m.group(1).strip()}",
                remediation="Configurar server_tokens off (nginx) o ServerTokens Prod (apache).",
                severity_rank=_SEV_RANK["MEDIUM"],
            )
        )

    # F200.B — Web server version EOL detection.
    # The http-server-token check above flags information disclosure
    # (MEDIUM CWE-200), but doesn't elevate severity when the disclosed
    # version is itself end-of-life. F200.B parses the version string
    # and flags HIGH CWE-1104 (Use of Unmaintained Third Party Components)
    # when the version is below the minimum supported.
    eol_finding = _check_webserver_eol(svc, headers)
    if eol_finding:
        findings.append(eol_finding)

    # F199.L — CWE-200 X-Powered-By header leaks app framework. Common
    # values seen in the wild:
    #   X-Powered-By: Express           → Node.js Express
    #   X-Powered-By: PHP/8.1.10        → PHP version
    #   X-Powered-By: ASP.NET           → IIS / .NET
    #   X-Powered-By: Servlet/3.1       → Java EE / Tomcat
    #   X-Powered-By: PleskLin / Sucuri → cPanel / Sucuri WAF tells
    # Even without a version, the framework name alone is useful CVE
    # cross-reference fuel (e.g. "Express" → CVE-2024-29041 redirect).
    xpb_m = re.search(r"^X-Powered-By:\s*([^\r\n]+)", headers, re.MULTILINE | re.IGNORECASE)
    if xpb_m:
        xpb_value = xpb_m.group(1).strip()
        findings.append(
            Finding(
                cwe="CWE-200",
                severity="MEDIUM",
                host=f"{svc.host}:{svc.port}",
                rule_id="http-xpoweredby",
                message="Header X-Powered-By expone framework / runtime.",
                evidence=f"X-Powered-By: {xpb_value}",
                remediation=(
                    "Suprimir el header. Por framework:\n"
                    "  Express:  app.disable('x-powered-by')  o  helmet().hidePoweredBy()\n"
                    "  PHP:      expose_php = Off  en php.ini\n"
                    "  ASP.NET:  <httpProtocol> <customHeaders> <remove name='X-Powered-By'/>\n"
                    "  Tomcat:   server.xml Connector xpoweredBy='false'"
                ),
                severity_rank=_SEV_RANK["MEDIUM"],
            )
        )

    # CWE-306: /admin accesible sin auth — F199.H distinguishes between
    # a real admin endpoint and a SPA catch-all that serves index.html
    # for every path (Angular / React / Vue with HTML5 routing). Helper
    # below compares the /admin response against the root: identical
    # body means SPA catch-all (no finding); different content means a
    # real admin surface (flag HIGH).
    admin_finding = _check_admin_open(svc)
    if admin_finding:
        findings.append(admin_finding)

    # F199.N — Password manager / secrets-vault self-hosted detection.
    # These are highest-value assets in any network: a compromised
    # Vaultwarden / Passbolt instance exposes the credentials for
    # everything else in scope. Flag HIGH so the operator pays attention.
    pm_finding = _check_password_manager(svc)
    if pm_finding:
        findings.append(pm_finding)

    return findings


# F199.N — Signature table for self-hosted password / secret managers.
# Each tuple: (regex, short_id, pretty_name). Patterns are conservative —
# we look for HTML title or unique JS/CSS asset paths that vendor ships.
_PASSWORD_MANAGER_SIGNATURES = (
    (re.compile(r"<title[^>]*>\s*Vaultwarden", re.IGNORECASE), "vaultwarden", "Vaultwarden (self-hosted Bitwarden)"),
    (re.compile(r"<title[^>]*>\s*Bitwarden", re.IGNORECASE), "bitwarden", "Bitwarden self-hosted"),
    (re.compile(r"<title[^>]*>\s*Passbolt", re.IGNORECASE), "passbolt", "Passbolt"),
    (re.compile(r"passbolt-api\.com", re.IGNORECASE), "passbolt", "Passbolt"),
    (re.compile(r"<title[^>]*>\s*Padloc", re.IGNORECASE), "padloc", "Padloc"),
    (re.compile(r"\bpadloc-app\b", re.IGNORECASE), "padloc", "Padloc"),
    (re.compile(r"<title[^>]*>\s*KeeWeb", re.IGNORECASE), "keeweb", "KeeWeb (KeePass web)"),
    (re.compile(r"<title[^>]*>\s*Pleasant Password Server", re.IGNORECASE), "pleasant", "Pleasant Password Server"),
    (re.compile(r"<title[^>]*>\s*Psono", re.IGNORECASE), "psono", "Psono (self-hosted)"),
    (re.compile(r"<title[^>]*>\s*Teampass", re.IGNORECASE), "teampass", "Teampass"),
)


# F202.U — cookie security flags detector (CWE-1004 + CWE-614 + CWE-1275).
# Surfaced docker/vulnerable-lab smoke test: target-web tiene cookies
# sin `HttpOnly` flag (intentional planted vuln). Antes de F202.U,
# Kryon NO detectaba este patron automaticamente — gap del producto
# vs ground truth del lab.
#
# 3 niveles de problema, ordenados por severidad banking:
#   - HttpOnly missing -> MEDIUM CWE-1004 (cookie stealable via XSS)
#   - Secure missing en HTTPS -> MEDIUM CWE-614 (cookie via MITM)
#   - SameSite=None o missing -> LOW CWE-1275 (CSRF risk)
#
# Banking: para session cookies (PHPSESSID, JSESSIONID, etc.), missing
# HttpOnly + missing Secure = compromise inmediato de la sesion del
# usuario logueado via XSS reflejado + sniff network.

_HTTP_SET_COOKIE_RE = re.compile(
    r"^Set-Cookie:\s*([^=\s]+)=([^;\r\n]*)([^\r\n]*)",
    re.MULTILINE | re.IGNORECASE,
)


def _check_http_cookie_flags(svc: DiscoveredService) -> list[Finding]:
    """F202.U — Check Set-Cookie headers for HttpOnly + Secure +
    SameSite flags. Returns multiple findings if multiple cookies miss
    different flags. Read-only HTTP HEAD-style request.
    """
    findings: list[Finding] = []
    if svc.state != "open":
        return findings
    if svc.port not in (80, 443, 8080, 8443, 8000, 8888):
        return findings

    scheme = "https" if svc.port in (443, 8443) else "http"
    url = f"{scheme}://{svc.host}:{svc.port}/"

    try:
        proc = subprocess.run(
            [
                shutil.which("curl") or "curl",
                "-sSI",
                "-k",
                "--max-redirs",
                "0",
                "--max-time",
                "5",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return findings

    headers = proc.stdout
    if not headers:
        return findings

    cookies_missing_httponly: list[str] = []
    cookies_missing_secure: list[str] = []
    cookies_missing_samesite: list[str] = []

    for m in _HTTP_SET_COOKIE_RE.finditer(headers):
        name = m.group(1).strip()
        # group 3 = rest of the attributes after the value
        attrs_lower = m.group(3).lower()

        if "httponly" not in attrs_lower:
            cookies_missing_httponly.append(name)
        # Secure flag only meaningful on HTTPS
        if svc.port in (443, 8443) and "secure" not in attrs_lower:
            cookies_missing_secure.append(name)
        if "samesite" not in attrs_lower:
            cookies_missing_samesite.append(name)

    if cookies_missing_httponly:
        findings.append(
            Finding(
                cwe="CWE-1004",
                severity="MEDIUM",
                host=f"{svc.host}:{svc.port}",
                rule_id="http-cookie-missing-httponly",
                message=(
                    f"Cookie(s) sin flag HttpOnly en {svc.host}:{svc.port}: "
                    f"{', '.join(cookies_missing_httponly[:5])}"
                    + (f" (+{len(cookies_missing_httponly) - 5} mas)" if len(cookies_missing_httponly) > 5 else "")
                    + ". Cookie stealable via XSS reflejado / DOM-XSS — "
                    "compromiso de sesion banking user inmediato."
                ),
                evidence="Set-Cookie headers (snippet):\n"
                + "\n".join(f"  {ln}" for ln in headers.splitlines() if "set-cookie" in ln.lower())[:600],
                remediation=(
                    "Setear HttpOnly en TODAS las session cookies. Por framework:\n"
                    "  - PHP: session.cookie_httponly = 1 en php.ini\n"
                    "  - Node.js Express: app.use(session({ cookie: { httpOnly: true }}))\n"
                    "  - Django: SESSION_COOKIE_HTTPONLY = True\n"
                    "  - Spring Boot: server.servlet.session.cookie.http-only=true\n"
                    "  - ASP.NET: <httpCookies httpOnlyCookies='true' /> in web.config\n"
                    "Banking: aplica a TODAS las cookies — auth, csrf-token, anti-bot, "
                    "tracking de session. Sin HttpOnly, XSS = full account takeover."
                ),
                severity_rank=_SEV_RANK["MEDIUM"],
            )
        )

    if cookies_missing_secure:
        findings.append(
            Finding(
                cwe="CWE-614",
                severity="MEDIUM",
                host=f"{svc.host}:{svc.port}",
                rule_id="http-cookie-missing-secure",
                message=(
                    f"Cookie(s) sin flag Secure en HTTPS {svc.host}:{svc.port}: "
                    f"{', '.join(cookies_missing_secure[:5])}. Cookie "
                    "transmissible sobre HTTP plain — MITM puede capturarla "
                    "si el cliente accidentalmente hits http://."
                ),
                evidence=f"HTTPS port {svc.port} returned Set-Cookie sin Secure flag: {cookies_missing_secure}",
                remediation=(
                    "Setear Secure en cookies en HTTPS endpoints:\n"
                    "  - PHP: session.cookie_secure = 1\n"
                    "  - Node.js Express: cookie: { secure: true }\n"
                    "  - Django: SESSION_COOKIE_SECURE = True\n"
                    "  - Spring Boot: server.servlet.session.cookie.secure=true\n"
                    "Adicional: HSTS header (Strict-Transport-Security: "
                    "max-age=31536000; includeSubDomains; preload) para "
                    "garantizar que el browser NUNCA hits http:// del dominio."
                ),
                severity_rank=_SEV_RANK["MEDIUM"],
            )
        )

    if cookies_missing_samesite:
        findings.append(
            Finding(
                cwe="CWE-1275",
                severity="LOW",
                host=f"{svc.host}:{svc.port}",
                rule_id="http-cookie-missing-samesite",
                message=(
                    f"Cookie(s) sin atributo SameSite en {svc.host}:{svc.port}: "
                    f"{', '.join(cookies_missing_samesite[:5])}. Riesgo CSRF "
                    "elevado si el endpoint acepta cross-origin requests."
                ),
                evidence=f"Set-Cookie sin SameSite: {cookies_missing_samesite}",
                remediation=(
                    "Setear SameSite=Lax (default seguro) o SameSite=Strict:\n"
                    "  - PHP: session.cookie_samesite = Lax\n"
                    "  - Node.js Express: cookie: { sameSite: 'lax' }\n"
                    "  - Django: SESSION_COOKIE_SAMESITE = 'Lax'\n"
                    "  - Spring Boot: server.servlet.session.cookie.same-site=lax\n"
                    "Para banking webapps, Strict es preferible salvo que "
                    "haya integraciones cross-origin legitimas."
                ),
                severity_rank=_SEV_RANK["LOW"],
            )
        )

    return findings


def _check_password_manager(svc: DiscoveredService) -> Finding | None:
    """Detect self-hosted password managers exposed in the segment.

    Surfaced by the Britimp POC pilot 2026-05-18 against .99, where the
    corporate Vaultwarden (`<title>Vaultwarden Web</title>`) was reachable
    from the data plane with only ssh-banner as the loudest signal —
    Kryon was treating it like any other HTTPS host.

    Severity HIGH (not CRITICAL — the asset is not vulnerable per se,
    it's an asset-value flag). The remediation walks the operator
    through the policy / segmentation review.
    """
    # Only meaningful for HTTP/HTTPS services. _check_http already gated
    # the caller to web ports, so this is a safety belt.
    if svc.service not in ("http", "https", "http-proxy") and svc.port not in (
        80,
        443,
        8080,
        8443,
        4443,
        9443,
    ):
        return None

    scheme = "https" if svc.port in (443, 8443, 4443, 9443) else "http"
    code, body = _http_get(f"{scheme}://{svc.host}:{svc.port}/")
    if code == 0 or not body:
        return None

    for rx, short_id, pretty in _PASSWORD_MANAGER_SIGNATURES:
        if rx.search(body):
            return Finding(
                cwe="CWE-668",  # Exposure of Resource to Wrong Sphere
                severity="HIGH",
                host=f"{svc.host}:{svc.port}",
                rule_id=f"password-manager-{short_id}",
                message=(
                    f"{pretty} detectado en {svc.host}:{svc.port}. "
                    "Asset de altísimo valor (gestor de credenciales corporativo) accesible desde "
                    "el segmento auditado. Una compromise de este host expone TODAS las "
                    "credenciales del equipo."
                ),
                evidence=f"GET {scheme}://{svc.host}:{svc.port}/ → {code}\n\nMatched signature: {rx.pattern}",
                remediation=(
                    "1. Revisar segmentación: el password manager debería vivir en una VLAN de gestión\n"
                    "   dedicada, no en el segmento de servidores generales.\n"
                    "2. Verificar TLS: certificado de CA confiable (no autofirmado) + HSTS preload.\n"
                    "3. Verificar versión: cross-ref con CVE database del fabricante:\n"
                    "   - Vaultwarden: CVE-2024-39926 (Webauthn bypass), CVE-2023-27924\n"
                    "   - Bitwarden: revisar advisories.bitwarden.com\n"
                    "   - Passbolt: passbolt.com/security/advisories\n"
                    "4. Forzar MFA (TOTP, Webauthn, Duo) en cada cuenta — sin excepción.\n"
                    "5. Auditar usuarios admin: deben ser ≤ 2, con accounts dedicadas (no email personal).\n"
                    "6. Backup encriptado off-site + procedimiento de recovery documentado.\n"
                    "7. Monitoreo: alertar en cada login admin + cada fallo de auth.\n"
                    "8. Considerar SaaS (1Password Business, Bitwarden Cloud) si la operación no\n"
                    "   puede asumir las responsabilidades de self-hosting."
                ),
                severity_rank=_SEV_RANK["HIGH"],
            )
    return None


def _http_get(url: str, *, timeout_s: int = 5) -> tuple[int, str]:
    """GET `url` via curl. Returns (status_code, body[:65536]).

    Uses `-k` to accept self-signed TLS — audit tooling must reach
    the service even when the cert is invalid (very common for
    internal admin panels, password managers, BMC web UIs).
    F202.M (POC Britimp .106 2026-05-19): use `--compressed` so curl
    auto-decompresses gzip/deflate/br responses. Without it, hosts
    that return `Content-Encoding: gzip` come back as binary bytes
    that never match the text-based body markers (Hikvision
    login.asp, Vaultwarden title, password-manager signatures, etc).
    Returns (0, '') on any error so callers can degrade gracefully.
    """
    try:
        proc = subprocess.run(
            [
                "curl",
                "-sS",
                "-k",
                "--compressed",
                # F202.S.B: --max-redirs 0 evita SSRF via Location header
                # malicioso (file://, http://169.254.169.254/ metadata,
                # http://internal-svc/). Sin esto, curl sigue hasta 30
                # redirects por default y puede exfiltrar a metadata
                # endpoints o servicios internos no autorizados.
                "--max-redirs",
                "0",
                "--max-time",
                str(timeout_s),
                "-w",
                "\n__HTTPCODE__%{http_code}",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_s + 2,
            check=False,
        )
        out = proc.stdout
        marker = "__HTTPCODE__"
        idx = out.rfind(marker)
        if idx >= 0:
            try:
                code = int(out[idx + len(marker) :].strip())
            except ValueError:
                code = 0
            body = out[:idx]
        else:
            code = 0
            body = out
        return code, body[:65536]
    except Exception:  # noqa: BLE001 — collapse all curl errors to (0, "")
        return 0, ""


_PYTHON_SIMPLEHTTP_SERVER_RE = re.compile(r"^Server:\s*SimpleHTTP/[\d.]+\s+Python/[\d.]+", re.MULTILINE | re.IGNORECASE)
_DIRECTORY_LISTING_RE = re.compile(r"<title>Directory listing for ", re.IGNORECASE)


def _check_python_simplehttp_exposed(svc: DiscoveredService) -> Finding | None:
    """F199.J — `python -m http.server` running on a production network.

    Surfaced by the Britimp POC pilot on 2026-05-18 against TORRE_SVR.200,
    where the Proxmox host had `python -m http.server 8888` left over from
    a VM migration — exposing the full `sgapp-temp-flat.vmdk` to anyone
    reachable on the segment.

    This is a CRITICAL data-exfiltration vector even though the generic
    http-plaintext check already flags the port: an attacker doesn't need
    to compromise auth or run an exploit — `curl http://target:port/file`
    is enough to walk away with the entire VM image (filesystem +
    credentials + DB dumps + private keys).

    Detection signature:
      1. HTTP response header: `Server: SimpleHTTP/X.X Python/Y.Y`
      2. GET / body contains `<title>Directory listing for ...`
    Both required — the Python http.server can be repurposed by users to
    serve a single file with a custom handler, in which case directory
    listing is off and the risk is lower.
    """
    try:
        headers_proc = subprocess.run(
            ["curl", "-sSI", "--max-time", "5", f"http://{svc.host}:{svc.port}/"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        headers = headers_proc.stdout or ""
    except Exception:  # noqa: BLE001
        return None

    if not _PYTHON_SIMPLEHTTP_SERVER_RE.search(headers):
        return None

    # Server header matches — fetch body to confirm directory listing.
    try:
        body_proc = subprocess.run(
            ["curl", "-sS", "--max-time", "5", f"http://{svc.host}:{svc.port}/"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        body = body_proc.stdout or ""
    except Exception:  # noqa: BLE001
        body = ""

    if not _DIRECTORY_LISTING_RE.search(body):
        # Server header matches but no directory listing → custom handler.
        # Still worth flagging at HIGH (Python http.server in prod is unusual)
        # but not the CRITICAL CRITICAL of unauthenticated dirlist.
        return Finding(
            cwe="CWE-200",
            severity="HIGH",
            host=f"{svc.host}:{svc.port}",
            rule_id="python-simplehttp-exposed",
            message=(
                f"`python -m http.server` (or BaseHTTPServer variant) detected on {svc.host}:{svc.port} "
                "— directory listing off but Python's reference HTTP server has no security guarantees "
                "for production."
            ),
            evidence=headers[:400],
            remediation=(
                "Replace with a hardened web server (nginx, Caddy, Apache) behind TLS + auth. "
                "Python's http.server module documentation explicitly says: 'It is not recommended "
                "to use this on the internet.'"
            ),
            severity_rank=_SEV_RANK["HIGH"],
        )

    # CRITICAL: server header + open directory listing = data exfiltration vector.
    # Pull a short body snippet for the evidence so the report shows what's exposed.
    body_snippet = body[:600]
    return Finding(
        cwe="CWE-548",  # Information Exposure Through Directory Listing
        severity="CRITICAL",
        host=f"{svc.host}:{svc.port}",
        rule_id="python-simplehttp-directory-listing",
        message=(
            f"`python -m http.server` running on {svc.host}:{svc.port} with open directory listing — "
            "anyone on the segment can download all files in the served directory without "
            "authentication. Probable cause: VM migration / backup tooling left running in production."
        ),
        evidence=f"Server: SimpleHTTP detected + Directory listing exposed.\n\nSample body:\n{body_snippet}",
        remediation=(
            "1. INMEDIATO: stop the python http.server process:\n"
            "   ssh <host> 'pgrep -af \"http.server\" && pkill -f http.server'\n"
            "2. Investigate what was served and whether the files contain sensitive data:\n"
            "   - VM disk images (.vmdk / .qcow2 / .vdi) — credenciales en filesystem\n"
            "   - DB dumps, code archives, log bundles\n"
            "3. Audit who could have downloaded the files (firewall logs, iptables LOG, network IDS).\n"
            "4. Replace with a hardened transfer mechanism: scp+sftp, rsync over SSH, signed-URL\n"
            "   object storage. Never expose `python -m http.server` on a production network."
        ),
        severity_rank=_SEV_RANK["CRITICAL"],
    )


# F202.A — DNS open resolver detection.
# Surfaced by Britimp POC .205 (Domain Controller britimp.com.py): the
# DNS server responded to recursive queries from the operator VPN for
# external domains (google.com resolved successfully). If the perimeter
# firewall allows UDP/53 from internet to this server, it becomes a
# DNS amplification DDoS reflector (response >> query, ~50x factor).
# From inside the network we cannot prove external reachability, so
# the finding is MEDIUM and the remediation points to ACL review at
# both the DNS service and the perimeter firewall.
_DNS_EXTERNAL_PROBE = "google.com"

_DNS_FAILURE_MARKERS = (
    "non-existent domain",
    "nxdomain",
    "server failed",
    "refused",
    "no response",
    "request timed out",
    "can't find",
    "timed out",
)

_RFC1918_PREFIXES: tuple[str, ...] = (
    "10.",
    "192.168.",
    "127.",
    "169.254.",
) + tuple(f"172.{n}." for n in range(16, 32))


def _is_external_ipv4(ip: str, target_host: str) -> bool:
    """Return True when `ip` is NOT in RFC1918 / loopback / link-local
    AND not the DNS server itself. F202.A helper.
    """
    if ip == target_host:
        return False
    return not any(ip.startswith(p) for p in _RFC1918_PREFIXES)


def _check_dns_open_resolver(svc: DiscoveredService) -> Finding | None:
    """F202.A — Probe a DNS server for recursion on external names.

    A correctly configured internal DNS either disables recursion for
    external clients entirely (BIND `allow-recursion`) or refuses to
    forward to upstream when the query is for a domain it isn't
    authoritative for. Microsoft DNS on AD DCs has recursion ON by
    default and the operator must scope it via ACL or perimeter.

    Method: nslookup an external domain (`google.com` — extremely
    unlikely to be a zone on the internal DNS). If we get a public
    IPv4 back, recursion is happening on our behalf and the only
    thing standing between this server and internet is the firewall.
    """
    if svc.state != "open" or svc.port != 53:
        return None

    try:
        proc = subprocess.run(
            ["nslookup", _DNS_EXTERNAL_PROBE, svc.host],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # F202.A error handling: granular instead of bare except.
        # TimeoutExpired = network slow / DNS down
        # FileNotFoundError = nslookup missing in PATH
        # OSError = network unreachable
        return None
    except Exception:  # noqa: BLE001 — consistent with other DNS checks
        return None

    out = (proc.stdout + "\n" + proc.stderr).lower()
    if any(m in out for m in _DNS_FAILURE_MARKERS):
        return None

    addrs = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", proc.stdout)
    external = [a for a in addrs if _is_external_ipv4(a, svc.host)]
    if not external:
        return None

    return Finding(
        cwe="CWE-406",
        severity="MEDIUM",
        host=f"{svc.host}:{svc.port}",
        rule_id="dns-open-resolver",
        message=(
            f"DNS server {svc.host}:53 acepta queries recursivas de clientes arbitrarios "
            f"(resolvio {_DNS_EXTERNAL_PROBE} -> {external[0]})."
        ),
        evidence=(f"nslookup {_DNS_EXTERNAL_PROBE} {svc.host} resolvio IP(s) externa(s): {', '.join(external[:3])}"),
        remediation=(
            "Restringir recursion a subnets internas y revisar perimetro.\n"
            "  - Microsoft DNS: dnsmgmt.msc > Properties > Advanced > "
            "'Disable recursion (also disables forwarders)' o usar "
            "Set-DnsServerRecursionScope -Name '.' -EnableRecursion $false y "
            "habilitarlo solo por scope con ACL.\n"
            "  - BIND: views { internal { match-clients { 10.0.0.0/8; "
            "172.16.0.0/12; 192.168.0.0/16; }; recursion yes; }; "
            "external { match-clients { any; }; recursion no; }; };\n"
            "  - Unbound: access-control: 0.0.0.0/0 refuse + "
            "access-control: <internal_subnet> allow_recursive\n"
            "Perimetro: firewall DEBE bloquear UDP/53 + TCP/53 desde "
            "internet hacia este DNS salvo que sea publico autoritativo. "
            "Sin esa restriccion el servidor funciona como amplificador "
            "DNS para ataques DDoS (factor ~50x con queries ANY o DNSSEC)."
        ),
        severity_rank=_SEV_RANK["MEDIUM"],
    )


# F202.B — DNS zone transfer (AXFR) detection.
# CWE-200 (info disclosure) + CWE-668 (exposure to wrong sphere). A
# successful AXFR from an arbitrary client exposes the FULL list of
# A / AAAA / SRV / TXT / MX records — a complete map of the internal
# environment including hostnames, IPs, mail servers, SPF/DMARC, and
# any custom TXT secrets the operator embedded. AXFR runs over TCP/53.
#
# Severity HIGH (not CRITICAL because no auth bypass), but the recon
# value to an attacker is huge — the rest of the engagement gets
# trivialized once they have the zone.


# Record-type tokens that indicate a successful zone dump.
_AXFR_RECORD_TYPE_RE = re.compile(
    r"\b(SOA|NS|A|AAAA|MX|CNAME|TXT|PTR|SRV)\b",
    re.IGNORECASE,
)

# Failure markers across dig + nslookup output.
_AXFR_FAILURE_MARKERS = (
    "transfer failed",
    "; transfer failed",
    "communications error",
    "query refused",
    "refused.",
    "; refused",
    "connection refused",
    "denied",
    "operation refused",
    "request timed out",
    "no answer",
    "couldn't get address",
    "host not found",
    "no records",
)


def _derive_dns_zone_candidates(host: str) -> list[str]:
    """F202.B helper — derive candidate zone names to attempt AXFR on.

    Strategy:
      1. PTR query: ask the target for its own PTR record. If it
         returns `dc01.britimp.com.py.` we extract `britimp.com.py`.
      2. Reverse zone: build the in-addr.arpa zone from the target IP
         (e.g. 172.18.201.205 -> `201.18.172.in-addr.arpa`).
      3. Common AD suffixes — `localdomain`, `local`.

    Returns ordered candidates (PTR-derived first, reverse second).
    Deduplicated, lowercased.
    """
    candidates: list[str] = []

    # 1. PTR lookup on the DNS server itself.
    try:
        proc = subprocess.run(
            ["nslookup", host, host],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
        # PTR response line looks like:
        #   Name:    dc01.britimp.com.py
        # Strip the leftmost label (hostname) to derive the zone.
        for line in proc.stdout.splitlines():
            m = re.search(r"^\s*Name\s*:\s*(\S+)", line, re.IGNORECASE)
            if not m:
                continue
            full = m.group(1).rstrip(".").lower()
            labels = full.split(".")
            if len(labels) >= 2:
                zone = ".".join(labels[1:])
                if zone and zone not in candidates:
                    candidates.append(zone)
    except Exception:  # noqa: BLE001
        pass

    # 2. Reverse in-addr.arpa zone.
    octets = host.split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        rev = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
        if rev not in candidates:
            candidates.append(rev)

    return candidates


def _try_axfr(host: str, zone: str) -> tuple[bool, str]:
    """F202.B helper — attempt AXFR for `zone` against `host`. Returns
    (success, evidence_snippet).

    Tries `dig` first (richer output, structured), falls back to
    `nslookup -type=AXFR` (universally available on Windows). Both
    are read-only DNS queries — no side effects on the target.
    """
    commands = (
        ["dig", "+time=4", "+tries=1", f"@{host}", "AXFR", zone],
        ["nslookup", "-type=AXFR", zone, host],
    )

    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
        except Exception:  # noqa: BLE001
            continue

        out = proc.stdout + "\n" + proc.stderr
        out_lower = out.lower()

        if any(m in out_lower for m in _AXFR_FAILURE_MARKERS):
            continue

        # Count record-type-bearing lines. >=3 distinct records is the
        # threshold: SOA + at least 2 non-SOA entries is a real zone
        # dump, not an isolated SOA query reply.
        record_lines = [ln for ln in proc.stdout.splitlines() if _AXFR_RECORD_TYPE_RE.search(ln)]
        if len(record_lines) >= 3:
            snippet = "\n".join(record_lines[:6])
            return True, snippet

    return False, ""


def _check_dns_zone_transfer(svc: DiscoveredService) -> Finding | None:
    """F202.B — Probe a DNS server for AXFR exposure.

    Discovers candidate zones from the server's own PTR + the reverse
    in-addr.arpa zone, then attempts AXFR on each. Bails out on any
    failure marker (refused / denied / timeout). Reports HIGH when at
    least one zone transfers successfully with >=3 records.
    """
    if svc.state != "open" or svc.port != 53:
        return None

    zones = _derive_dns_zone_candidates(svc.host)
    if not zones:
        return None

    transferable: list[tuple[str, str]] = []
    for zone in zones[:4]:  # cap attempts to keep latency bounded
        ok, snippet = _try_axfr(svc.host, zone)
        if ok:
            transferable.append((zone, snippet))

    if not transferable:
        return None

    leaked_zones = ", ".join(z for z, _ in transferable[:3])
    evidence_blocks = "\n\n".join(f"Zone {zone}:\n{snippet}" for zone, snippet in transferable[:2])

    return Finding(
        cwe="CWE-200",
        severity="HIGH",
        host=f"{svc.host}:{svc.port}",
        rule_id="dns-axfr-allowed",
        message=(
            f"DNS server {svc.host}:53 permite AXFR (zone transfer) "
            f"sin restriccion para zona(s): {leaked_zones}. Expone el "
            "mapa completo de hostnames, IPs, SPF/DMARC y TXT records "
            "internos a cualquier cliente con TCP/53 alcanzable."
        ),
        evidence=evidence_blocks[:1200],
        remediation=(
            "Restringir AXFR a servidores secundarios autorizados unicamente.\n"
            "  - Microsoft DNS: dnsmgmt.msc > <zona> > Properties > Zone "
            "Transfers > 'Only to servers listed on the Name Servers tab' "
            "o 'Only to the following servers' con IPs explicitas.\n"
            '  - BIND: zone "example.com" { allow-transfer { 10.0.0.5; '
            "10.0.0.6; }; }; (vacio = deny por default desde 9.4+).\n"
            "  - Unbound: no aplica (Unbound es solo recursor; AXFR "
            "no esta soportado).\n"
            "Perimetro: firewall DEBE bloquear TCP/53 desde internet hacia "
            "este DNS salvo secondaries autorizados.\n"
            "Post-remediation verify: dig @<host> AXFR <zona> debe retornar "
            "'Transfer failed' o 'communications error end of file'."
        ),
        severity_rank=_SEV_RANK["HIGH"],
    )


# F202.C — DNS CHAOS class info disclosure.
# BIND / Unbound / PowerDNS expose debug data through CHAOS class TXT
# queries by default (must be explicitly suppressed):
#   - `version.bind` TXT CH       -> server version string (BIND, Unbound)
#   - `version.server` TXT CH     -> alternative version probe
#   - `hostname.bind` TXT CH      -> internal hostname (BIND)
#   - `id.server` TXT CH          -> server identity (RFC 4892, common in
#                                    anycast / CDN DNS like Cloudflare)
# Version disclosure feeds CVE matching (e.g. BIND 9.18.x -> CVE-2023-3341
# stack-exhaust). Hostname/id leaks expose internal infrastructure naming
# convention. Microsoft DNS does NOT respond to CHAOS class by default —
# this check primarily catches BIND / Unbound / PowerDNS instances.

_DNS_CHAOS_PROBES: tuple[tuple[str, str], ...] = (
    ("version.bind", "version del servidor DNS"),
    ("version.server", "version del servidor (RFC 4892 alternative)"),
    ("hostname.bind", "hostname interno del DNS"),
    ("id.server", "server identity (RFC 4892)"),
)

_DNS_CHAOS_FAILURE_MARKERS = (
    "non-existent domain",
    "nxdomain",
    "server failed",
    "refused",
    "no response",
    "request timed out",
    "can't find",
    "timed out",
    "no answer",
)


def _try_chaos_query(host: str, name: str) -> str | None:
    """F202.C helper — attempt a CHAOS class TXT query. Returns the TXT
    value if the server replies, or None on any failure / empty answer.
    """
    try:
        proc = subprocess.run(
            ["nslookup", "-class=chaos", "-type=txt", name, host],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
    except Exception:  # noqa: BLE001
        return None

    out = proc.stdout + "\n" + proc.stderr
    out_lower = out.lower()
    if any(m in out_lower for m in _DNS_CHAOS_FAILURE_MARKERS):
        return None

    # Match `text = "value"` (Windows nslookup) or `name TXT "value"`
    # (dig-style); we accept the broader regex.
    m = re.search(r'(?:text|TXT)\s*=?\s*"([^"]+)"', proc.stdout, re.IGNORECASE)
    if m:
        value = m.group(1).strip()
        if value:
            return value
    return None


def _check_dns_chaos_leak(svc: DiscoveredService) -> Finding | None:
    """F202.C — Probe a DNS server for CHAOS class info disclosure.

    Tries the four canonical CHAOS TXT probes (version.bind,
    version.server, hostname.bind, id.server). Reports the leaks with
    severity MEDIUM when hostname/id is exposed (internal recon
    payload), LOW when only version is leaked.
    """
    if svc.state != "open" or svc.port != 53:
        return None

    leaks: list[tuple[str, str]] = []
    for probe_name, _probe_label in _DNS_CHAOS_PROBES:
        value = _try_chaos_query(svc.host, probe_name)
        if value:
            leaks.append((probe_name, value))

    if not leaks:
        return None

    hostname_leak = any(p in ("hostname.bind", "id.server") for p, _ in leaks)
    severity = "MEDIUM" if hostname_leak else "LOW"

    evidence_lines = [f"  {probe} CH TXT -> {value}" for probe, value in leaks]
    evidence = "\n".join(evidence_lines)
    leaked_probes = ", ".join(probe for probe, _ in leaks)

    return Finding(
        cwe="CWE-200",
        severity=severity,
        host=f"{svc.host}:{svc.port}",
        rule_id="dns-chaos-leak",
        message=(f"DNS server {svc.host}:53 responde a queries CHAOS class y revela info debug: {leaked_probes}."),
        evidence=evidence[:800],
        remediation=(
            "Suprimir respuestas CHAOS class en el motor DNS:\n"
            '  - BIND named.conf: options { version ""; hostname ""; '
            'server-id ""; };\n'
            "  - Unbound: server: hide-version: yes + hide-identity: yes\n"
            "  - PowerDNS recursor.conf: version-string=anonymous + server-id=disabled\n"
            "  - Knot Resolver: options.cache_size + nsid module disabled\n"
            "  - Microsoft DNS: no responde a CHAOS class por default — "
            "este leak indica que el motor NO es Windows DNS (probable BIND "
            "u otro abierto en TCP/53).\n"
            "Aunque el leak parece menor, version disclosure facilita CVE "
            "matching (ej. BIND 9.18.x -> CVE-2023-3341 stack-exhaust, "
            "Unbound 1.13.x -> CVE-2021-37207). Hostname/id leaks revelan "
            "naming convention interna y son recon barato.\n"
            "Verificar post-fix: nslookup -class=chaos -type=txt version.bind "
            "<host> debe retornar Refused o NXDOMAIN."
        ),
        severity_rank=_SEV_RANK[severity],
    )


# F202.D — DNS cache snooping (privacy leak).
# Sending a query with RD=0 (recursion-not-desired) + CD=1 (checking
# disabled) to a recursor causes it to answer ONLY if the name is
# already cached. By probing a curated list of SaaS / banking / social
# domains and observing which ones return an ANSWER SECTION, an
# attacker fingerprints what services the internal users consume.
# Impact: privacy disclosure + phishing-target identification +
# competitive-intelligence (which vendors the org uses).
#
# Severity: MEDIUM. The recursor itself isn't broken; it's a privacy
# config gap. Microsoft DNS exposes this by default; BIND with
# `allow-query-cache { internal; };` mitigates it.
#
# Banca-safe: 12 read-only DNS probes per target. Total ~30s with
# 3s timeout each in serial. Banking POC explicitly authorized for
# this kind of recon.

_DNS_SNOOP_PROBES: tuple[str, ...] = (
    # SaaS frecuente en empresas — Microsoft 365 stack
    "outlook.office365.com",
    "login.microsoftonline.com",
    # SaaS general
    "slack.com",
    "dropbox.com",
    "github.com",
    # Banking Paraguay (Britimp context)
    "bcp.com.py",
    "bancard.com.py",
    "mercadopago.com.py",
    # Payments global
    "stripe.com",
    # Personal / social — uso en horario laboral = leak
    "whatsapp.com",
    "instagram.com",
    "tiktok.com",
)

# Minimum cached hits to flag — single hit could be coincidence
# (a recursor's own forwarder warming the cache). >=2 means the
# internal users are actually consuming these services.
_DNS_SNOOP_THRESHOLD = 2

_DNS_SNOOP_DIG_FAILURE_MARKERS = (
    "status: refused",
    "connection timed out",
    "connection refused",
    "communications error",
    "no servers could be reached",
    "couldn't get address",
)

_DIG_ANSWER_SECTION_RE = re.compile(
    r";;\s*answer\s+section\s*:\s*\n((?:[^\n;].*\n)+)",
    re.IGNORECASE,
)


def _try_cache_snoop(host: str, name: str) -> bool | None:
    """F202.D helper — probe whether `name` is cached on the target
    recursor using dig +norecurse +cd.

    Returns:
      - True  -> name is in cache (ANSWER SECTION contains an A record)
      - False -> name is NOT cached (no ANSWER SECTION, but server replied)
      - None  -> probe could not be performed (dig missing / refused /
                 timeout). Caller treats None as "skip this probe".
    """
    try:
        proc = subprocess.run(
            [
                "dig",
                "+norecurse",
                "+cd",
                "+time=3",
                "+tries=1",
                f"@{host}",
                name,
                "A",
            ],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except FileNotFoundError:
        # dig not installed — we cannot perform this check on Windows
        # without it. Caller will see None and skip cleanly.
        return None
    except Exception:  # noqa: BLE001
        return None

    out = proc.stdout + "\n" + proc.stderr
    out_lower = out.lower()

    if any(m in out_lower for m in _DNS_SNOOP_DIG_FAILURE_MARKERS):
        return None

    m = _DIG_ANSWER_SECTION_RE.search(out)
    if not m:
        return False  # no answer section = not cached, but server replied

    answer_block = m.group(1)
    # ANSWER must contain the queried name AND an A record IPv4 form.
    if name.lower() in answer_block.lower() and re.search(r"\bA\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", answer_block):
        return True
    return False


def _check_dns_cache_snoop(svc: DiscoveredService) -> Finding | None:
    """F202.D — Probe for DNS cache snooping. Reports MEDIUM when at
    least `_DNS_SNOOP_THRESHOLD` curated domains return cached
    answers from a non-recursive query.
    """
    if svc.state != "open" or svc.port != 53:
        return None

    cached_hits: list[str] = []
    probe_attempted = 0
    probe_succeeded = 0  # number of probes where the server actually
    # replied (cached or not). If 0, dig is unavailable and we can't
    # determine anything — skip the check silently.

    for probe in _DNS_SNOOP_PROBES:
        result = _try_cache_snoop(svc.host, probe)
        probe_attempted += 1
        if result is None:
            continue
        probe_succeeded += 1
        if result is True:
            cached_hits.append(probe)

    # Bail if dig is unavailable on this host (all probes returned None).
    if probe_succeeded == 0:
        return None

    if len(cached_hits) < _DNS_SNOOP_THRESHOLD:
        return None

    leaked_summary = ", ".join(cached_hits[:5])
    if len(cached_hits) > 5:
        leaked_summary += f", + {len(cached_hits) - 5} more"

    return Finding(
        cwe="CWE-200",
        severity="MEDIUM",
        host=f"{svc.host}:{svc.port}",
        rule_id="dns-cache-snoop",
        message=(
            f"DNS recursor {svc.host}:53 vulnerable a cache snooping: "
            f"{len(cached_hits)} dominio(s) curados estan cacheados y "
            f"detectables con queries RD=0. Filtra que servicios SaaS / "
            f"banking / social consume la organizacion. Dominios "
            f"cacheados detectados: {leaked_summary}."
        ),
        evidence=(
            f"dig +norecurse +cd @{svc.host} <domain> A retorno ANSWER SECTION para:\n  - " + "\n  - ".join(cached_hits)
        ),
        remediation=(
            "Aislar el cache recursor de queries no autorizadas.\n"
            "  - Microsoft DNS: dnsmgmt.msc > server > Properties > "
            "Advanced > 'Secure cache against pollution' + scoping de "
            "recursion (ACL Set-DnsServerRecursionScope).\n"
            "  - BIND: views { internal { match-clients { 10.0.0.0/8; "
            "}; recursion yes; allow-query-cache { internal; }; }; "
            "external { match-clients { any; }; recursion no; "
            "allow-query-cache { none; }; }; };\n"
            "  - Unbound: access-control: 0.0.0.0/0 deny + "
            "access-control: <internal_subnet> allow + "
            "cache-min-ttl: 0 (forzar lookup fresco para sensitive "
            "names si privacy es critica).\n"
            "Idealmente este DNS solo responde queries de subnets "
            "internas; el cache snooping requiere TCP/UDP 53 desde "
            "internet con ACL al recursor.\n"
            "Privacy impact: el cache filtra que dominios consume la "
            "org. Combinado con timing analysis (TTLs) se puede "
            "inferir patrones de uso y horarios. Recon barato pre-phishing."
        ),
        severity_rank=_SEV_RANK["MEDIUM"],
    )


# F202.E — DNSSEC validation status check (CWE-345).
# DNSSEC adds cryptographic signatures over DNS records so the resolver
# can prove the answer hasn't been tampered with. A resolver may:
#   - "support" DNSSEC (forward signatures, set AD flag from upstream)
#     yet NOT actually validate them itself.
#   - have validation explicitly disabled (Microsoft DNS pre-2016,
#     BIND with `dnssec-validation no;`, Unbound without validator).
#
# Without validation, the resolver accepts spoofed answers that claim
# the zone is unsigned even when it isn't. Kaminsky-style cache
# poisoning + MITM (rogue Wi-Fi, compromised ISP) become viable
# against any client behind this resolver.
#
# Probe technique: query Verisign's `dnssec-failed.org` (a domain that
# intentionally serves invalid DNSSEC signatures). A validating
# resolver MUST return SERVFAIL; a non-validating resolver happily
# returns the IP records.

_DNSSEC_TEST_DOMAIN = "dnssec-failed.org"

_DNSSEC_VALID_MARKERS = (
    "server failed",  # nslookup phrasing when SERVFAIL is returned
    "servfail",
    "broken",
    "no answer",
    "dnssec validation failed",
)

_DNSSEC_INCONCLUSIVE_MARKERS = (
    "no response",
    "request timed out",
    "timed out",
    "communications error",
    "non-existent domain",  # zone might be temporarily down
    "nxdomain",
    "couldn't get address",
)


def _check_dnssec_validation(svc: DiscoveredService) -> Finding | None:
    """F202.E — Probe a recursor for DNSSEC validation.

    Methodology:
      1. Query `dnssec-failed.org` (broken-by-design DNSSEC).
      2. If we get SERVFAIL -> validation works -> no finding.
      3. If we get a non-loopback IPv4 answer -> NO validation ->
         flag MEDIUM CWE-345.
      4. If we get timeout / NXDOMAIN -> can't determine -> no
         finding (avoid false positive when network blocks the
         probe).
    """
    if svc.state != "open" or svc.port != 53:
        return None

    try:
        proc = subprocess.run(
            ["nslookup", _DNSSEC_TEST_DOMAIN, svc.host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:  # noqa: BLE001
        return None

    out = proc.stdout + "\n" + proc.stderr
    out_lower = out.lower()

    # GOOD outcome — validation works.
    if any(m in out_lower for m in _DNSSEC_VALID_MARKERS):
        return None

    # INCONCLUSIVE — probe couldn't be performed cleanly.
    if any(m in out_lower for m in _DNSSEC_INCONCLUSIVE_MARKERS):
        return None

    # Look for non-loopback IPv4 answers. If present, the resolver
    # returned the broken-DNSSEC zone records -> validation OFF.
    addrs = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", proc.stdout)
    external = [a for a in addrs if a != svc.host and not a.startswith("127.") and not a.startswith("0.")]
    if not external:
        return None

    return Finding(
        cwe="CWE-345",
        severity="MEDIUM",
        host=f"{svc.host}:{svc.port}",
        rule_id="dnssec-validation-disabled",
        message=(
            f"DNS recursor {svc.host}:53 NO valida DNSSEC: resolvio "
            f"{_DNSSEC_TEST_DOMAIN} (Verisign domain con firma rota a "
            f"proposito) a {external[0]}. Un recursor con validacion "
            "habilitada habria retornado SERVFAIL. Vulnerable a "
            "cache poisoning + MITM injection."
        ),
        evidence=(
            f"nslookup {_DNSSEC_TEST_DOMAIN} {svc.host} retorno IP(s) "
            f"cuando deberia retornar SERVFAIL: {', '.join(external[:3])}"
        ),
        remediation=(
            "Habilitar validacion DNSSEC en el recursor:\n"
            "  - Microsoft DNS (W2016+): Set-DnsServerSetting "
            "-EnableDnsSec $true. Verificar tambien que los Trust "
            "Anchors esten actualizados (Get-DnsServerTrustAnchor).\n"
            "  - BIND: options { dnssec-validation auto; }; (default "
            "desde 9.16+). Con `auto` el resolver usa los root trust "
            "anchors built-in.\n"
            '  - Unbound: server: module-config: "validator iterator" '
            "+ auto-trust-anchor-file (default /var/lib/unbound/root.key).\n"
            "  - Knot Resolver: trust_anchors.add_file('root.key') o "
            "trust_anchors.set_insecure() solo para zonas problematicas.\n"
            "Impacto: sin validacion, atacante MITM (red interna, ISP "
            "comprometido, rogue Wi-Fi adyacente al recursor) puede "
            "inyectar respuestas falsas via Kaminsky-style cache "
            "poisoning. Records sensibles: MX (email phishing), banking "
            "domains (man-in-the-middle de portales), SaaS endpoints "
            "(token harvesting). NIST 800-81-2 lo recomienda como baseline.\n"
            "Verificar post-fix: nslookup dnssec-failed.org <host> debe "
            "retornar 'Server failed' (SERVFAIL)."
        ),
        severity_rank=_SEV_RANK["MEDIUM"],
    )


# F202.F — DNS reverse zone enumeration check (CWE-200).
# A DNS server that resolves PTR records for an entire /24 reveals
# internal hostname conventions. Even without zone transfer (F202.B
# blocked) an attacker can walk the subnet IP-by-IP via PTR queries:
#   nslookup 172.18.201.5 <dns>  -> dc02.britimp.com.py
#   nslookup 172.18.201.50 <dns> -> bastion-ubuntu.britimp.com.py
#   nslookup 172.18.201.150 <dns> -> postgres-prod.britimp.com.py
# In banking: names like "core-banking-db" / "swift-gateway" /
# "payments-prod" become the high-value target list.
#
# Severity:
#   - MEDIUM when only generic internal hostnames leak (dc, mail)
#   - HIGH when sensitive function keywords leak (banking, payment,
#     swift, prod, db, vault)
#
# Banca-safe: 10 PTR queries per target, total <20s with 2s
# timeout. POC bancario autoriza este recon explicitamente.

# Deterministic octet sample (no full /24 sweep). Targets the
# common high-value IPs: gateway range (1-5), DC range (5-10),
# bastion range (50, 100), DB range (150, 200), and final
# host before broadcast (254).
_REVERSE_PROBE_OCTETS: tuple[int, ...] = (
    1,
    5,
    10,
    20,
    50,
    100,
    150,
    200,
    222,
    254,
)
_REVERSE_HIT_THRESHOLD = 3

# Function-revealing keywords that elevate the finding to HIGH.
# Lowercase; matched as substrings of the hostname.
_SENSITIVE_HOSTNAME_KEYWORDS: tuple[str, ...] = (
    # Banking / payments / SWIFT
    "bank",
    "banco",
    "payment",
    "pago",
    "swift",
    "ach",
    "bancard",
    "stripe",
    "mastercard",
    "visa",
    "core-bank",
    "corebank",
    # Production / database
    "prod",
    "production",
    "produccion",
    "db-",
    "-db.",
    "sql-",
    "-sql.",
    "rds-",
    "postgres",
    "mongo",
    "redis",
    "oracle",
    "backup",
    "bkp",
    # Identity / secrets / AD
    "ldap",
    "ad-",
    "-ad.",
    "dc-",
    "-dc.",
    "vault",
    "secret",
    "kdc",
    # Mail / exchange
    "exchange",
    "mail-",
    "-mail.",
    "smtp",
    # File / share
    "fileserver",
    "share-",
)

_REVERSE_FAILURE_MARKERS = (
    "can't find",
    "non-existent domain",
    "nxdomain",
    "server failed",
    "request timed out",
    "timed out",
    "no response",
    "refused",
)


def _try_ptr_query(host: str, ip: str) -> str | None:
    """F202.F helper — probe a single PTR record. Returns the
    resolved hostname (lowercased, no trailing dot) or None on
    failure / NXDOMAIN / refused.
    """
    try:
        proc = subprocess.run(
            ["nslookup", ip, host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:  # noqa: BLE001
        return None

    out = proc.stdout + "\n" + proc.stderr
    out_lower = out.lower()
    if any(m in out_lower for m in _REVERSE_FAILURE_MARKERS):
        return None

    # Windows nslookup PTR response shape:
    #   Server:  UnKnown
    #   Address:  172.18.201.205
    #
    #   Name:    dc01.britimp.com.py
    #   Address:  172.18.201.205
    # Match the `Name:    <fqdn>` line; ignore the server identity line.
    for line in proc.stdout.splitlines():
        m = re.search(r"^\s*Name\s*:\s*(\S+)", line, re.IGNORECASE)
        if not m:
            continue
        name = m.group(1).rstrip(".").lower()
        # Skip echo of the DNS server's own hostname / synthetic
        # responses (e.g. the server identity line).
        if "." not in name:
            continue
        return name
    return None


def _is_generic_ptr(hostname: str, ip: str) -> bool:
    """A 'generic' PTR is one whose label is just the IP digits in
    some encoding (e.g. `1-2-3-4.dyn.isp.net`, `host-172-18-201-5.x`,
    `5.201.18.172.in-addr.arpa`). These don't expose internal
    naming conventions and we shouldn't flag them.
    """
    if "in-addr.arpa" in hostname:
        return True
    octets = ip.split(".")
    # If the hostname contains all four octet substrings (joined by
    # any separator), it's IP-derived.
    if all(o in hostname for o in octets):
        return True
    return False


def _check_reverse_dns_enum(svc: DiscoveredService) -> Finding | None:
    """F202.F — Walk a deterministic 10-IP sample of the /24 and
    collect resolved PTR hostnames. Flags MEDIUM at >=3 hits,
    elevates to HIGH when any hit matches a sensitive-function
    keyword.
    """
    if svc.state != "open" or svc.port != 53:
        return None

    octets = svc.host.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return None

    base_net = ".".join(octets[:3])
    discovered: list[tuple[str, str]] = []  # (ip, hostname)
    probes_attempted = 0
    probes_succeeded = 0  # server actually replied (could be NXDOMAIN)

    for octet in _REVERSE_PROBE_OCTETS:
        ip = f"{base_net}.{octet}"
        if ip == svc.host:
            continue
        probes_attempted += 1
        result = _try_ptr_query(svc.host, ip)
        if result is None:
            continue
        # Resolution succeeded — count as success even if generic
        # (means the server is willing to answer reverse).
        probes_succeeded += 1
        if _is_generic_ptr(result, ip):
            continue
        discovered.append((ip, result))

    if len(discovered) < _REVERSE_HIT_THRESHOLD:
        return None

    sensitive_hits = [(ip, hn) for ip, hn in discovered if any(kw in hn for kw in _SENSITIVE_HOSTNAME_KEYWORDS)]
    severity = "HIGH" if sensitive_hits else "MEDIUM"

    evidence_lines = [f"  {ip} -> {hn}" for ip, hn in discovered[:8]]
    if sensitive_hits:
        evidence_lines.append("")
        evidence_lines.append("Hostnames con keywords sensibles:")
        evidence_lines.extend(f"  {ip} -> {hn}" for ip, hn in sensitive_hits[:5])
    evidence = "\n".join(evidence_lines)

    discovered_summary = ", ".join(hn for _, hn in discovered[:5])
    if len(discovered) > 5:
        discovered_summary += f", + {len(discovered) - 5} mas"

    return Finding(
        cwe="CWE-200",
        severity=severity,
        host=f"{svc.host}:{svc.port}",
        rule_id="dns-reverse-enum",
        message=(
            f"DNS server {svc.host}:53 expone PTR records de la /24 a "
            f"clientes externos. Sample de 10 IPs retorno "
            f"{len(discovered)} hostname(s) internos: {discovered_summary}. "
            + (
                f"{len(sensitive_hits)} hostname(s) revelan funcion sensible "
                "(banking / DB / prod / secrets) — alta prioridad para "
                "hardening o renombre."
                if sensitive_hits
                else "Recon barato pre-targeting de servicios criticos."
            )
        ),
        evidence=evidence[:1200],
        remediation=(
            "Restringir queries reverse a subnets internas:\n"
            "  - Microsoft DNS: dnsmgmt.msc > <reverse zone>.in-addr.arpa "
            "> Properties > Security: limitar query permissions a internal "
            "subnets. O usar Set-DnsServerZoneTransfer / "
            "Set-DnsServerRecursionScope con ACL.\n"
            '  - BIND: zone "<X>.in-addr.arpa" { type master; '
            "allow-query { 10.0.0.0/8; 172.16.0.0/12; }; };\n"
            "  - Unbound: stub-zone para reverse interno + "
            "access-control: 0.0.0.0/0 deny + access-control: "
            "<internal> allow.\n"
            "Trade-off operativo: alternativa es usar PTR genericos "
            "(host-N.internal.example) que no revelen funcion. Se "
            "pierde clarity en logs pero se reduce el exposure pre-attack. "
            "Para nodos sensibles (DB / SWIFT / payments) considerar el "
            "renombre incluso si el reverse zone va a quedar restringido."
        ),
        severity_rank=_SEV_RANK[severity],
    )


# F202.G — DNS dynamic update without TSIG auth (CWE-345 + CWE-284).
# RFC 2136 defines the UPDATE opcode that lets clients add / modify /
# delete records remotely. RFC 2845 (TSIG) and RFC 3645 (GSS-TSIG)
# secure it; without them, anyone with TCP/UDP 53 reachable can:
#   - inject `evil.britimp.com.py A <attacker_ip>` -> phishing infra
#   - rewrite MX -> intercept email
#   - delete critical records -> DoS
#   - create CNAME chains -> subdomain takeover
#
# Probe technique: build a NO-OP UPDATE (delete a record that doesn't
# exist) using dnspython. Observe the RCODE:
#   - NOERROR (0) -> server processed the UPDATE -> finding HIGH
#   - REFUSED (5) -> auth disabled or required   -> no finding
#   - NOTAUTH (9) -> TSIG required               -> no finding
#   - any other  -> conservative no finding
#
# Banca-safe: the test record uses a long random label that won't
# collide with anything real, AND the action is a delete-of-nothing
# (no-op in terms of zone state). dnspython is a soft dependency —
# if not installed, the check skips silently.


def _check_dns_dynamic_update(svc: DiscoveredService) -> Finding | None:
    """F202.G — Probe whether the DNS server accepts UPDATE messages
    without TSIG auth.
    """
    if svc.state != "open" or svc.port != 53:
        return None

    try:
        import dns.exception
        import dns.query
        import dns.rcode
        import dns.rdatatype
        import dns.update
    except ImportError:
        # dnspython not available -> skip silently (graceful
        # degradation, same pattern as F202.D with dig missing).
        return None

    # Use the same zone-discovery helper as F202.B. We need a real
    # zone name to formulate the UPDATE — bogus zone names get
    # FORMERR / NOTAUTH and yield no signal.
    zones = _derive_dns_zone_candidates(svc.host)
    if not zones:
        return None

    accepted_zones: list[str] = []
    for zone in zones[:2]:  # cap attempts to keep latency bounded
        # Skip reverse zones — UPDATE on in-addr.arpa is more
        # operationally sensitive (PTR records), and even though we
        # do delete-of-nothing it's cleaner to stay out of reverse.
        if "in-addr.arpa" in zone:
            continue

        update = dns.update.UpdateMessage(zone)
        # Long random label so we never hit a real record.
        test_label = f"kryon-rfc2136-noop-probe-{int(time.time())}"
        update.delete(test_label, dns.rdatatype.TXT)

        try:
            response = dns.query.udp(update, svc.host, timeout=4)
        except (dns.exception.Timeout, OSError):
            continue
        except Exception:  # noqa: BLE001
            continue

        rcode = response.rcode()

        # NOERROR means the server actually processed the UPDATE
        # message. With auth required (TSIG / GSS-TSIG / ACL) we'd
        # have gotten REFUSED or NOTAUTH instead.
        if rcode == dns.rcode.NOERROR:
            accepted_zones.append(zone)

    if not accepted_zones:
        return None

    zones_str = ", ".join(accepted_zones)
    return Finding(
        cwe="CWE-345",
        severity="HIGH",
        host=f"{svc.host}:{svc.port}",
        rule_id="dns-dynamic-update-open",
        message=(
            f"DNS server {svc.host}:53 acepta UPDATE messages (RFC 2136) "
            f"sin TSIG / GSS-TSIG auth para zona(s): {zones_str}. "
            "Atacante puede inyectar A / MX / CNAME records sin "
            "credenciales -> phishing infra, mail interception, "
            "subdomain takeover."
        ),
        evidence=(
            f"UDP/53 dns.update.UpdateMessage(<zone>) con "
            f"delete(kryon-rfc2136-noop-probe-*, TXT) retorno "
            f"RCODE=NOERROR (0) para: {zones_str}. Un servidor con "
            f"auth habilitada habria retornado REFUSED (5) o NOTAUTH (9)."
        ),
        remediation=(
            "Requerir TSIG / GSS-TSIG para todo dynamic update:\n"
            "  - Microsoft DNS (AD-integrated): dnsmgmt.msc > zone > "
            "Properties > General > Dynamic updates: cambiar de "
            "'Nonsecure and secure' a 'Secure only' (requiere GSS-TSIG / "
            "Kerberos auth contra el DC). Validar con "
            "Get-DnsServerZone | Select Name,DynamicUpdate.\n"
            '  - BIND: zone "example.com" { type master; '
            "allow-update { key dhcp-key; }; }; + definir TSIG key "
            "compartida con DHCP server, NUNCA `allow-update { any; };`.\n"
            "  - PowerDNS: api-key required + disable-syslog en "
            "endpoints publicos.\n"
            "Alternativa para zonas que NO necesitan dynamic update "
            "(la mayoria de las zonas de produccion): bloquear el "
            "UPDATE opcode entirely en el firewall a nivel L7 (Suricata "
            "regla: dns.opcode == 5 -> drop) y deshabilitar update en el "
            "DNS engine.\n"
            "Impacto financiero: en banking, un UPDATE no autenticado "
            "permite reescribir el MX de britimp.com.py hacia atacante -> "
            "intercept de mail con tokens 2FA, fraude bancario por "
            "phishing infra dentro del dominio legitimo."
        ),
        severity_rank=_SEV_RANK["HIGH"],
    )


# F202.H — Cross-DC config drift detection.
# Surfaced by the Britimp POC pilot 2026-05-18 against britimp.com.py:
# .205 (primary DC) and .5 (secondary DC) belong to the same AD
# domain but have ASYMMETRIC DNS posture:
#   - both have dns-open-resolver (consistent bug — sistemico)
#   - only .205 fails DNSSEC validation; .5 timeouts (probably valid)
#   - only .5 exposes IIS plaintext :80
#   - only .5 has SSH-for-Windows :22 + RealServer 7070
# Asymmetric trust from the client's perspective: depending on which
# DC the client lands on first, it gets DIFFERENT security guarantees
# — a poison attack against .205 wouldn't be visible from .5's
# clients and vice versa.
# CWE-1188 (Insecure Default Initialization of Resource) — the
# config was intended to be uniform across replicas, the drift is
# an operational bug not a deliberate split.

# Rule IDs that should be IDENTICAL across DCs of the same domain.
# Each entry: (rule_id, severity_if_asymmetric, label)
_DC_DRIFT_DNS_RULES: tuple[tuple[str, str, str], ...] = (
    ("dns-open-resolver", "HIGH", "DNS recursion abierta"),
    ("dns-axfr-allowed", "HIGH", "AXFR / zone transfer"),
    ("dns-chaos-leak", "MEDIUM", "CHAOS class info disclosure"),
    ("dns-cache-snoop", "MEDIUM", "Cache snooping (privacy leak)"),
    ("dnssec-validation-disabled", "HIGH", "DNSSEC validation"),
    ("dns-reverse-enum", "MEDIUM", "Reverse zone enumeration"),
    ("dns-dynamic-update-open", "HIGH", "RFC 2136 dynamic UPDATE"),
)

# Service-level drift indicators (presence of port on one DC but not
# the other). The check inspects `_DiscoveredService` lists when
# they're attached to the host-findings dict, OR infers from the
# host's findings themselves (e.g. http-plaintext implies port 80).
_DC_DRIFT_PORT_INFERENCE: tuple[tuple[str, int, str], ...] = (
    ("http-plaintext", 80, "HTTP plaintext"),
    ("ssh-banner-visible", 22, "SSH habilitado"),
)


def _is_domain_controller_host(findings: list[Finding]) -> bool:
    """F202.H helper — heuristic: a host is treated as a DC when its
    findings include >=1 AD-* rule (from Phase 2b windows_ad checks).
    The AD compliance pack only fires when the engage detected
    `windows_ad` family, so it's a reliable proxy.
    """
    return any(f.rule_id.startswith("AD-") for f in findings)


def _rule_ids_present(findings: list[Finding]) -> set[str]:
    """Convenience: deduplicated set of rule_ids that appear on a host."""
    return {f.rule_id for f in findings}


def diff_dc_dns_posture(
    host_findings: dict[str, list[Finding]],
) -> list[Finding]:
    """F202.H — Compare DNS posture (and a few service-presence
    indicators) across all detected DCs of the input host set.
    Returns one Finding per asymmetric configuration item.

    Input: `{host_ip: [Finding, ...]}` — typically built by a
    queue processor or ad-hoc script that runs `kryon engage`
    against multiple hosts of the same segment / domain.

    The function:
      1. Filters hosts that are DCs (have AD-* findings).
      2. If <2 DCs, returns [] (no drift to compute).
      3. For each rule_id in `_DC_DRIFT_DNS_RULES`, compares the
         set of DCs where the rule fires vs where it doesn't. If
         partial coverage (asymmetric), emits a drift finding.
      4. Same for `_DC_DRIFT_PORT_INFERENCE` — service presence.

    The output findings have:
      - `host` = `"drift:<dc_a>+<dc_b>"`
      - `rule_id` = `"dc-drift-<original_rule>"`
      - `cwe` = `"CWE-1188"`
    """
    dc_hosts: dict[str, list[Finding]] = {
        host: findings for host, findings in host_findings.items() if _is_domain_controller_host(findings)
    }
    if len(dc_hosts) < 2:
        return []

    drift_findings: list[Finding] = []
    rule_sets: dict[str, set[str]] = {host: _rule_ids_present(findings) for host, findings in dc_hosts.items()}

    # 1. DNS-rule drift
    for rule_id, drift_severity, label in _DC_DRIFT_DNS_RULES:
        with_rule = [host for host, rules in rule_sets.items() if rule_id in rules]
        without_rule = [host for host, rules in rule_sets.items() if rule_id not in rules]
        if with_rule and without_rule:
            drift_findings.append(
                Finding(
                    cwe="CWE-1188",
                    severity=drift_severity,
                    host=f"drift:{'+'.join(sorted(dc_hosts.keys()))}",
                    rule_id=f"dc-drift-{rule_id}",
                    message=(
                        f"Config drift entre DCs del dominio: '{label}' "
                        f"presente en {', '.join(sorted(with_rule))} pero "
                        f"ausente en {', '.join(sorted(without_rule))}. "
                        "Postura asimetrica de seguridad — clientes reciben "
                        "garantias distintas segun cual DC les responda."
                    ),
                    evidence=(
                        f"Rule `{rule_id}` triggered on: "
                        f"{', '.join(sorted(with_rule))}\n"
                        f"Rule `{rule_id}` NOT triggered on: "
                        f"{', '.join(sorted(without_rule))}"
                    ),
                    remediation=(
                        "Sincronizar la configuracion DNS entre todos los DCs "
                        f"del dominio. Para '{label}':\n"
                        "  - Inspeccionar config con `Get-DnsServerSetting` y "
                        "`Get-DnsServerRecursionScope` (Microsoft DNS) en ambos "
                        "DCs y reconciliar.\n"
                        "  - Para BIND: rsync named.conf entre los hosts o "
                        "ponerlo en config management (Ansible / Salt / Puppet).\n"
                        "  - Replicacion AD por si misma NO sincroniza DNS "
                        "server settings (solo zone data) — los settings son "
                        "per-host y hay que aplicar GPO o IaC.\n"
                        "Trampa comun: agregar un secundario DC nuevo con "
                        "wizard heredando defaults distintos del primario. "
                        "Cada upgrade major de Windows Server cambia algun "
                        "default DNS."
                    ),
                    severity_rank=_SEV_RANK[drift_severity],
                )
            )

    # 2. Port / service inference drift (HTTP plaintext, SSH enabled, etc.)
    for rule_id, port, label in _DC_DRIFT_PORT_INFERENCE:
        with_service = [host for host, rules in rule_sets.items() if rule_id in rules]
        without_service = [host for host, rules in rule_sets.items() if rule_id not in rules]
        if with_service and without_service:
            drift_findings.append(
                Finding(
                    cwe="CWE-1188",
                    severity="MEDIUM",
                    host=f"drift:{'+'.join(sorted(dc_hosts.keys()))}",
                    rule_id=f"dc-drift-service-{rule_id}",
                    message=(
                        f"Config drift entre DCs: '{label}' (puerto {port}) "
                        f"expuesto en {', '.join(sorted(with_service))} pero "
                        f"NO en {', '.join(sorted(without_service))}. "
                        "Superficie de ataque desigual entre replicas."
                    ),
                    evidence=(
                        f"Servicio inferido por rule `{rule_id}` (port "
                        f"{port}/tcp) detectado en: "
                        f"{', '.join(sorted(with_service))}\n"
                        f"No detectado en: {', '.join(sorted(without_service))}"
                    ),
                    remediation=(
                        f"Decidir si el servicio en puerto {port} debe estar "
                        "expuesto desde TODOS los DCs o NINGUNO:\n"
                        f"  - Si es operacionalmente necesario, replicar la "
                        "exposicion + hardening (TLS, ACL, auth) a todos los "
                        "DCs.\n"
                        "  - Si no es necesario, deshabilitar el servicio "
                        "en el DC donde aparece. Para IIS: `Stop-WebAppPool` "
                        "+ `Set-Service W3SVC -StartupType Disabled`. Para "
                        "SSH-for-Windows: `Disable-Service sshd`.\n"
                        "Mantener IaC / GPO para garantizar consistencia "
                        "en futuras nuevas replicas."
                    ),
                    severity_rank=_SEV_RANK["MEDIUM"],
                )
            )

    return drift_findings


# F202.O — Proxmox cluster config drift detector (CWE-1188).
# Surfaced POC Britimp 2026-05-19: cluster `britimp-cluster` con 3
# nodos Proxmox VE (.115 proxmox2, .200 pve-britimp, .222 pve-torre-
# prod) corriendo 3 versiones DIFERENTES (9.1.4, 8.4.16, 9.1.8). El
# .200 quedo aislado del cluster por incompatibilidad de version. Solo
# 2 nodos en quorum = single point of failure cluster-wide.
#
# Banking impact:
#   - Mixed-version cluster: features cluster operations incompatibles
#     (HA, live migration, ceph) — comportamiento impredecible.
#   - Single point of failure: si cae cualquier nodo en quorum, el
#     cluster ENTERO se cae (no failover automatico).
#   - Hallazgos diferenciales por nodo: workload "accidental" unico
#     por host (Node.js Express en .115, python http.server en .200)
#     indica falta de gestion centralizada de workload.

# Rule IDs Proxmox que deben ser IDENTICOS cross-cluster.
# Cada entry: (rule_id, drift_severity, label)
_PROXMOX_CLUSTER_DRIFT_RULES: tuple[tuple[str, str, str], ...] = (
    ("PVE-1.2", "HIGH", "2FA enforcement para usuarios admin"),
    ("PVE-2.1", "HIGH", "Cluster quorum / fencing"),
    ("PVE-3.1", "HIGH", "Backup retention + verification"),
    ("PVE-4.1", "HIGH", "SSL/TLS certificate validity"),
    ("PVE-5.1", "MEDIUM", "Subscription / repository config"),
    ("PVE-6.1", "MEDIUM", "Quorum tie-breaker en cluster impar"),
    ("PVE-7.1", "MEDIUM", "Audit log retention"),
    ("PVE-8.1", "MEDIUM", "Remote syslog config"),
    ("sshd-permit-root-login", "CRITICAL", "PermitRootLogin (cluster-wide ssh hardening)"),
    ("python-simplehttp-directory-listing", "CRITICAL", "python http.server (workload accidental)"),
)

# Servicios "no estandar" en un host hypervisor (cuyo trabajo es solo
# correr VMs/LXC). Si UN host del cluster expone algo unico que los
# otros no, indica workload no aislado.
_PROXMOX_DRIFT_SERVICE_RULES: tuple[tuple[str, int, str], ...] = (
    ("http-plaintext", 8080, "Workload HTTP en :8080 (hypervisor no debe alojar apps)"),
    ("http-plaintext", 8888, "Workload HTTP en :8888 (probable python -m http.server)"),
    ("http-xpoweredby", 8080, "Node.js Express en hypervisor"),
)


def _is_proxmox_host(findings: list[Finding]) -> bool:
    """F202.O helper — heuristica: host es Proxmox si tiene >=1 rule
    PVE-* (de Phase 2b proxmox checks)."""
    return any(f.rule_id.startswith("PVE-") for f in findings)


def diff_proxmox_cluster_posture(
    host_findings: dict[str, list[Finding]],
) -> list[Finding]:
    """F202.O — Compare Proxmox VE posture cross-cluster nodes.

    Similar a F202.H (DC drift) pero para cluster Proxmox. Detecta:
      - Rule drift: PVE checks que fallan en algunos nodos pero no
        en otros (config drift Ansible)
      - Service drift: workload accidental en hypervisor host (un
        nodo expone un servicio que otros no — anti-pattern de
        virtualization)

    Input: `{host_ip: [Finding]}`. Como F202.H, es una funcion pura;
    debe ser invocada por orchestration externa con findings agregados
    de multiples engages contra los nodos del cluster.
    """
    pve_hosts: dict[str, list[Finding]] = {
        host: findings for host, findings in host_findings.items() if _is_proxmox_host(findings)
    }
    if len(pve_hosts) < 2:
        return []

    drift_findings: list[Finding] = []
    rule_sets: dict[str, set[str]] = {host: {f.rule_id for f in findings} for host, findings in pve_hosts.items()}

    # 1. Rule drift cross-nodes
    for rule_id, drift_severity, label in _PROXMOX_CLUSTER_DRIFT_RULES:
        with_rule = [host for host, rules in rule_sets.items() if rule_id in rules]
        without_rule = [host for host, rules in rule_sets.items() if rule_id not in rules]
        if with_rule and without_rule:
            drift_findings.append(
                Finding(
                    cwe="CWE-1188",
                    severity=drift_severity,
                    host=f"cluster-drift:{'+'.join(sorted(pve_hosts.keys()))}",
                    rule_id=f"pve-cluster-drift-{rule_id}",
                    message=(
                        f"Cluster Proxmox drift: '{label}' presente en "
                        f"{', '.join(sorted(with_rule))} pero ausente en "
                        f"{', '.join(sorted(without_rule))}. Config no "
                        "uniforme cross-nodes — feature behavior "
                        "impredecible + potencial split-brain."
                    ),
                    evidence=(
                        f"Rule `{rule_id}` triggered en: "
                        f"{', '.join(sorted(with_rule))}\n"
                        f"NO triggered en: {', '.join(sorted(without_rule))}"
                    ),
                    remediation=(
                        f"Sincronizar configuracion '{label}' en TODOS "
                        "los nodos del cluster:\n"
                        "  - Comparar config con `pvecm status` + "
                        "`pveversion -v` en cada nodo.\n"
                        "  - Aplicar mismo Ansible/Salt playbook a todos "
                        "los nodos del cluster (NO solo a uno).\n"
                        "  - `pvecm nodes` debe mostrar TODOS los nodos "
                        "con misma version PVE major.\n"
                        "  - Para upgrades coordinados: rolling update "
                        "(pvecm expected + apt upgrade + reboot rolling).\n"
                        "Trampa comun POC Britimp: VM-Wazuh STOPPED en "
                        "cluster + python http.server en .200 + Node.js "
                        "Express en .115 = workload accidental NO "
                        "controlado por config management central."
                    ),
                    severity_rank=_SEV_RANK[drift_severity],
                )
            )

    # 2. PVE version drift (special: extract version from first PVE
    # rule's evidence). Si los nodos tienen versiones distintas, flag
    # como drift independientemente de qué rule_ids fallaron.
    versions_per_host: dict[str, str] = {}
    for host, findings in pve_hosts.items():
        for f in findings:
            evidence_lower = (f.evidence or "").lower()
            if "pve-manager" in evidence_lower or "pveversion" in evidence_lower:
                # F202.S code-quality cleanup: usar `re` top-level (ya
                # importado en linea 43) en lugar de reimportar dentro
                # del loop.
                m = re.search(r"pve-manager/(\d+\.\d+\.\d+)", f.evidence or "")
                if m:
                    versions_per_host[host] = m.group(1)
                    break

    unique_versions = set(versions_per_host.values())
    if len(unique_versions) > 1:
        drift_findings.append(
            Finding(
                cwe="CWE-1188",
                severity="HIGH",
                host=f"cluster-drift:{'+'.join(sorted(pve_hosts.keys()))}",
                rule_id="pve-cluster-drift-version",
                message=(
                    f"Cluster Proxmox con {len(unique_versions)} versiones "
                    "PVE distintas — incompatibilidad cluster operations "
                    "(HA / live migration / ceph). Risk de split-brain."
                ),
                evidence="\n".join(f"  {host}: pve-manager/{ver}" for host, ver in sorted(versions_per_host.items())),
                remediation=(
                    "Unificar version PVE cross-cluster:\n"
                    "  1. Identificar nodo target (mas reciente).\n"
                    "  2. Backup cluster config (/etc/pve/) before upgrade.\n"
                    "  3. Rolling upgrade del cluster:\n"
                    "     a. Migrar VMs / LXCs fuera del nodo target.\n"
                    "     b. apt update && apt dist-upgrade en el nodo.\n"
                    "     c. Reboot.\n"
                    "     d. Repetir con siguiente nodo.\n"
                    "  4. Para upgrades major (8.x -> 9.x): seguir guia "
                    "oficial https://pve.proxmox.com/wiki/Upgrade_from_8_to_9.\n"
                    "Trampa comun: 'me funciona, no toco'. Mantener cluster "
                    "con versiones distintas indefinidamente lleva a fallar "
                    "live migration + HA, y eventualmente el nodo viejo "
                    "queda aislado del corosync."
                ),
                severity_rank=_SEV_RANK["HIGH"],
            )
        )

    return drift_findings


# F200.B — Web server EOL table. Keep `min_supported` conservative
# (a few versions above the minor with a notable CVE). When the
# scanner banner reports a lower version, flag HIGH with the CVE list.
# `min_supported` is a tuple (major, minor, patch) so version
# comparison stays semantic.
_WEBSERVER_EOL_TABLE: tuple = (
    {
        "name_re": re.compile(r"^nginx(?:/(\d+)\.(\d+)\.(\d+))?\b", re.IGNORECASE),
        "pretty": "nginx",
        "min_supported": (1, 26, 0),  # 1.26 LTS (Apr 2024) — anything older has accumulating CVEs
        "cves": (
            ("CVE-2021-23017", "CRITICAL", "Pre-auth RCE remoto vía DNS resolver heap overflow (fixed 1.20.1)"),
            ("CVE-2022-41741", "HIGH", "mp4 module heap overflow (fixed 1.23.2)"),
            ("CVE-2022-41742", "HIGH", "mp4 module OOB read (fixed 1.23.2)"),
            ("CVE-2024-7347", "HIGH", "mp4 module RCE potential (fixed 1.27.4)"),
        ),
        "remediation_extra": (
            "Upgrade path:\n"
            "  Ubuntu 22.04 (apt nginx 1.18) → enable nginx PPA o compilar 1.26.x\n"
            "  Debian 12 (apt nginx 1.22)    → upgrade a 1.26.x desde nginx.org repo\n"
            "  Compilar desde nginx.org/en/download.html (mainline = 1.27.x, stable = 1.26.x)"
        ),
    },
    {
        "name_re": re.compile(r"^Apache(?:/(\d+)\.(\d+)\.(\d+))?", re.IGNORECASE),
        "pretty": "Apache httpd",
        "min_supported": (2, 4, 62),  # 2.4.62 (Aug 2024) — earlier 2.4.x has multiple CVEs
        "cves": (
            ("CVE-2024-38476", "CRITICAL", "mod_rewrite RCE via request URL (fixed 2.4.60)"),
            ("CVE-2024-38477", "HIGH", "mod_proxy NULL deref (fixed 2.4.60)"),
            ("CVE-2023-31122", "MEDIUM", "mod_macro OOB read (fixed 2.4.58)"),
            ("CVE-2022-23943", "CRITICAL", "mod_sed heap overflow (fixed 2.4.53)"),
        ),
        "remediation_extra": (
            "Upgrade path:\n"
            "  Debian 12 (apache2 2.4.62-1~deb12u2) → apt upgrade\n"
            "  Ubuntu 22.04 (2.4.52)                 → apt upgrade (current 2.4.58)\n"
            "  Compilar desde httpd.apache.org/download.cgi (current 2.4.x)"
        ),
    },
    {
        # IIS version banners ship as "Microsoft-IIS/X.Y" (no patch).
        # Capture X, Y, and an empty third group so the unpack matches
        # the (major, minor, patch) tuple expected by _parse_semver.
        "name_re": re.compile(r"^Microsoft-IIS(?:/(\d+)\.(\d+)())?", re.IGNORECASE),
        "pretty": "Microsoft IIS",
        "min_supported": (10, 0, 0),  # IIS 10.0 (Windows Server 2016+); earlier (7.5/8.0) on EOL Windows
        "cves": (
            ("CVE-2022-22025", "HIGH", "IIS XSS in default error page"),
            ("CVE-2020-0645", "MEDIUM", "IIS info disclosure"),
        ),
        "remediation_extra": (
            "IIS < 10.0 means el host corre Windows Server <= 2012 R2 (EOL Oct 2023).\n"
            "Migration urgente: Win Server 2022 + IIS 10.0.20348.x (release Aug 2021+)."
        ),
    },
)


def _parse_semver(major_s: str | None, minor_s: str | None, patch_s: str | None) -> tuple[int, int, int] | None:
    """Return (major, minor, patch) if at least the major is parseable.
    Patch defaults to 0 (e.g. IIS banner ships only major.minor).
    Returns None when all three are missing (banner without version).
    """
    if major_s is None and minor_s is None and patch_s is None:
        return None
    try:
        return (int(major_s or "0"), int(minor_s or "0"), int(patch_s or "0"))
    except (TypeError, ValueError):
        return None


def _check_webserver_eol(svc: DiscoveredService, headers: str) -> Finding | None:
    """F200.B — Flag HIGH when the Server header reveals a web server
    version below the minimum supported (i.e. EOL with accumulated CVEs).

    Surfaced by the Britimp POC pilot 2026-05-18 against .18 (nginx
    1.18.0 EOL desde abril 2023). The generic http-server-token check
    flagged the info disclosure (MEDIUM) but missed that the disclosed
    version was the precondition for CVE-2021-23017 (CRITICAL pre-auth
    RCE).
    """
    server_m = re.search(r"^Server:\s*([^\r\n]+)", headers, re.MULTILINE | re.IGNORECASE)
    if not server_m:
        return None
    server_value = server_m.group(1).strip()

    for entry in _WEBSERVER_EOL_TABLE:
        v_m = entry["name_re"].search(server_value)
        if not v_m:
            continue
        observed = _parse_semver(*v_m.groups()[:3])
        if observed is None:
            return None  # version present but unparsable — skip
        min_v = entry["min_supported"]
        if observed >= min_v:
            return None  # version is supported, nothing to flag

        # EOL — build the finding with CVE list + upgrade path.
        cve_lines = "\n".join(f"  [{sev:8s}] {cve_id}: {desc}" for cve_id, sev, desc in entry["cves"])
        observed_str = ".".join(str(p) for p in observed)
        min_str = ".".join(str(p) for p in min_v)
        return Finding(
            cwe="CWE-1104",  # Use of Unmaintained Third Party Components
            severity="HIGH",
            host=f"{svc.host}:{svc.port}",
            rule_id=f"{entry['pretty'].lower().replace(' ', '-')}-version-eol",
            message=(
                f"{entry['pretty']} {observed_str} es EOL / por debajo del mínimo soportado "
                f"({min_str}). CVEs públicas aplicables a esta versión:"
            ),
            evidence=f"Server: {server_value}\n\nCVEs históricas para {entry['pretty']} <= {observed_str}:\n{cve_lines}",
            remediation=(
                f"Upgrade a {entry['pretty']} {min_str} o superior.\n\n"
                f"{entry['remediation_extra']}\n\n"
                "Validar con `curl -sSI` post-upgrade que el header Server refleje la versión nueva."
            ),
            severity_rank=_SEV_RANK["HIGH"],
        )
    return None


def _check_admin_open(svc: DiscoveredService) -> Finding | None:
    """F199.H — Flag CWE-306 only when /admin is meaningfully different
    from the root. SPA frameworks (Angular/React/Vue) serve index.html
    for every path under their HTML5 routing config; comparing the
    bodies tells us whether /admin is a real admin surface or a
    catch-all artefact.
    """
    base_url = f"http://{svc.host}:{svc.port}"
    root_code, root_body = _http_get(f"{base_url}/")
    admin_code, admin_body = _http_get(f"{base_url}/admin")

    # No /admin response at all (404, connect-refused) — nothing to flag.
    if admin_code != 200:
        return None

    # If the root also returns 200 and the bodies are identical, this is
    # a SPA catch-all, not a real admin endpoint. The cheapest stable
    # signature is (length, sha256). We skip a tiny prefix to allow for
    # CSRF tokens / nonces injected per-request.
    import hashlib

    def _fingerprint(body: str) -> tuple[int, str]:
        return len(body), hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()

    if root_code == 200 and _fingerprint(root_body) == _fingerprint(admin_body):
        return None  # SPA catch-all — not an exposed admin

    return Finding(
        cwe="CWE-306",
        severity="HIGH",
        host=f"{svc.host}:{svc.port}",
        rule_id="http-admin-open",
        message="Endpoint /admin accesible sin autenticación.",
        evidence=(f"GET {svc.host}:{svc.port}/admin → 200 (body distinto del root, no es SPA catch-all)"),
        remediation="Proteger /admin con autenticación (auth_basic / OAuth / mTLS).",
        severity_rank=_SEV_RANK["HIGH"],
    )


def _check_ssh(svc: DiscoveredService, ssh_target: str | None, ssh_password: str | None) -> list[Finding]:
    """SSH banner grab + (optional) config check via SSH."""
    findings: list[Finding] = []

    # Banner is always visible. Use a context manager so the socket closes
    # even when recv times out or the peer resets — leaked FDs were real
    # across long engagements.
    import socket

    banner = ""
    try:
        with socket.create_connection((svc.host, svc.port), timeout=3) as s:
            raw = s.recv(128).decode(errors="replace").splitlines()
            banner = raw[0] if raw else ""
    except (TimeoutError, OSError) as exc:
        logger.debug("ssh banner grab failed on %s:%s: %s", svc.host, svc.port, exc)

    if banner and not ssh_target:
        findings.append(
            Finding(
                cwe="CWE-200",
                severity="LOW",
                host=f"{svc.host}:{svc.port}",
                rule_id="ssh-banner-visible",
                message="SSH expone banner con versión del servidor.",
                evidence=banner,
                remediation="Reducir verbosidad del banner (no suele ser crítico).",
                severity_rank=_SEV_RANK["LOW"],
            )
        )

    if not ssh_target:
        return findings

    # Deeper checks require creds
    user, _, host = ssh_target.partition("@")
    if ":" in host:
        host, port = host.split(":", 1)
    else:
        port = str(svc.port)

    def _remote(cmd: str) -> str:
        base = [
            "ssh",
            # F202.S security hardening (POC Britimp audit): accept-new
            # pins el host fingerprint la primera vez; rechaza si el
            # fingerprint cambia (MITM detection). NO usar `=no` que
            # acepta cualquier fingerprint sin warning. Banking-grade.
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-p",
            port,
            f"{user}@{host}",
        ]
        # Pass password via env (`sshpass -e`) so it never appears in argv
        # / /proc/<pid>/cmdline. Banks regularly audit running processes;
        # `sshpass -p <password>` is a reliable demo killer.
        env = None
        if ssh_password:
            env = {**os.environ, "SSHPASS": ssh_password}
            base = ["sshpass", "-e"] + base
        try:
            r = subprocess.run(base + [cmd], capture_output=True, text=True, timeout=15, check=False, env=env)
            return r.stdout
        except Exception:
            return ""

    cfg = _remote("sudo cat /etc/ssh/sshd_config 2>/dev/null || cat /etc/ssh/sshd_config")
    if not cfg:
        logger.info("SSH config read failed (auth? sudo?)")
        return findings

    if re.search(r"^\s*PermitRootLogin\s+yes", cfg, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                cwe="CWE-521",
                severity="CRITICAL",
                host=f"{user}@{host}",
                rule_id="sshd-permit-root-login",
                message="sshd permite login de root por SSH.",
                evidence="PermitRootLogin yes",
                remediation="Desactivar PermitRootLogin en /etc/ssh/sshd_config.",
                remediation_command=(
                    "sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "
                    "/etc/ssh/sshd_config && sudo systemctl reload sshd"
                ),
                target_host=f"{user}@{host}",
                severity_rank=_SEV_RANK["CRITICAL"],
            )
        )
    if re.search(r"^\s*PasswordAuthentication\s+yes", cfg, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                cwe="CWE-521",
                severity="HIGH",
                host=f"{user}@{host}",
                rule_id="sshd-password-auth",
                message="sshd permite autenticación por contraseña.",
                evidence="PasswordAuthentication yes",
                remediation="Requerir autenticación por clave pública.",
                remediation_command=(
                    "sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "
                    "/etc/ssh/sshd_config && sudo systemctl reload sshd"
                ),
                target_host=f"{user}@{host}",
                severity_rank=_SEV_RANK["HIGH"],
            )
        )
    # F202.V — X11Forwarding yes (CWE-250 — Execution with Unnecessary
    # Privileges). Surfaced docker/vulnerable-lab smoke test: ground truth
    # planted vuln no detectada antes. X11 forwarding sobre SSH es vector
    # de privilege escalation: cliente SSH puede inyectar X events al
    # server display (xdotool-style), bypass de session lock, keystroke
    # injection. Banking: nunca usar X11 forwarding en produccion.
    if re.search(r"^\s*X11Forwarding\s+yes", cfg, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                cwe="CWE-250",
                severity="MEDIUM",
                host=f"{user}@{host}",
                rule_id="sshd-x11-forwarding",
                message="sshd permite X11Forwarding — vector de privilege escalation via X event injection.",
                evidence="X11Forwarding yes",
                remediation=(
                    "Deshabilitar X11Forwarding en /etc/ssh/sshd_config. "
                    "Solo habilitarlo en hosts no-banking que realmente lo necesiten "
                    "(estaciones de desarrollo con GUI), nunca en servers."
                ),
                remediation_command=(
                    "sudo sed -i 's/^X11Forwarding yes/X11Forwarding no/' "
                    "/etc/ssh/sshd_config && sudo systemctl reload sshd"
                ),
                target_host=f"{user}@{host}",
                severity_rank=_SEV_RANK["MEDIUM"],
            )
        )
    m = re.search(r"^\s*MaxAuthTries\s+(\d+)", cfg, re.MULTILINE | re.IGNORECASE)
    if m and int(m.group(1)) > 4:
        findings.append(
            Finding(
                cwe="CWE-307",
                severity="MEDIUM",
                host=f"{user}@{host}",
                rule_id="sshd-max-auth-tries",
                message=f"MaxAuthTries {m.group(1)} permite fuerza bruta prolongada.",
                evidence=f"MaxAuthTries {m.group(1)}",
                remediation="Bajar a 3 y habilitar fail2ban.",
                remediation_command=(
                    f"sudo sed -i 's/^MaxAuthTries {m.group(1)}/MaxAuthTries 3/' "
                    "/etc/ssh/sshd_config && sudo systemctl reload sshd"
                ),
                target_host=f"{user}@{host}",
                severity_rank=_SEV_RANK["MEDIUM"],
            )
        )
    return findings


# F202.R — SIEM agent activity check (CWE-778 — Insufficient Logging).
# Surfaced POC Britimp 2026-05-19: VM-Ubuntu-Wazuh (VM 101 en cluster
# Proxmox) STOPPED. El SIEM Wazuh esta deployed pero apagado → blind
# spot total de eventos seguridad. Sin SIEM activo:
#   - No detection de auth failures (brute force invisible)
#   - No detection de file integrity changes (rootkit invisible)
#   - No detection de anomalous network flows
#   - No incident response triggered
# Banking-CRITICAL: PCI-DSS Req 10 (logging + monitoring), SOC2 CC7.2
# (continuous monitoring), BCP Paraguay SIB regulaciones.
#
# Check requiere SSH al host. Severidad:
#   - CRITICAL: Wazuh installed pero agent inactive (worst case — false
#     sense of security)
#   - HIGH: No SIEM agent en absoluto (no monitoring infrastructure)
#   - MEDIUM: Otro SIEM activo (filebeat/auditd/osquery) pero sin
#     Wazuh — config heterogenea
#   - No finding: Wazuh active OR (auditd + filebeat + remote syslog)

_SIEM_PACKAGES_TO_CHECK = (
    "wazuh-agent",  # Wazuh OSSEC fork — top SIEM en LATAM banca
    "filebeat",  # Elastic Beats log shipper
    "auditd",  # Linux audit daemon — base de cualquier SIEM
    "osquery",  # Facebook osquery
    "rsyslog",  # Remote syslog (mejor que nada)
    "syslog-ng",  # Alternative syslog
)


def _check_siem_activity(
    host: str,
    ssh_target: str | None,
    ssh_key: str | None,
    ssh_password: str | None,
) -> Finding | None:
    """F202.R — Check SIEM agent + audit daemon activity on a Linux host.

    Requires SSH access. Without creds, returns None (no false claim).
    Read-only: `systemctl is-active <svc>` + `test -d /var/ossec`.
    Banca-safe.
    """
    if not ssh_target:
        return None

    user, _, host_port = ssh_target.partition("@")
    host_only, _, port_str = host_port.partition(":")
    host_only = host_only or host
    port = port_str or "22"

    def _remote(cmd: str) -> str:
        base = [
            "ssh",
            # F202.S security hardening (POC Britimp audit review):
            # accept-new pins fingerprint la primera vez; rechaza si
            # cambia (MITM detection). NO `=no` que es vulnerable a MITM
            # en redes bancarias internas con ARP spoofing posible.
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-p",
            port,
        ]
        if ssh_key:
            base.extend(["-i", ssh_key])
        base.append(f"{user}@{host_only}")
        env = None
        if ssh_password:
            env = {**os.environ, "SSHPASS": ssh_password}
            base = ["sshpass", "-e"] + base
        try:
            r = subprocess.run(
                base + [cmd],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                env=env,
            )
            return r.stdout
        except Exception:  # noqa: BLE001
            return ""

    probe_cmd = (
        "for svc in " + " ".join(_SIEM_PACKAGES_TO_CHECK) + "; do "
        "  status=$(systemctl is-active $svc 2>/dev/null || echo missing); "
        '  echo "$svc=$status"; '
        "done; "
        'echo "ossec_dir=$(test -d /var/ossec && echo yes || echo no)"; '
        'echo "wazuh_dir=$(test -d /var/ossec/etc && echo yes || echo no)"'
    )

    output = _remote(probe_cmd)
    if not output.strip():
        return None  # SSH failed silently — graceful skip

    statuses: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            statuses[k.strip()] = v.strip()

    if not statuses:
        return None

    wazuh_active = statuses.get("wazuh-agent") == "active"
    wazuh_installed = (
        statuses.get("wazuh-agent") in ("inactive", "failed", "activating")
        or statuses.get("ossec_dir") == "yes"
        or statuses.get("wazuh_dir") == "yes"
    )
    filebeat_active = statuses.get("filebeat") == "active"
    auditd_active = statuses.get("auditd") == "active"
    osquery_active = statuses.get("osquery") == "active"
    rsyslog_active = statuses.get("rsyslog") == "active" or statuses.get("syslog-ng") == "active"

    other_siem_active = filebeat_active or osquery_active

    # CASO 1: Wazuh installed pero agent inactive — el peor caso, falsa
    # sensacion de seguridad ("tenemos SIEM!" pero apagado).
    if wazuh_installed and not wazuh_active:
        return Finding(
            cwe="CWE-778",
            severity="CRITICAL",
            host=f"{user}@{host_only}",
            rule_id="siem-wazuh-installed-inactive",
            message=(
                f"Host {host_only} tiene Wazuh agent INSTALADO pero "
                f"INACTIVE (estado: {statuses.get('wazuh-agent', 'unknown')}). "
                "Blind spot total de eventos seguridad — falsa sensacion "
                "de monitoring."
            ),
            evidence=(
                f"systemctl is-active wazuh-agent = "
                f"{statuses.get('wazuh-agent')}\n"
                f"/var/ossec exists: {statuses.get('ossec_dir')}\n"
                f"Other SIEM: filebeat={statuses.get('filebeat')}, "
                f"auditd={statuses.get('auditd')}, "
                f"osquery={statuses.get('osquery')}"
            ),
            remediation=(
                "Re-activar Wazuh agent:\n"
                "  systemctl enable --now wazuh-agent\n"
                "  systemctl status wazuh-agent\n"
                "Verificar conectividad al manager:\n"
                "  grep -E '<server>' /var/ossec/etc/ossec.conf\n"
                "  nc -zv <manager_ip> 1514\n"
                "Si el manager esta down (VM-Wazuh STOPPED en cluster) "
                "encender la VM primero. Causa raiz comun: Wazuh manager "
                "moved/migrated y agents quedaron apuntando a IP vieja.\n"
                "Compliance impact: PCI-DSS Req 10.5 (proteccion de logs), "
                "10.7 (retention 1 ano), SOC2 CC7.2 (continuous monitoring), "
                "BCP Paraguay SIB Cap. 8 (audit trail). Wazuh inactive "
                "implica todos esos controles fallan."
            ),
            severity_rank=_SEV_RANK["CRITICAL"],
        )

    # CASO 2: Nada de SIEM — host sin monitoring infrastructure
    if not wazuh_active and not other_siem_active and not auditd_active:
        return Finding(
            cwe="CWE-778",
            severity="HIGH",
            host=f"{user}@{host_only}",
            rule_id="siem-no-agent",
            message=(
                f"Host {host_only} no tiene ningun SIEM agent corriendo "
                "(no Wazuh, no Filebeat, no Osquery, no auditd). Sin "
                "logging/monitoring centralizado."
            ),
            evidence=f"Daemon status: {statuses}",
            remediation=(
                "Instalar SIEM agent. Para banca-LATAM se recomienda Wazuh:\n"
                "  curl -so wazuh-agent.deb https://packages.wazuh.com/...\n"
                "  WAZUH_MANAGER='<mgr_ip>' dpkg -i wazuh-agent.deb\n"
                "  systemctl enable --now wazuh-agent\n"
                "Como minimo (banca-safe baseline):\n"
                "  apt install auditd rsyslog\n"
                "  systemctl enable --now auditd rsyslog\n"
                "  + configurar remote syslog hacia el SIEM central."
            ),
            severity_rank=_SEV_RANK["HIGH"],
        )

    # CASO 3: Wazuh active OR auditd + remote syslog activos — OK
    if wazuh_active:
        return None
    if auditd_active and rsyslog_active:
        return None

    # CASO 4: SIEM heterogeneo (filebeat sin wazuh, o auditd solo) —
    # MEDIUM info. Operationally menos optimo que un stack unificado.
    active_daemons = ", ".join(name for name, status in statuses.items() if status == "active")
    return Finding(
        cwe="CWE-778",
        severity="MEDIUM",
        host=f"{user}@{host_only}",
        rule_id="siem-heterogeneous",
        message=(
            f"Host {host_only} tiene SIEM heterogeneo. Active: "
            f"{active_daemons}. Faltan: Wazuh OR (auditd + rsyslog remoto)."
        ),
        evidence=f"Daemon status: {statuses}",
        remediation=(
            "Unificar stack SIEM. Si la flota usa Wazuh manager, "
            "instalar wazuh-agent para que el host envie eventos al "
            "mismo manager central. Sino, validar que filebeat/osquery "
            "tengan output configurado a un Elastic/Splunk central."
        ),
        severity_rank=_SEV_RANK["MEDIUM"],
    )


# F202.Q — SMB anonymous share enumeration detector (CWE-200 + CWE-548).
# Surfaced POC Britimp .200.26 mediavault: smbclient -L -N anonymous
# login successful + share name visible (`rpa-teisa`). Aunque el tree-
# connect quedo denied (file access protected), la disclosure del
# nombre del share revelo cliente Britimp (TEISA). Banking-relevant:
# nombres de shares suelen revelar clientes / proyectos / sistemas
# internos -> vector de pivot post-credential-compromise.
#
# Severidad: LOW por default (info disclosure menor). MEDIUM cuando
# share name matchea keywords sensitive (banking / payment / customer
# / prod / rpa).

_SMB_FAILURE_MARKERS = (
    "connection refused",
    "no route to host",
    "session setup failed",
    "logon failure",
    "access denied",
)

# Keywords en share names que elevan severidad a MEDIUM
_SMB_SENSITIVE_KEYWORDS = (
    "bank",
    "banco",
    "payment",
    "pago",
    "swift",
    "rpa",
    "automation",
    "prod",
    "production",
    "customer",
    "cliente",
    "backup",
    "bkp",
    "vault",
    "secret",
    "finance",
    "finanzas",
    "core",
)


def _check_smb_anonymous_shares(svc: DiscoveredService) -> Finding | None:
    """F202.Q — Probe SMB :445 for anonymous share listing.

    Read-only: `smbclient -L //host -N` lists share names without
    needing credentials. File access is a separate operation that we
    do NOT perform — solo la enumeracion del share-list es banca-safe.

    Returns Finding when:
      - Anonymous login succeeds AND
      - At least one non-IPC$ share name is listed.
    Severidad LOW por default; MEDIUM cuando share name matchea
    keywords sensitive (banking / payment / customer / etc).
    """
    if svc.state != "open" or svc.port != 445:
        return None

    try:
        proc = subprocess.run(
            ["smbclient", "-L", f"//{svc.host}", "-N", "--option=client min protocol=SMB2"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        # smbclient missing in operator host — graceful skip
        return None
    except Exception:  # noqa: BLE001
        return None

    out = proc.stdout + "\n" + proc.stderr
    out_lower = out.lower()

    # F202.S code-quality: la condicion previa con failure_markers era
    # dead logic (un subset del check siguiente). Si no hay "anonymous
    # login successful" en output, no hay nada que reportar — sin
    # importar si hay failure markers.
    if "anonymous login successful" not in out_lower:
        return None

    # Parse share names from output:
    #   Sharename       Type      Comment
    #   ---------       ----      -------
    #   rpa-teisa       Disk
    #   IPC$            IPC       IPC Service
    shares: list[str] = []
    in_share_section = False
    for line in proc.stdout.splitlines():
        if "Sharename" in line and "Type" in line:
            in_share_section = True
            continue
        if "---------" in line:
            continue
        if in_share_section:
            stripped = line.strip()
            if not stripped:
                in_share_section = False
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                name = parts[0]
                if name != "IPC$" and not name.endswith("$"):
                    shares.append(name)

    if not shares:
        return None

    sensitive_hits = [s for s in shares if any(kw in s.lower() for kw in _SMB_SENSITIVE_KEYWORDS)]
    severity = "MEDIUM" if sensitive_hits else "LOW"

    shares_str = ", ".join(shares[:5])
    if len(shares) > 5:
        shares_str += f", + {len(shares) - 5} more"

    return Finding(
        cwe="CWE-200",
        severity=severity,
        host=f"{svc.host}:{svc.port}",
        rule_id="smb-anonymous-list",
        message=(
            f"SMB en {svc.host}:445 permite anonymous login para listar "
            f"share names ({len(shares)} share(s) visibles: {shares_str})."
            + (
                f" {len(sensitive_hits)} share(s) revelan funcion sensible "
                "(banking / RPA / customer / prod) — pre-attack recon vector."
                if sensitive_hits
                else ""
            )
        ),
        evidence=(
            f"smbclient -L //{svc.host} -N retorno:\n  Anonymous login successful\n  Shares: {', '.join(shares)}"
        ),
        remediation=(
            "Deshabilitar enumeracion anonymous de shares:\n"
            "  - **Linux Samba** (smb.conf [global]):\n"
            "      restrict anonymous = 2\n"
            "      map to guest = Never\n"
            "      guest account = nobody (NO root!)\n"
            "      lanman auth = no\n"
            "      ntlm auth = no\n"
            "  - **Windows**: Group Policy > Security Settings > Local "
            "Policies > Security Options:\n"
            '      "Network access: Do not allow anonymous enumeration of '
            'SAM accounts and shares" = Enabled\n'
            '      "Network access: Restrict anonymous access to Named '
            'Pipes and Shares" = Enabled\n'
            "Impacto banking: share names suelen revelar clientes, "
            "proyectos, fileservers internos. Aun cuando file-access "
            "esta protegido (tree-connect denied), la disclosure del "
            "share-list es info-leak pre-attack."
        ),
        severity_rank=_SEV_RANK[severity],
    )


# F202.N — BGP (Border Gateway Protocol) exposure detector (CWE-200 + CWE-306).
# Surfaced by POC Britimp BASE .203.1: router edge con TCP/179 abierto al
# data plane. Banking impact: si el peer auth (MD5 / TCP-AO) no esta
# activo Y el firewall no restringe :179 a los IPs de peers BGP
# autorizados, atacante puede iniciar sesion BGP falsa e inyectar
# rutas (BGP hijack) → redirigir trafico bancario, MITM portales.
# Severidad MEDIUM (banner grab no confirma si auth esta o no — la
# remediation siempre apunta a TCP-AO + ACL + prefix-list).


def _check_bgp_exposure(svc: DiscoveredService) -> Finding | None:
    """F202.N — Detect BGP TCP/179 exposed to data plane.

    BGP routers expose TCP/179 only to authorized peers in a
    well-configured environment. Visibility from the data plane (where
    workloads / users live) is a banking-relevant gap:
      - Without TCP-AO / MD5 auth: attacker can attempt BGP session
        hijack with crafted OPEN messages.
      - Without prefix-list inbound: even with auth, malicious peer
        announcement of arbitrary prefixes redirects bank traffic.
    The check itself is read-only — TCP connect only, no BGP OPEN
    message sent (banca-safe).
    """
    if svc.state != "open" or svc.port != 179:
        return None

    return Finding(
        cwe="CWE-200",
        severity="MEDIUM",
        host=f"{svc.host}:{svc.port}",
        rule_id="bgp-exposed-data-plane",
        message=(
            f"BGP (TCP/179) accesible en {svc.host}:{svc.port} desde el "
            "data plane. Si el firewall no restringe :179 a peers BGP "
            "autorizados y el peer auth (TCP-AO / MD5) no esta activo, "
            "atacante puede iniciar sesion BGP falsa o spoofear "
            "anuncios de prefijos."
        ),
        evidence=(
            f"nmap detecto puerto 179/tcp open en {svc.host}. Banner: {svc.product or '(suprimido / tcpwrapped)'}"
        ),
        remediation=(
            "Banking-mandatory hardening BGP:\n"
            "  - **TCP-AO / RFC 5925** (recomendado) o MD5 / RFC 2385 "
            "para autenticar cada sesion peer:\n"
            "    Cisco IOS:  neighbor X password 7 <secret>\n"
            "                neighbor X ao keychain <keychain>\n"
            "    Juniper:    set protocols bgp group X authentication-key <md5>\n"
            "    FortiGate:  config router bgp / neighbor X / set password X\n"
            "    MikroTik:   /routing bgp peer set X password=<secret>\n"
            "  - **prefix-list inbound** para limitar prefijos aceptados:\n"
            "    neighbor X prefix-list IN-ALLOW in\n"
            "    Evita inyeccion de rutas arbitrarias.\n"
            "  - **ACL TCP/179**: el firewall debe DENY :179 desde TODO "
            "salvo IPs de peers autorizados (lista corta — normalmente "
            "1-3 IPs del ISP o nodos BGP internos).\n"
            "  - **RPKI ROV** (Route Origin Validation) para validar "
            "anuncios externos contra el RIR.\n"
            "  - Banca-LATAM: verificar que sesiones eBGP a ISP tienen "
            "TODO lo anterior + GTSM (TTL 255) cuando los peers estan "
            "directamente conectados (RFC 5082).\n"
            "Verify post-fix: desde IP no-peer, `nc -zv <host> 179` "
            "debe retornar timeout (no connection refused — refused "
            "expone que :179 esta corriendo)."
        ),
        severity_rank=_SEV_RANK["MEDIUM"],
    )


# F199.O — Per-engine metadata for the database-exposed check. Maps the
# (service name, port) pair to the proper rule_id / human label /
# vendor-specific remediation snippet. Keeps the generic _check_database
# function below readable.
_DATABASE_ENGINES: dict[tuple[str, int], dict[str, str]] = {
    ("mysql", 3306): {
        "engine": "mysql",
        "pretty": "MySQL",
        "remediation": (
            "Habilitar require_secure_transport=ON, restringir bind-address "
            "a la red de management, exigir TLS en todos los usuarios "
            "(REQUIRE SSL en el CREATE USER)."
        ),
    },
    ("mysql", 33060): {
        "engine": "mysql",
        "pretty": "MySQL X Protocol",
        "remediation": (
            "Deshabilitar el X Protocol si no se usa (mysqlx en my.cnf). "
            "Sino, exigir TLS en mysqlx_socket_owner y restringir bind."
        ),
    },
    ("postgresql", 5432): {
        "engine": "postgresql",
        "pretty": "PostgreSQL",
        "remediation": (
            "En postgresql.conf: ssl = on, ssl_cert_file, ssl_key_file. "
            "En pg_hba.conf: usar `hostssl` en lugar de `host` para forzar TLS. "
            "Restringir listen_addresses a la red interna."
        ),
    },
    ("mongodb", 27017): {
        "engine": "mongodb",
        "pretty": "MongoDB",
        "remediation": (
            "En mongod.conf: net.tls.mode = requireTLS + net.tls.certificateKeyFile. "
            "Forzar authentication via security.authorization = enabled. "
            "Bind-IP solo a la red de aplicación."
        ),
    },
    ("redis", 6379): {
        "engine": "redis",
        "pretty": "Redis",
        "remediation": (
            "En redis.conf: tls-port 6380 + tls-cert-file/tls-key-file. "
            "Setear `requirepass <strong>` o usar ACL (Redis 6+). "
            "Bind 127.0.0.1 si no es accedido remotamente."
        ),
    },
    # F202.J — Microsoft SQL Server (TDS protocol). Surfaced by POC
    # Britimp .15: ms-sql-s en :1433 expuesto al segmento sin flag —
    # F199.O cubria solo MySQL/PostgreSQL/MongoDB/Redis. Sin esto
    # cualquier cliente bancario con SQL Server (core-banking +
    # reporting comun en stacks Microsoft) quedaba sin deteccion
    # automatica de DB exposure.
    ("ms-sql-s", 1433): {
        "engine": "mssql",
        "pretty": "Microsoft SQL Server",
        "remediation": (
            "Forzar TLS: SQL Server Configuration Manager > Protocols > "
            "Properties > Force Encryption = Yes + Certificate signed por "
            "CA interna. Restringir TCP/IP a la VLAN de aplicacion. "
            "Deshabilitar SQL Browser (1434/UDP) si no se necesita "
            "named-instance discovery. Auditar logins SA / mixed-mode "
            "auth — preferir Windows Auth integrada con AD."
        ),
    },
    ("ms-sql", 1433): {
        "engine": "mssql",
        "pretty": "Microsoft SQL Server",
        "remediation": (
            "Forzar TLS: SQL Server Configuration Manager > Protocols > "
            "Properties > Force Encryption = Yes + Certificate signed por "
            "CA interna. Restringir TCP/IP a la VLAN de aplicacion. "
            "Deshabilitar SQL Browser (1434/UDP) si no se necesita "
            "named-instance discovery. Auditar logins SA / mixed-mode "
            "auth — preferir Windows Auth integrada con AD."
        ),
    },
    ("ms-sql-m", 1434): {
        "engine": "mssql-browser",
        "pretty": "Microsoft SQL Server Browser",
        "remediation": (
            "El SQL Browser service (1434/UDP) expone los nombres de "
            "instancias y sus puertos dinamicos — recon util pre-attack. "
            "Deshabilitar via SQL Server Configuration Manager > SQL Server "
            "Browser > Stop + Disabled startup type, salvo que se necesite "
            "named-instance discovery desde subnets distintas. Si se "
            "mantiene, restringirlo via firewall a las subnets de "
            "aplicacion unicamente."
        ),
    },
    # F202.K — Oracle Database TNS Listener. Banking-relevant: la mayoria
    # de los core-banking suites de LATAM (T24, Flexcube, Finacle,
    # Bantotal) corren sobre Oracle DB. El TNS Listener en :1521 sin
    # TCPS encryption es el patron mas comun de DB exposure en bancos
    # con stack Oracle. Severity HIGH por defecto: TNS protocol en
    # cleartext + el listener historicamente acepta `service_name`
    # discovery sin auth (TNS Poison / CVE-2012-1675 si no esta
    # parcheado a 11g+ con COST settings).
    ("oracle-tns", 1521): {
        "engine": "oracle",
        "pretty": "Oracle Database TNS Listener",
        "remediation": (
            "Forzar TCPS (TNS sobre TLS): listener.ora -> "
            "(ADDRESS = (PROTOCOL = TCPS)(HOST = ...)(PORT = 2484)) "
            "+ sqlnet.ora con SQLNET.ENCRYPTION_SERVER = required, "
            "SQLNET.CRYPTO_CHECKSUM_SERVER = required. "
            "Cerrar 1521 plaintext via firewall una vez que las "
            "applicaciones migren a 2484. "
            "Hardening del Listener: listener.ora -> "
            "SECURE_REGISTER_<listener> = (TCPS) + ADMIN_RESTRICTIONS_<listener> = ON "
            "para bloquear remote SET / SHOW / SHUTDOWN. "
            "Auditar parche TNS Poison (CVE-2012-1675): requires "
            "11.2.0.4+ con COST = (PROTOCOL = TCPS) y NO permitir "
            "SERVICE_NAME registration desde clientes no autenticados. "
            "Banca-LATAM: restringir Listener a la VLAN de aplicacion "
            "(NO al segmento de servidores generales) — un compromiso "
            "lateral basico llega a core-banking sin saltar firewall."
        ),
    },
    ("oracle-tns", 1522): {
        "engine": "oracle",
        "pretty": "Oracle Database TNS Listener (alternate port)",
        "remediation": (
            "Mismo hardening que TNS Listener default — operador usa "
            "puerto no-default para reducir scanning automatico, pero "
            "la superficie es identica. Forzar TCPS, ADMIN_RESTRICTIONS, "
            "SECURE_REGISTER. VLAN dedicada de DB obligatoria."
        ),
    },
    # tns is the legacy / generic service name some nmap probes return.
    ("tns", 1521): {
        "engine": "oracle",
        "pretty": "Oracle Database TNS Listener",
        "remediation": (
            "Ver remediation oracle-tns 1521 — banner detection variant. "
            "Forzar TCPS + ADMIN_RESTRICTIONS_<listener> = ON. "
            "Auditar TNS Poison patch (CVE-2012-1675)."
        ),
    },
}


def _resolve_database_engine(svc: DiscoveredService) -> dict[str, str]:
    """F199.O — Identify the database engine from svc.service and svc.port.

    The port-only fallback covers cases where nmap couldn't grab the
    service banner (filtered version detection, slow throttle). Returns
    a dict with `engine`, `pretty`, `remediation`. Defaults to a
    generic "database" entry when nothing matches.
    """
    service = (svc.service or "").lower()
    # Try (service, port) first — most specific.
    key = (service, svc.port)
    if key in _DATABASE_ENGINES:
        return _DATABASE_ENGINES[key]
    # Fallback by port alone.
    for (_engine, port), meta in _DATABASE_ENGINES.items():
        if port == svc.port:
            return meta
    # Generic fallback.
    return {
        "engine": "database",
        "pretty": f"Database service on port {svc.port}",
        "remediation": (
            "Restringir bind-address al management LAN, forzar TLS en la "
            "conexión, exigir autenticación fuerte (no defaults)."
        ),
    }


def _check_mysql(svc: DiscoveredService) -> list[Finding]:
    """F199.O — Database-port open + plaintext (no forced TLS detectable
    remotely). Funciona para MySQL / PostgreSQL / MongoDB / Redis — el
    rule_id y la remediation salen de _resolve_database_engine para que
    el reporte refleje el engine real, no "mysql" hardcodeado.
    """
    meta = _resolve_database_engine(svc)
    engine = meta["engine"]
    pretty = meta["pretty"]
    return [
        Finding(
            cwe="CWE-319",
            severity="HIGH",
            host=f"{svc.host}:{svc.port}",
            rule_id=f"{engine}-exposed",
            message=f"{pretty} accesible en {svc.host}:{svc.port} sin TLS forzado.",
            evidence=f"nmap detectó {svc.product or engine} {svc.version} en tcp/{svc.port}",
            remediation=meta["remediation"],
            severity_rank=_SEV_RANK["HIGH"],
        )
    ]


# F202.W — MySQL deep audit con creds (CWE-668 + CWE-319 + CWE-521).
# Surfaced docker/vulnerable-lab smoke test target-db: ground truth
# incluye bind 0.0.0.0 + sin require_secure_transport + weak password,
# pero _check_mysql() solo emite el genérico "mysql-exposed" sin
# detección de config interna. Con creds DB (env KRYON_DB_USER +
# KRYON_DB_PASSWORD) podemos conectar y leer @@variables.
#
# Soft dep `pymysql`: si no esta instalado, graceful skip.
# Banca-safe: SELECT-only queries de variables session/global, sin
# INSERT/UPDATE/DELETE. read-only contract.


def _check_mysql_deep(svc: DiscoveredService) -> list[Finding]:
    """F202.W — Deep MySQL audit con creds.

    Requires `KRYON_DB_USER` + `KRYON_DB_PASSWORD` env vars. Sin ellos
    -> graceful skip (no finding, no error).
    """
    if svc.state != "open":
        return []
    if svc.port not in (3306, 33060):
        return []

    db_user = os.environ.get("KRYON_DB_USER", "").strip()
    db_password = os.environ.get("KRYON_DB_PASSWORD", "").strip()
    if not db_user or not db_password:
        return []  # no creds — graceful skip

    try:
        import pymysql
    except ImportError:
        return []  # soft dep missing

    findings: list[Finding] = []
    try:
        conn = pymysql.connect(
            host=svc.host,
            port=svc.port,
            user=db_user,
            password=db_password,
            connect_timeout=6,
            read_timeout=6,
        )
    except Exception:  # noqa: BLE001 — auth fail / network / timeout
        return []

    try:
        cur = conn.cursor()

        # Helper: run single-value query, swallow errors
        def _q(query: str, col: int = 0):
            try:
                cur.execute(query)
                row = cur.fetchone()
                return row[col] if row else None
            except Exception:  # noqa: BLE001
                return None

        bind_addr = _q("SELECT @@bind_address")
        require_ssl = _q("SELECT @@require_secure_transport")
        # SHOW VARIABLES LIKE returns ('var_name', 'value') — queremos value
        have_ssl = _q("SHOW VARIABLES LIKE 'have_ssl'", col=1)
        local_infile = _q("SELECT @@local_infile")
        version = _q("SELECT VERSION()")

        # CWE-668 — bind 0.0.0.0 exposes DB a toda la red en lugar
        # de a la VLAN de aplicacion.
        if bind_addr == "0.0.0.0" or bind_addr == "::":
            findings.append(
                Finding(
                    cwe="CWE-668",
                    severity="HIGH",
                    host=f"{svc.host}:{svc.port}",
                    rule_id="mysql-bind-public",
                    message=(
                        f"MySQL @@bind_address={bind_addr} — DB escucha "
                        "en todas las interfaces. Cualquier host del "
                        "segmento puede conectar."
                    ),
                    evidence=f"SELECT @@bind_address -> '{bind_addr}'",
                    remediation=(
                        "En my.cnf [mysqld]:\n"
                        "  bind-address = <VLAN_DB_INTERNAL_IP>\n"
                        "Si es cluster, agregar TODAS las IPs de los nodos "
                        "permitidos (bind-address = 10.0.1.5,10.0.1.6).\n"
                        "Banking: NUNCA usar 0.0.0.0 en produccion."
                    ),
                    severity_rank=_SEV_RANK["HIGH"],
                )
            )

        # CWE-319 — TLS available pero NO required
        if require_ssl == 0 or require_ssl is None:
            # require_ssl=None puede ser version <5.7 que no tiene
            # la variable. Solo flag si have_ssl=YES (TLS configured
            # pero no enforced).
            if have_ssl == "YES":
                findings.append(
                    Finding(
                        cwe="CWE-319",
                        severity="HIGH",
                        host=f"{svc.host}:{svc.port}",
                        rule_id="mysql-tls-not-required",
                        message=(
                            "MySQL tiene SSL configurado (have_ssl=YES) "
                            "pero NO forza TLS (require_secure_transport=0). "
                            "Clientes pueden conectar plaintext."
                        ),
                        evidence=(
                            f"SELECT @@require_secure_transport -> {require_ssl}\n"
                            f"SHOW VARIABLES LIKE 'have_ssl' -> 'YES'"
                        ),
                        remediation=(
                            "En my.cnf [mysqld]:\n"
                            "  require_secure_transport = ON\n"
                            "Adicional: en CREATE USER agregar REQUIRE SSL\n"
                            "para cada user de aplicacion. Rotar las creds "
                            "que ya pasaron por la red plaintext."
                        ),
                        severity_rank=_SEV_RANK["HIGH"],
                    )
                )

        # CWE-200 — local_infile permite LOAD DATA LOCAL desde client
        # (vector de exfiltracion de archivos del client si el server
        # esta comprometido). MEDIUM porque requiere chain con SQLi.
        if local_infile == 1:
            findings.append(
                Finding(
                    cwe="CWE-200",
                    severity="MEDIUM",
                    host=f"{svc.host}:{svc.port}",
                    rule_id="mysql-local-infile-enabled",
                    message=(
                        "MySQL local_infile=1 permite LOAD DATA LOCAL "
                        "INFILE — un server malicioso (post-compromise o "
                        "MITM) puede solicitar archivos del filesystem "
                        "del cliente."
                    ),
                    evidence=f"SELECT @@local_infile -> {local_infile}",
                    remediation=(
                        "En my.cnf [mysqld]:\n"
                        "  local_infile = 0\n"
                        "En cliente: --local-infile=0 by default desde "
                        "MySQL 8.x salvo override explicito."
                    ),
                    severity_rank=_SEV_RANK["MEDIUM"],
                )
            )

        # CWE-1104 — MySQL EOL version. 5.7 EOL Oct 2023. 5.6/5.5/5.0 EOL hace anos.
        if version and re.match(r"^5\.(7|6|5|0|1)\.", version):
            findings.append(
                Finding(
                    cwe="CWE-1104",
                    severity="HIGH",
                    host=f"{svc.host}:{svc.port}",
                    rule_id="mysql-version-eol",
                    message=(f"MySQL {version} es EOL. Sin patches de seguridad desde el end-of-life date."),
                    evidence=f"SELECT VERSION() -> '{version}'",
                    remediation=(
                        "Upgrade path:\n"
                        "  - MySQL 5.7 (EOL Oct 2023) -> 8.0 o 8.4 LTS\n"
                        "  - MySQL 5.6 (EOL Feb 2021) -> 8.0\n"
                        "  - MySQL 5.5 (EOL Dec 2018) -> 8.0\n"
                        "Usar mysql_upgrade post-major-version-bump."
                    ),
                    severity_rank=_SEV_RANK["HIGH"],
                )
            )
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    return findings


# -----------------------------------------------------------------------------
# F77.A — compliance + agent integration
# -----------------------------------------------------------------------------


def _run_compliance(
    frameworks: list[str],
    *,
    host: str,
    ssh_target: str | None,
    ssh_password: str | None,
    ssh_key: str | None,
) -> dict[str, list[dict]]:
    """Run the compliance runner per framework.

    Returns a dict keyed by framework id with CheckResult-dict lists
    ready to feed ``multi_framework_pdf.render_multi_framework_pdf``.
    """
    from kryon.compliance.checks.base import CheckContext
    from kryon.compliance.runner import (
        _import_all_checks,
        registered_checks,
        run_all,
    )

    # Side-effect import populates _REGISTERED_CHECKS.
    _import_all_checks()

    ssh_user = ""
    ssh_port = 22
    if ssh_target:
        user, _, host_port = ssh_target.partition("@")
        ssh_user = user
        host_only, _, port = host_port.partition(":")
        host = host_only or host
        ssh_port = int(port) if port else 22

    # CheckContext only exposes ssh_key_path (no password field) — mirror
    # that. For password-only engagements the runner falls back to the
    # SSHPASS env var, which matches how the deterministic Phase 2 checks
    # already authenticate.
    if ssh_password:
        os.environ.setdefault("SSHPASS", ssh_password)
    ctx = CheckContext(
        host=host,
        ssh_user=ssh_user,
        ssh_key_path=ssh_key or "",
        ssh_port=ssh_port,
    )

    all_results = run_all(ctx)
    all_dicts = [r.to_json_reproducible() if hasattr(r, "to_json_reproducible") else r.__dict__ for r in all_results]

    # Bucket results by their registered framework. Each Check carries
    # a `frameworks` attribute listing the regulations it maps to.
    check_frameworks: dict[str, set[str]] = {}
    for check in registered_checks():
        fws = getattr(check, "frameworks", None) or [getattr(check, "framework", "pci_dss")]
        check_frameworks[check.control_id] = {fw.lower() for fw in fws}

    wanted = {fw.lower() for fw in frameworks}
    out: dict[str, list[dict]] = {fw: [] for fw in wanted}
    for r in all_dicts:
        control_id = r.get("control_id", "")
        result_fws = check_frameworks.get(control_id, set())
        for fw in wanted:
            if fw in result_fws or not result_fws:
                out[fw].append(r)
    # Drop frameworks with no results so the PDF renderer's
    # "must contain at least one framework" guard doesn't trip.
    return {fw: lst for fw, lst in out.items() if lst}


# Match any fenced JSON block (array or object). The agent may emit:
#   1. ```json [ ... ]```            → bare array of findings
#   2. ```json { "findings": [...] }```  → object with findings key + summary
#   3. raw JSON without fences
_AGENT_JSON_FENCE_RE = re.compile(
    r"```(?:json)?\s*([\[{].*?[\]}])\s*```",
    re.DOTALL,
)


def _parse_agent_findings(text: str, *, target_host: str) -> list[Finding]:
    """Extract structured findings from the agent's final output.

    F150 — R1-tolerant. Uses ``kryon.parsing.llm_output`` to:
      1. Strip ``<think>...</think>`` reasoning blocks (R1 distill).
      2. Walk every JSON candidate in the cleaned text.
      3. Reject tool-call shapes (``{"name": ..., "arguments": ...}``)
         and keep only finding-shaped dicts.

    Accepts the legacy shapes too: a fenced ```json``` block, a bare
    array, or ``{"findings": [...]}`` envelope. Items missing required
    fields are skipped rather than failing the whole engagement.
    """
    if not text:
        return []

    from kryon.parsing.llm_output import extract_finding_json_blocks

    items = extract_finding_json_blocks(text)
    if not items:
        return []

    # F181.C — gated parse-decision trail. Stays dormant unless
    # ``KRYON_DEBUG_PARSE`` is set, so production runs aren't slowed
    # by extra disk I/O. The trail is what found the F181 self-confirm
    # FP path; keep it available for future regression hunting.
    _debug_parse = os.environ.get("KRYON_DEBUG_PARSE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    _debug_path = None
    if _debug_parse:
        import json as _json
        from pathlib import Path as _Path

        _debug_path = _Path(".kryon/debug") / f"parse_{os.environ.get('KRYON_ENGAGEMENT_ID', 'unknown')}.jsonl"
        _debug_path.parent.mkdir(parents=True, exist_ok=True)
        with _debug_path.open("a", encoding="utf-8") as _fh:
            _fh.write(_json.dumps({"event": "parse_start", "items": len(items), "text_len": len(text)}) + "\n")

    from kryon.redaction.pan_redactor import redact_sensitive
    from kryon.validation.cve_applicability import (
        extract_target_tech_stack,
        is_cve_applicable_for_finding,
    )
    from kryon.validation.cve_validator import validate_finding_cve
    from kryon.validation.finding_applicability import (
        is_finding_applicable_general,
    )

    # F180 — derive tech stack from the agent's PRE-JSON narration. The
    # model typically mentions detected technologies before emitting
    # findings (whatweb dumps, "X-Powered-By: Express", etc.). We
    # deliberately exclude the JSON block itself — otherwise a finding's
    # own ``message`` mentioning the wrong-stack product (e.g. "JAMon
    # 2.7") would be self-confirming and the gate would never fire.
    json_start_match = re.search(r"```|^\s*\[\s*\{|^\s*\{", text, re.MULTILINE)
    narration = text[: json_start_match.start()] if json_start_match else text
    tech_stack = extract_target_tech_stack(narration)

    # F192 — persist whatever stack info we have on this host so the
    # next engagement gets the authoritative hint without re-dumping
    # WhatWeb signals. We union the narration-derived tokens with the
    # F180.B hardcoded host hint (if any) — otherwise reporting-phase
    # narration alone can be too thin to produce a useful fingerprint,
    # and the file never gets written.
    if target_host:
        try:
            from kryon.validation.cve_applicability import _target_tech_hint
            from kryon.validation.target_fingerprint_cache import (
                save_target_fingerprint,
            )

            persisted_stack = set(tech_stack) | _target_tech_hint(target_host)
            if persisted_stack:
                save_target_fingerprint(target_host, persisted_stack)
        except Exception as exc:  # noqa: BLE001 — non-fatal
            logger.debug("F192 fingerprint save failed: %s", exc)

    out: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity", "")).upper()
        if sev not in _SEV_RANK:
            continue
        msg = str(item.get("message") or item.get("finding") or "").strip()
        if not msg:
            continue
        # F151 — drop findings whose rule_id looks like a CVE but
        # fails format/year/cache validation. Catches LLM-invented
        # CVE IDs that survived the F150 parser.
        cve_ok, cve_reason = validate_finding_cve(item)
        if _debug_path:
            import json as _json

            with _debug_path.open("a", encoding="utf-8") as _fh:
                _fh.write(
                    _json.dumps(
                        {
                            "event": "F151_check",
                            "rule_id": item.get("rule_id"),
                            "host": item.get("host"),
                            "ok": cve_ok,
                            "reason": cve_reason,
                        }
                    )
                    + "\n"
                )
        if not cve_ok:
            logger.warning("F151 dropped LLM finding: %s", cve_reason)
            continue
        # F180 — third validation gate: even when the CVE is real and
        # published (F171), it might not apply to this target. The F170
        # bench saw gpt-oss emit CVE-2013-6235 (JAMon JSP XSS) against
        # a Node.js target — F173 drops it when the CVE's products
        # don't overlap with the detected tech stack.
        app_ok, app_reason = is_cve_applicable_for_finding(item, tech_stack=tech_stack)
        if _debug_path:
            import json as _json

            with _debug_path.open("a", encoding="utf-8") as _fh:
                _fh.write(
                    _json.dumps(
                        {
                            "event": "F180_check",
                            "rule_id": item.get("rule_id"),
                            "host": item.get("host"),
                            "tech_stack": sorted(tech_stack),
                            "ok": app_ok,
                            "reason": app_reason,
                        }
                    )
                    + "\n"
                )
        if not app_ok:
            logger.warning("F173 dropped LLM finding: %s", app_reason)
            continue
        # F183 — broader applicability gate: catches FPs whose
        # rule_id is non-CVE-shaped (e.g. ``WEB-XSS-001``) but whose
        # message/evidence still cite a wrong-stack product (the F182
        # bench saw the model disguise the JAMon FP under
        # ``rule_id=WEB-XSS-001``). Scans message + evidence for product
        # keywords and compares against the same effective stack.
        gen_ok, gen_reason = is_finding_applicable_general(item, tech_stack=tech_stack)
        if _debug_path:
            import json as _json

            with _debug_path.open("a", encoding="utf-8") as _fh:
                _fh.write(
                    _json.dumps(
                        {
                            "event": "F183_check",
                            "rule_id": item.get("rule_id"),
                            "host": item.get("host"),
                            "ok": gen_ok,
                            "reason": gen_reason,
                        }
                    )
                    + "\n"
                )
        if not gen_ok:
            logger.warning("F183 dropped LLM finding: %s", gen_reason)
            continue
        # F119 — Redact PAN/CVV/PY-ID before persisting into a Finding.
        # The agent may have echoed sensitive data from a response body
        # into its narration; redact at the boundary, not at render time.
        msg_red = redact_sensitive(msg).text
        ev_red = redact_sensitive(str(item.get("evidence", ""))[:800]).text
        rem_red = redact_sensitive(str(item.get("remediation", ""))).text
        out.append(
            Finding(
                cwe=str(item.get("cwe", "CWE-0")),
                severity=sev,
                host=str(item.get("host", target_host)),
                rule_id=str(item.get("rule_id", "agent-finding")),
                message=msg_red,
                evidence=ev_red,
                remediation=rem_red,
                severity_rank=_SEV_RANK[sev],
                # F134 — LLM-emitted findings start at 0.5; the
                # post-engagement annotate_confidence pass may boost
                # them if a deterministic finding corroborates.
                confidence=0.5,
                needs_verification=True,
            )
        )
    return out


def _invoke_agent_deepening(
    console,
    *,
    target: str,
    scope: str,
    findings: list[Finding],
    families: list[str] | None = None,
) -> tuple[list[str], list[Finding]]:
    """Spin up the unified Kryon agent for one deep-dive turn.

    Returns (observations, new_findings). The agent is asked to emit
    structured JSON findings; we parse the fenced block and convert
    each item to a Finding. Failures are non-fatal — deterministic
    Phase 2 + Phase 2b output is the authoritative surface and the
    agent contributes depth, not correctness.

    F85.D — when `families` is supplied (the result of Phase 1 device
    detection) we hot-swap the agent's skills via
    ``update_agent_skills(agent, ...)`` so the LLM gets skills matched
    against the detected target profile instead of the generic ones
    chosen at agent construction time. Example: detecting a FortiGate
    swaps recon-scout out for fortigate-audit before Phase 2c runs.
    """
    try:
        from kryon.agents import get_agent_by_name
        from kryon.sdk.agents.run import Runner
    except Exception as exc:  # pragma: no cover — dependency missing
        console.print(f"  [dim]agent deepening skipped: {exc}[/dim]")
        return [], []

    os.environ["KRYON_AGENT_TYPE"] = "kryon"
    try:
        agent = get_agent_by_name("kryon", agent_id="ENGAGE")
    except Exception as exc:  # pragma: no cover — runtime only
        console.print(f"  [yellow]agent load failed: {exc}[/yellow]")
        return [], []

    # F85.D — Mid-engagement skill swap. Build a target profile from
    # the detected families and re-rank skills. Done in a try/except
    # so that any failure here falls back to whatever skills the agent
    # was built with — never block the engagement on a swap miss.
    #
    # F202.AD — extend intent with keywords derived from the actual
    # findings + open services so CWE-detection skills (XSS, SQLi,
    # CSRF, SSRF, auth) activate when relevant. Without this, only
    # device-family skills (proxmox, fortigate) get loaded, so a
    # webapp-heavy target never triggers cwe-79-xss/cwe-89-sqli even
    # though those families are right there in the findings.
    if families or findings:
        try:
            from kryon.skills.loader import SkillLoader
            from kryon.skills.unified_agent import update_agent_skills

            loader = getattr(agent, "_skill_loader", None) or SkillLoader()
            profile = {"tech": list(families or [])}

            # Derive keywords from findings + open services. Use
            # rule_ids and CWEs as hints — the cwe-* skills already
            # have triggers like 'cookie samesite', 'cwe-352', etc.
            #
            # F202.AD — explicit rule_id → cwe-id mapping. The CWE
            # of a finding often points at the CAUSE not the
            # CLASSIFICATION skill we want loaded. E.g. a cookie
            # finding has cwe='CWE-1004' but the skill we want is
            # cwe-352-csrf. So we map rule_id keywords directly to
            # the cwe-N skill IDs that handle those classification
            # families.
            extra_kw: list[str] = []
            for f in findings or []:
                rid = (f.rule_id or "").lower()
                cwe = (f.cwe or "").lower()
                # http-* findings -> webapp + classification skills
                if rid.startswith("http-") or "http" in rid:
                    extra_kw.extend(["webapp", "http", "web vulnerability", "cwe-79", "cwe-89", "cwe-22"])
                if "cookie" in rid or "samesite" in rid or "csrf" in cwe:
                    extra_kw.extend(["cookie", "csrf", "samesite", "cwe-352"])
                if "ssh" in rid or "auth" in rid or "password" in rid or "credential" in rid:
                    extra_kw.extend(["auth", "authentication", "ssh", "cwe-287"])
                if "mysql" in rid or "postgres" in rid or "mongo" in rid or "redis" in rid:
                    extra_kw.extend(["sqli", "sql injection", "database", "cwe-89", "cwe-918"])
                if "admin-open" in rid or "weak-pass" in rid or "default-cred" in rid:
                    extra_kw.append("cwe-287")
                # F202.AD — propagate CWE id itself for direct skill match.
                if cwe.startswith("cwe-"):
                    extra_kw.append(cwe)

            # Dedup but preserve order; loader.match treats user_msg
            # as a single string for keyword scanning.
            seen: set[str] = set()
            uniq_kw = [k for k in extra_kw if not (k in seen or seen.add(k))]

            intent_parts = list(families or []) + uniq_kw + ["audit"]
            intent = " ".join(intent_parts).strip()

            new_skills = loader.match(profile=profile, user_msg=intent)
            if new_skills:
                update_agent_skills(agent, new_skills)
                console.print(
                    f"  [dim]skills swapped: {[s.name for s in new_skills][:6]} "
                    f"(families={families}, +{len(uniq_kw)} kw from findings)[/dim]"
                )
        except Exception as exc:  # pragma: no cover — runtime only
            console.print(f"  [yellow]skill swap skipped: {exc}[/yellow]")

    preamble = (
        f"Ya se ejecutó un barrido determinista contra {target} (scope: "
        f"{scope}) y hay {len(findings)} hallazgos. Revisa los servicios "
        "abiertos y confirma o extiende la superficie de riesgo. "
        "\n\n"
        "Al terminar tu investigación, DEVUELVE un objeto JSON con dos "
        "campos: `summary` (string narrativo corto) y `findings` (array "
        "de nuevos hallazgos NO repetidos de los deterministas). "
        "Cada finding tiene: cwe, severity (CRITICAL/HIGH/MEDIUM/LOW), "
        "host, rule_id (snake_case), message (una línea), evidence "
        "(extracto de salida real), remediation (una frase). "
        "Envuelve el array de findings dentro de un bloque ```json … ``` "
        "para que el orquestador pueda parsearlo."
    )
    summary_lines: list[str] = []
    new_findings: list[Finding] = []
    try:
        import asyncio

        # Max turns is tunable via KRYON_AGENT_MAX_TURNS so that pilots
        # against real targets (where the agent needs many SSH-based
        # checks) can extend it without code changes. Default 4 stays
        # because the engage demo flow expects a quick deepening, not
        # a full audit replacement.
        _agent_max = int(os.environ.get("KRYON_AGENT_MAX_TURNS", "4"))

        async def _one_shot() -> str:
            result = await Runner.run(agent, preamble, max_turns=_agent_max)
            return getattr(result, "final_output", "") or ""

        text = asyncio.run(_one_shot())
        if text:
            summary_lines.append(text.strip())
            new_findings = _parse_agent_findings(text, target_host=target)
    except Exception as exc:  # pragma: no cover — runtime only
        console.print(f"  [yellow]agent turn failed: {exc}[/yellow]")
    return summary_lines, new_findings


# -----------------------------------------------------------------------------
# Phase 2c' (F85.F) — orchestrated multi-phase engagement
# -----------------------------------------------------------------------------


_PHASE_PREAMBLES: dict[str, str] = {
    "recon": (
        "Phase: reconnaissance. The target is {target} (scope: {scope}). "
        "Phase 1 nmap already ran — current findings: {findings_count}. "
        "Detected device families: {families}. Use whatweb / nikto / "
        "nuclei to deepen the service inventory. Report new evidence "
        "as structured JSON findings (cwe, severity, host, rule_id, "
        "message, evidence, remediation)."
    ),
    "proxmox_audit": (
        "Phase: Proxmox VE deep-audit. Target {target}. The compliance "
        "runner already ran the deterministic PVE-* checks; your job "
        "is to chase non-deterministic risks: pveproxy reverse-proxy "
        "configuration, root@pam vs root@pve hygiene, qemu agent "
        "exposure, weak TLS ciphers on 8006, exposed API tokens. "
        "Emit JSON findings."
    ),
    "fortigate_audit": (
        "Phase: FortiGate deep-audit. Target {target}. The FGT-* "
        "deterministic checks already ran; chase: SSL-VPN portal "
        "TLS configuration, web admin idle timeouts, log forwarding "
        "destinations, license expiry, IPS/AV signature freshness. "
        "Emit JSON findings."
    ),
    "ad_recon": (
        "Phase: Active Directory enumeration. Target {target}. Run "
        "ldapsearch / kerberos enumeration / SMB null-session probes "
        "(NON-EXPLOITATIVE — read-only enumeration only). Report "
        "domain controllers, trust relationships, weak Kerberos "
        "encryption, exposed services. Emit JSON findings."
    ),
    "vuln_scan": (
        "Phase: vulnerability assessment. Target {target}. Current "
        "findings ({findings_count}): {findings_summary}. Cross-check "
        "with public CVE databases, run nuclei templates against the "
        "open ports, and propose remediation. Emit JSON findings for "
        "any NEW vulnerabilities not in the deterministic surface."
    ),
    "reporting": (
        "Phase: reporting. Target {target}. {findings_count} findings "
        "accumulated. Write a 3-paragraph executive summary in Spanish "
        "for a non-technical bank manager: (1) critical risks and "
        "business impact, (2) patterns and tendencies, (3) "
        "prioritised recommendation. NO new findings — narrative only."
    ),
    # F128 — Goal-aware phases. Preambles below tell the LLM what to
    # produce when the orchestrator injected one of these phases in
    # response to the declared --objective.
    "compliance_audit": (
        "Phase: compliance audit (goal-driven). Target {target}. "
        "The operator declared a COMPLIANCE goal — verify framework "
        "controls against the running services. Look for: missing "
        "security headers, weak TLS, default credentials, exposed "
        "admin panels, audit-log gaps. Tag findings with the "
        "framework's control prefix (PCI-DSS-x.y, HIPAA-x.y, etc) "
        "so the goal evaluator picks them up. Emit JSON findings."
    ),
    "web_vuln_scan": (
        "Phase: web vulnerability scan (goal-driven). Target {target}. "
        "The operator declared a VULN_SEARCH goal with web-class "
        "vuln types. Run nuclei web templates, fuzz parameters, look "
        "for SQLi/XSS/RCE/SSRF/path-traversal. Read-only payloads "
        "only — no destructive write attempts. Emit JSON findings "
        "tagged with the vuln class in rule_id (e.g. WEB-SQLi-001)."
    ),
    "tech_fingerprint": (
        "Phase: technology fingerprinting (goal-driven). Target "
        "{target}. The operator declared a RECON goal — enumerate "
        "every framework / library / server stack reachable on "
        "this host. Use whatweb, http response headers, JS asset "
        "comments, exposed paths. Emit JSON findings naming each "
        "tech (rule_id=tech-<name>, message includes version when "
        "detected)."
    ),
    "endpoint_discovery": (
        "Phase: endpoint discovery (goal-driven). Target {target}. "
        "RECON goal — enumerate paths the web app exposes. Use "
        "ffuf with a banca-safe wordlist (rate-limited, GET only). "
        "Report each distinct path: rule_id=path-<slug>, message "
        "includes the path + response code + size. NO destructive "
        "requests."
    ),
}


def _phase_preamble(phase_name: str, *, target: str, scope: str, families: list[str], findings: list[Finding]) -> str:
    """Render the per-phase LLM preamble. Falls back to a generic
    template if the phase is unknown (e.g., custom phases injected by
    extended adapt_plan rules)."""
    template = _PHASE_PREAMBLES.get(
        phase_name,
        "Phase: {phase}. Target {target}. Current findings: "
        "{findings_count}. Investigate and emit structured JSON "
        "findings if you discover anything new.",
    )
    findings_summary = "; ".join(f"{f.rule_id} ({f.severity})" for f in findings[:5]) or "none yet"
    rendered = template.format(
        phase=phase_name,
        target=target,
        scope=scope,
        families=", ".join(families) if families else "none detected",
        findings_count=len(findings),
        findings_summary=findings_summary,
    )
    # F150 — R1-tolerant output contract. Tell the model exactly what
    # shape we want at the end, with a concrete example. This stays
    # short so it doesn't dominate the prompt budget but it's enough
    # to push R1 past "I'll just emit tool calls and stop". Instruct
    # models (kryon-14b baseline) already follow this naturally.
    rendered += (
        "\n\nIMPORTANT — after you finish reasoning and running tools, your "
        "FINAL message MUST contain a JSON array of findings, exactly in "
        'this shape: [{"cwe": "CWE-...", "severity": "CRITICAL|HIGH|MEDIUM|'
        'LOW|INFO", "host": "...", "rule_id": "...", "message": "...", '
        '"evidence": "...", "remediation": "..."}]. Emit [] if there are '
        "no findings. Tool-call JSON does NOT count as a finding. "
        "<think>...</think> blocks are accepted; the parser strips them.\n"
        "F152 — In the ``evidence`` field, ALWAYS cite the concrete tool "
        "output that backs the finding: include the literal ``call_id: <id>`` "
        "or ``step <N>`` or ``según output de <tool>``. Findings without a "
        "tool citation will be flagged as needs_verification and may be "
        "dropped under banca-safe mode.\n"
        "F151 — If ``rule_id`` is a CVE, use the real published format "
        "(CVE-YYYY-NNNN with a plausible year). Invented CVE IDs will be "
        "dropped by the validator. Prefer non-CVE rule_ids when you don't "
        "have a verified upstream CVE reference."
    )
    # F159/F160 — Activate Qwen3 dense thinking mode (kryon-14b). The
    # Qwen3 chat template (see ``ollama show kryon-14b --template``)
    # appends `` /think`` at the END of the LAST user message when its
    # ``IsThinkSet`` flag fires. Going through the OpenAI-compat path,
    # Ollama doesn't surface that flag, so we replicate the exact
    # placement by appending ``/think`` as the final whitespace-
    # separated token. Prepending it at the start (as F159 did) made
    # Qwen3 treat ``/think`` as freeform text and the model never
    # entered thinking mode — it produced a runaway pseudo-CoT that
    # never returned, which is why F159.B stalled mid-recon.
    if os.environ.get("KRYON_DEEP_REASONING", "").strip().lower() in {"1", "true", "yes", "on"}:
        rendered = rendered.rstrip() + " /think"
    return rendered


def _invoke_orchestrated_engagement(
    console,
    *,
    target: str,
    scope: str,
    findings: list[Finding],
    families: list[str],
    goal: Any = None,
) -> tuple[list[str], list[Finding], dict | None]:
    """F85.F — Orchestrated multi-phase agent invocation.

    Replacement for ``_invoke_agent_deepening`` activated via the
    ``--orchestrated`` CLI flag. Where the legacy helper invokes a
    single ``Runner.run(max_turns=4)``, this version:

    1. Builds a ``PentestPlan`` via ``PentestPlanner.generate_plan``.
    2. Pre-adapts the plan via ``adapt_plan_for_families`` so detected
       devices (proxmox, fortigate, unifi, windows_ad) get dedicated
       audit phases injected.
    3. Walks the plan phase-by-phase. Each phase runs as a separate
       ``Runner.run`` with a phase-specific preamble and skill set.
    4. After each phase: re-applies ``adapt_plan(plan, findings)`` so
       evidence from earlier phases can grow or skip downstream
       phases (LangChain plan-and-execute pattern).
    5. Honors KRYON_MAX_TURNS / KRYON_PRICE_LIMIT globally (the
       StuckDetector + budget hardening from F85.B/E apply per-phase
       because each phase is a separate ``Runner.run``).

    Failures inside any phase are non-fatal — the failing phase is
    skipped and the orchestrator continues. Deterministic Phase 2/2b
    output remains authoritative; the orchestrator only adds depth.
    """
    try:
        from kryon.agents import get_agent_by_name
        from kryon.audit.action_log import ActionLog, clear_active_log, default_log_path, set_active_log
        from kryon.sdk.agents.run import Runner
        from kryon.state.checkpoint import build_checkpoint, delete_checkpoint, save_checkpoint
        from kryon.tools.autonomous.engagement_goal import GoalEvaluator
        from kryon.tools.autonomous.pentest_planner import PentestPlanner, PhaseStatus
        from kryon.tools.autonomous.phase_evaluator import (
            PhaseVerdict,
            cascade_skip_dependents,
            cascade_skip_remaining,
            consecutive_unproductive_phases,
            dedup_findings_by_rule_and_host,
            evaluate_phase,
        )
    except Exception as exc:  # pragma: no cover
        console.print(f"  [dim]orchestrated path skipped: {exc}[/dim]")
        return [], [], None

    os.environ["KRYON_AGENT_TYPE"] = "kryon"
    try:
        agent = get_agent_by_name("kryon", agent_id="ENGAGE")
    except Exception as exc:  # pragma: no cover
        console.print(f"  [yellow]agent load failed: {exc}[/yellow]")
        return [], []

    planner = PentestPlanner()
    plan = planner.generate_plan(scope=[target], profile="standard")
    # F128 — Goal-aware pre-adaptation. If --objective was declared,
    # inject phases that match the goal kind (compliance_audit,
    # web_vuln_scan, tech_fingerprint, endpoint_discovery) before the
    # family-based + findings-based adapters run.
    plan = planner.adapt_plan_for_goal(plan, goal)
    plan = planner.adapt_plan_for_families(plan, families)
    plan = planner.adapt_plan(plan, findings)

    console.print(f"  [dim]plan: {len(plan.phases)} phases ({', '.join(p.name for p in plan.phases)})[/dim]")

    summary_lines: list[str] = []
    new_findings: list[Finding] = []

    eval_enabled = os.environ.get("KRYON_PHASE_EVAL_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
    retry_max = max(0, int(os.environ.get("KRYON_PHASE_EVAL_RETRY_MAX", "1")))
    # F124 — Circuit breaker: abort the plan if N consecutive phases are
    # unproductive (FAILED/SKIPPED). Default N=3 keeps the orchestrator
    # from burning budget on a plan that has stopped producing evidence.
    failure_threshold = max(1, int(os.environ.get("KRYON_PHASE_FAILURE_THRESHOLD", "3")))
    circuit_breaker_tripped = False

    # F119 — Forensic audit log. One JSONL file per engagement under
    # ``KRYON_AUDIT_LOG_PATH`` (default ``.kryon/audit/``). Args + results
    # pass through the PAN redactor before being persisted.
    engagement_id = (
        os.environ.get("KRYON_ENGAGEMENT_ID", "").strip() or f"engage-{target.replace(':', '_').replace('/', '_')}"
    )
    audit_log = ActionLog(path=default_log_path(engagement_id), engagement_id=engagement_id)
    audit_log.append(
        tool_name="orchestrated_engagement_start",
        args={"target": target, "scope": scope, "families": families},
        result={"phases": [p.name for p in plan.phases]},
        phase="bootstrap",
        status="ok",
    )
    goal_early_terminate = os.environ.get("KRYON_GOAL_EARLY_TERMINATE", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    goal_evaluator = GoalEvaluator() if goal is not None else None
    if goal is not None:
        console.print(f"  [dim]goal:[/dim] [cyan]{goal.kind.value}[/cyan] [dim]({goal.raw[:80]})[/dim]")

    import asyncio

    async def _run_phase(phase, extra_hint: str = "") -> str:
        max_turns = int(os.environ.get("KRYON_AGENT_MAX_TURNS", str(phase.max_turns)))
        preamble = _phase_preamble(
            phase.name,
            target=target,
            scope=scope,
            families=families,
            findings=findings + new_findings,
        )
        if extra_hint:
            preamble = f"{preamble}\n\nRetry hint: {extra_hint}"

        # F131 — Goal-aware phase skill swap. When a phase was injected
        # by adapt_plan_for_goal it carries goal_kind_hint; re-run the
        # SkillLoader.match with the goal so the agent gets the matching
        # playbook bodies (pci-dss-audit / vuln-hunter / recon-scout)
        # loaded before this phase's LLM turn. Best-effort: failures
        # are non-fatal and the agent runs with whatever skills it
        # already had.
        if getattr(phase, "goal_kind_hint", None) and goal is not None:
            try:
                from kryon.skills.loader import SkillLoader
                from kryon.skills.unified_agent import update_agent_skills

                loader_for_phase = getattr(agent, "_skill_loader", None) or SkillLoader()
                profile = {"tech": list(families), "ports": []}
                new_skills = loader_for_phase.match(
                    profile=profile,
                    user_msg=f"{phase.name} {goal.raw}",
                    goal=goal,
                )
                if new_skills:
                    update_agent_skills(agent, new_skills)
            except Exception as exc:  # pragma: no cover
                console.print(f"  [dim]goal-skill swap failed for '{phase.name}': {exc}[/dim]")

        # F185 — Pre-hooks deterministic execution. If any active skill
        # declares ``pre_hooks:`` (e.g. vuln-hunter runs nuclei + nikto
        # before the LLM), execute them now and append the output to
        # the preamble. The model sees authoritative tool output as
        # context — no decision needed on whether to invoke the tool.
        #
        # F185.C — also re-activate skills for THIS phase using the
        # objective + phase name as user_msg. The goal-swap above (line
        # 1022) only fires when phase.goal_kind_hint is set, which the
        # base "recon/vuln_scan/reporting" template phases lack. Without
        # the re-match, ``vuln-hunter`` (which carries the pre_hooks)
        # never enters ``agent._active_skills`` and pre_hooks no-op.
        try:
            from kryon.skills.loader import SkillLoader
            from kryon.skills.pre_hook_integration import maybe_run_pre_hooks
            from kryon.skills.unified_agent import update_agent_skills

            os.environ["KRYON_TARGET_HOST"] = target
            objective_text = goal.raw if goal is not None else ""
            phase_msg = f"{phase.name} {objective_text} {target}".strip()
            try:
                loader_for_hooks = getattr(agent, "_skill_loader", None) or SkillLoader()
                profile = {"tech": list(families), "ports": []}
                hook_skills = loader_for_hooks.match(
                    profile=profile,
                    user_msg=phase_msg,
                    goal=goal,
                )
                if hook_skills:
                    update_agent_skills(agent, hook_skills)
            except Exception:  # pragma: no cover — non-fatal skill match
                pass

            pre_hook_suffix = await maybe_run_pre_hooks(agent, phase_msg, console)
            if pre_hook_suffix:
                preamble = preamble + pre_hook_suffix
        except Exception as exc:  # pragma: no cover — non-fatal
            console.print(f"  [dim]pre-hooks skipped for '{phase.name}': {exc}[/dim]")

        # F123 — Register the active ActionLog so every tool call inside
        # this phase lands as its own audit entry. Cleared in finally so
        # one phase's audit doesn't bleed into the next phase or into
        # other agent runs in the same process.
        set_active_log(audit_log, phase=phase.name)
        try:
            result = await Runner.run(agent, preamble, max_turns=max_turns)
        finally:
            clear_active_log()
        return getattr(result, "final_output", "") or ""

    for phase in plan.phases:
        if phase.status != PhaseStatus.PENDING:
            console.print(f"  [dim]skipped phase '{phase.name}' (status={phase.status.value})[/dim]")
            continue
        # F124 — Circuit breaker check: if the tail of the plan has too
        # many consecutive FAILED/SKIPPED phases, stop walking and abort.
        run_len = consecutive_unproductive_phases(plan)
        if run_len >= failure_threshold:
            circuit_breaker_tripped = True
            console.print(
                f"  [red]✕[/red] circuit breaker: {run_len} consecutive unproductive phase(s) "
                f">= threshold {failure_threshold} — aborting plan"
            )
            audit_log.append(
                tool_name="circuit_breaker_trip",
                args={"threshold": failure_threshold, "consecutive": run_len},
                result={"action": "abort_plan"},
                phase="orchestrator",
                status="aborted",
            )
            # Mark remaining as SKIPPED so the plan state stays consistent.
            cascade_skip_remaining(plan, except_names=("reporting",))
            break
        phase.status = PhaseStatus.RUNNING
        phase.findings_before = len(findings) + len(new_findings)
        phase_findings_before = list(findings) + list(new_findings)
        import time as _time

        phase_start = _time.monotonic()
        try:
            console.print(f"  [cyan]▸[/cyan] phase: {phase.name}")
            text = asyncio.run(_run_phase(phase))
        except Exception as exc:  # pragma: no cover
            console.print(f"  [yellow]phase '{phase.name}' failed: {exc}[/yellow]")
            phase.status = PhaseStatus.FAILED
            audit_log.append(
                tool_name="phase_run",
                args={"phase": phase.name, "agent_key": phase.agent_key, "max_turns": phase.max_turns},
                result={"error": str(exc)},
                phase=phase.name,
                duration_ms=int((_time.monotonic() - phase_start) * 1000),
                status="failed",
            )
            continue
        if text:
            summary_lines.append(f"[{phase.name}] {text.strip()[:500]}")
            parsed = _parse_agent_findings(text, target_host=target)
            # F121 — Dedup by (rule_id, host) against everything we already
            # have so a phase that re-emits the same finding (or that
            # overlaps with an earlier phase) doesn't fatten the report.
            unique = dedup_findings_by_rule_and_host(findings + new_findings, parsed)
            new_findings.extend(unique)
        phase.status = PhaseStatus.COMPLETED
        phase.findings_after = len(findings) + len(new_findings)

        # F119 — Persist phase boundary to forensic audit log.
        audit_log.append(
            tool_name="phase_run",
            args={"phase": phase.name, "agent_key": phase.agent_key, "max_turns": phase.max_turns},
            result={
                "text": text[:2000] if text else "",
                "new_findings_delta": phase.findings_after - phase.findings_before,
            },
            phase=phase.name,
            duration_ms=int((_time.monotonic() - phase_start) * 1000),
            status="ok",
        )

        # F136 — Checkpoint snapshot after every phase. If the process
        # crashes between here and the next phase, --resume can pick up
        # from this point without re-running the work just completed.
        try:
            save_checkpoint(
                build_checkpoint(
                    engagement_id=engagement_id,
                    target=target,
                    scope=scope,
                    families=families,
                    plan_phases=plan.phases,
                    findings=findings,
                    new_findings=new_findings,
                    goal=goal,
                )
            )
        except Exception as exc:  # pragma: no cover
            console.print(f"  [dim]checkpoint save skipped: {exc}[/dim]")

        # F117 meta-evaluation: classify the phase, retry on PARTIAL,
        # cascade-skip dependents on BARREN.
        if eval_enabled:
            phase_findings_after = list(findings) + list(new_findings)
            evaluation = evaluate_phase(phase, phase_findings_before, phase_findings_after)
            verdict_color = {
                PhaseVerdict.USEFUL: "green",
                PhaseVerdict.PARTIAL: "yellow",
                PhaseVerdict.BARREN: "red",
                PhaseVerdict.INCONCLUSIVE: "dim",
            }[evaluation.verdict]
            console.print(
                f"  [dim]eval[/dim] [{verdict_color}]{evaluation.verdict.value}[/{verdict_color}] "
                f"[dim]Δ={evaluation.delta_findings} crit/high={evaluation.delta_critical_high} "
                f"reason={evaluation.reasoning}[/dim]"
            )

            if evaluation.recommend_retry and retry_max > 0:
                hint = f"missed expected signatures: {', '.join(evaluation.expected_sigs_missed)}"
                console.print(f"  [yellow]↻[/yellow] retry phase '{phase.name}' with sharper preamble")
                retry_start = _time.monotonic()
                try:
                    retry_text = asyncio.run(_run_phase(phase, extra_hint=hint))
                except Exception as exc:  # pragma: no cover
                    console.print(f"  [yellow]retry of '{phase.name}' failed: {exc}[/yellow]")
                    # F121 — Persist the retry attempt to the audit log
                    # even when it fails, so forensia keeps the trail.
                    audit_log.append(
                        tool_name="phase_run_retry",
                        args={"phase": phase.name, "agent_key": phase.agent_key, "hint": hint},
                        result={"error": str(exc)},
                        phase=phase.name,
                        duration_ms=int((_time.monotonic() - retry_start) * 1000),
                        status="failed",
                    )
                else:
                    retry_findings_added = 0
                    if retry_text:
                        summary_lines.append(f"[{phase.name}*] {retry_text.strip()[:500]}")
                        retry_parsed = _parse_agent_findings(retry_text, target_host=target)
                        # F121 — Dedup retry findings against everything
                        # already known (incl. what the first attempt
                        # produced) so the retry doesn't double the report.
                        retry_unique = dedup_findings_by_rule_and_host(findings + new_findings, retry_parsed)
                        new_findings.extend(retry_unique)
                        retry_findings_added = len(retry_unique)
                        phase.findings_after = len(findings) + len(new_findings)
                    # F121 — Persist the retry as a separate audit entry.
                    audit_log.append(
                        tool_name="phase_run_retry",
                        args={"phase": phase.name, "agent_key": phase.agent_key, "hint": hint},
                        result={
                            "text": retry_text[:2000] if retry_text else "",
                            "new_findings_added": retry_findings_added,
                        },
                        phase=phase.name,
                        duration_ms=int((_time.monotonic() - retry_start) * 1000),
                        status="ok",
                    )

            if evaluation.skip_dependents:
                cascaded = cascade_skip_dependents(plan, phase.name)
                if cascaded:
                    console.print(
                        f"  [red]✕[/red] [dim]skipped {cascaded} dependent phase(s) "
                        f"(gating phase '{phase.name}' was BARREN)[/dim]"
                    )

        # Re-adapt the plan with the new findings so downstream phases
        # can react to evidence discovered just now.
        plan = planner.adapt_plan(plan, findings + new_findings)

        # F118 — Goal-directed reasoning: check progress after the phase.
        # On success, optionally short-circuit the rest of the plan.
        if goal_evaluator is not None and goal is not None:
            progress = goal_evaluator.evaluate(goal, findings + new_findings)
            verdict_color = {
                "satisfied": "green",
                "partial": "yellow",
                "not_met": "red",
            }.get(progress.verdict.value, "dim")
            console.print(
                f"  [dim]goal[/dim] [{verdict_color}]{progress.verdict.value}[/{verdict_color}] "
                f"[dim]{progress.reasoning}[/dim]"
            )
            if progress.should_terminate_early() and goal_early_terminate:
                # F121 — Keep the reporting phase pending even on early
                # termination so the operator still gets a written summary.
                # Without this exception the engagement ends with a verdict
                # but no narrative-driven report.
                terminated = cascade_skip_remaining(plan, except_names=("reporting",))
                kept_reporting = any(p.name == "reporting" and p.status == PhaseStatus.PENDING for p in plan.phases)
                msg = f"goal satisfied — skipping {terminated} remaining phase(s)"
                if kept_reporting:
                    msg += " (reporting kept)"
                console.print(f"  [green]✓[/green] {msg}")
                if not kept_reporting:
                    break  # nothing left worth running

    # Final verdict (only emitted when a goal was declared).
    verdict_info: dict | None = None
    if goal_evaluator is not None and goal is not None:
        final_progress = goal_evaluator.evaluate(goal, findings + new_findings)
        verdict_color = {
            "satisfied": "green",
            "partial": "yellow",
            "not_met": "red",
        }.get(final_progress.verdict.value, "dim")
        console.print(
            f"  [bold]engagement verdict:[/bold] "
            f"[{verdict_color}]{final_progress.verdict.value.upper()}[/{verdict_color}] "
            f"[dim]— {final_progress.reasoning}[/dim]"
        )
        # F122 — Surface the verdict to the reporting layer so the PDF
        # can render it alongside the findings table.
        verdict_info = {
            "verdict": final_progress.verdict.value,
            "reasoning": final_progress.reasoning,
            "goal_kind": goal.kind.value,
            "goal_raw": goal.raw,
            "evidence_count": len(final_progress.evidence),
            "circuit_breaker_tripped": circuit_breaker_tripped,
        }

    # F194 — emit a learning signal so the synthesizer can turn this
    # engagement into a candidate skill draft. Best-effort: any failure
    # is silently swallowed by ``emit_engagement_learning_signal`` so a
    # learning side-effect can never crash an engagement.
    try:
        from kryon.learning.engagement_signal import emit_engagement_learning_signal

        draft_path = emit_engagement_learning_signal(
            target=target,
            verdict_info=verdict_info,
            findings=findings + new_findings,
            families=list(families or []),
            audit_log_path=audit_log.path,
            engagement_id=engagement_id,
            objective=(goal.raw if goal is not None else ""),
        )
        if draft_path:
            console.print(f"  [dim]📝 skill draft synthesized:[/dim] [cyan]{draft_path}[/cyan]")
    except Exception as exc:  # pragma: no cover — non-fatal
        console.print(f"  [dim]learning signal skipped: {exc}[/dim]")

    # F136 — Engagement completed cleanly; remove the checkpoint so it
    # doesn't accumulate disk noise. Resume only makes sense for
    # interrupted runs.
    try:
        delete_checkpoint(engagement_id)
    except Exception:  # pragma: no cover
        pass

    return summary_lines, new_findings, verdict_info


# -----------------------------------------------------------------------------
# Phase 2b' — device-family deterministic compliance checks
# -----------------------------------------------------------------------------

# Mapping: family-name → (import path, control_id prefixes, pretty-name).
# `control_id_prefixes` is a tuple so families with non-uniform numbering
# (CIS section_*, where control_ids are "2.2.7", "6.3.3", etc) still get
# filtered cleanly. Adding a new family is one row + an explicit-import
# `__init__.py` on the corresponding check package.
_DEVICE_FAMILIES: list[tuple[str, list[str], tuple[str, ...], str]] = [
    ("proxmox", ["kryon.compliance.checks.proxmox"], ("PVE-",), "Proxmox VE"),
    ("fortigate", ["kryon.compliance.checks.fortigate"], ("FGT-",), "FortiGate"),
    (
        "linux",
        [
            "kryon.compliance.checks.section_2",
            "kryon.compliance.checks.section_6",
            "kryon.compliance.checks.section_8",
            "kryon.compliance.checks.section_10",
        ],
        ("2.", "6.", "8.", "10."),  # CIS Linux uses numeric dotted ids
        "Linux CIS",
    ),
    ("windows_ad", ["kryon.compliance.checks.active_directory"], ("AD-",), "Windows AD"),
    ("asterisk", ["kryon.compliance.checks.asterisk"], ("VOIP-",), "Asterisk / VoIP"),
    ("windows", ["kryon.compliance.checks.windows"], ("WIN-",), "Windows Server / endpoint"),
    ("tomcat", ["kryon.compliance.checks.tomcat"], ("TOMCAT-",), "Apache Tomcat"),
    # F199.E — BMC (out-of-band management: HP iLO, Dell iDRAC, Supermicro IPMI).
    # No deterministic checks yet (F205 in roadmap). Listed here so it survives
    # the appliance-vs-linux disambiguation below and produces an explicit
    # `bmc detected` banner instead of mis-firing the Linux CIS playbook.
    ("bmc", [], ("BMC-",), "BMC (iLO / iDRAC / IPMI)"),
    # F199.P — activated. Surfaced by POC .8 (UniFi Controller on :8443
    # was mis-classified as FortiGate by the old port-only rule).
    ("unifi", ["kryon.compliance.checks.unifi"], ("UNF-",), "UniFi"),
    # F201.A — DVR / IP camera / NVR (Hikvision / Dahua / Axis / TVT).
    # Surfaced by POC .12: a Hikvision NVR running on Windows was tagged
    # `windows` + `windows_ad` and got 24 CIS FPs because the OS is vendor
    # firmware (you cannot apply registry policies to an NVR). No
    # deterministic checks yet — F197 ships dvr_recon/onvif_probe tools
    # and the dvr-audit playbook (recon-only). The family entry exists so
    # `dvr` survives appliance disambiguation and Windows CIS doesn't fire.
    ("dvr", [], ("DVR-",), "DVR / IP camera / NVR (Hikvision / Dahua / Axis)"),
    # F202.P — Network multi-function printer (Kyocera / HP / Lexmark /
    # Brother / Canon / Xerox / Konica Minolta / Ricoh). Surfaced by POC
    # Britimp .200.249: Kyocera MFP en data center segment con banner
    # `Server: KM-MFP-http/V0.0.1` + path `/wlmesp/`. Originalmente
    # mis-classifico como "host con Cockpit + Prometheus" porque :9090
    # + :9100 estan abiertos — pero :9100 es JetDirect (raw print), no
    # node_exporter; y :9090 es admin web de la impresora, no Cockpit.
    # Banking-relevant: MFP procesa documentos sensibles (recibos,
    # reportes, internal docs) y firmware viejo tiene CVEs Kyocera /
    # HP / Lexmark (admin bypass + cred storage en config files
    # accesible sin auth).
    ("printer", [], ("MFP-",), "Network printer / MFP (Kyocera / HP / Lexmark / Brother / Canon)"),
]


# F199.E — Banner markers that identify out-of-band management controllers.
# These appliances expose SSH+HTTP+HTTPS just like a generic Linux server, but
# running CIS Linux compliance against them generates false positives because
# the OS is a vendor firmware, not Debian/RHEL/Ubuntu.
_BMC_BANNER_MARKERS = (
    "integrated lights-out",  # HP iLO
    "ilo ",  # HP iLO short form
    "mpssh",  # HP iLO custom SSH daemon
    "idrac",  # Dell iDRAC
    "dell remote access",  # Dell DRAC legacy
    "supermicro",  # Supermicro IPMI
    "aten ",  # ATEN-based IPMI (Supermicro, ASRock)
    "ami megarac",  # AMI MegaRAC (IPMI 2.0 reference)
    "raritan",  # Raritan KVM-over-IP
    "lenovo xclarity",  # Lenovo XClarity / IMM2
    "ibm system director",  # legacy IBM
)


# F201.A — DVR / IP camera / NVR vendor markers (banner OR HTTP body).
# Hikvision NVRs and Dahua DVRs run vendor firmware on top of Windows or
# Linux; classifying them as a generic OS family fires irrelevant CIS
# checks because the operator cannot apply registry policies or edit
# sshd_config on a sealed appliance.
_DVR_BANNER_MARKERS = (
    "hikvision",  # Hikvision DVR/NVR
    "dahua",  # Dahua DVR/NVR
    "dahuasecurity",  # Dahua web banner
    "dvrip",  # DVR-over-IP generic
    "ip camera",  # generic
    "axis communications",  # Axis cameras
    "vivotek",  # Vivotek cameras
    "tvt nvr",  # TVT (Shenzhen TVT Digital)
    "swann",  # Swann DVRs
    "tiandy",  # Tiandy DVRs
    "uniview",  # Uniview NVRs
    "tp-link tapo",  # TP-Link Tapo camera
    "onvif",  # ONVIF service banner
    "realserver",  # Real Networks RTSP (Hikvision uses port 7070 + this)
)

# F201.A — Body markers (HTTP root content). Hikvision web consoles ship a
# CSP header allowlisting `*.hikvision.com`, the Dahua console embeds
# `dahuasecurity.com` references. These are stable across firmware
# versions and survive whitelabel rebranding (the JS still hits the
# vendor CDN).
_DVR_BODY_MARKERS = (
    "hikvision.com",  # Hikvision CSP / DDNS
    "dahuasecurity.com",  # Dahua CSP / DDNS
    "dahuatech.com",  # Dahua legacy domain
    "hcwebcontrol",  # Hikvision ActiveX/JS plugin
    "vpwebcontrol",  # Hikvision VP web plugin
    "ezviz.com",  # Hikvision cloud subsidiary
    "axis-communications.com",  # Axis cloud
    "uniview.com",  # Uniview cloud
    "tvt.net.cn",  # TVT cloud
    "isapi/",  # Hikvision ISAPI URL path
    "/cgi-bin/magicbox.cgi",  # Dahua web API path (compared lowercase)
    # F201.A.B — Hikvision modern firmware login URLs (POC Britimp
    # TORRE_USR .2 + .250 2026-05-19). Banner anonimizado pero el JS
    # del root redirige a `/doc/page/login.asp` o `./doc/page/login.htm`
    # con timestamp anti-cache — patron diagnostico de Hikvision DVR
    # / NVR / IP camera con firmware 2020+. Server header tambien suele
    # ser "Webs" (Goahead WebServer embebido, comun en Hikvision).
    "/doc/page/login.asp",  # Hikvision DVR login path (POC .2)
    "/doc/page/login.htm",  # Hikvision NVR alt
    "doc/page/wizard",  # Hikvision setup wizard URL
    "server: webs",  # Goahead WebServer signature (en HTTP headers
    # extraidos como parte del body fetch)
)

# F201.A — Port combinations that are diagnostic of DVR/NVR appliances.
# RTSP (554/tcp) alone is too generic (any media server can expose it).
# But 554 + 7070 is the canonical Hikvision combo; 554 + 37777 is Dahua.
_DVR_PORT_COMBOS: tuple[frozenset[int], ...] = (
    frozenset({554, 7070}),  # Hikvision RTSP + Real Networks RTSP
    frozenset({554, 7070, 8081}),  # Hikvision NVR full
    frozenset({554, 37777}),  # Dahua DVR
    frozenset({554, 37778}),  # Dahua DVR alt
    frozenset({554, 8000}),  # Hikvision SDK port + RTSP
    frozenset({554, 8200}),  # Axis VAPIX
    # F201.A.B — POC Britimp TORRE_USR .2: 80 + 8000 (HTTP + Hikvision
    # SDK port, sin RTSP visible — RTSP filtrado por firewall pero el
    # SDK abierto al data plane). Combinacion suficiente para
    # clasificar como DVR sin requerir 554.
    frozenset({80, 8000}),  # HTTP + Hikvision SDK
    frozenset({443, 8000}),  # HTTPS + Hikvision SDK
)


# F202.P — Network printer banner markers (HTTP Server header).
# Surfaced by POC Britimp .200.249 — `Server: KM-MFP-http` + path
# `/wlmesp/`. Kyocera is the most common in LATAM banca; HP/Lexmark/
# Brother round out the top 4. Banking-relevant CVEs:
#   - CVE-2022-29856 Lexmark cred disclosure
#   - CVE-2022-1026 HP firmware tampering
#   - CVE-2021-36165 Kyocera default admin
_PRINTER_BANNER_MARKERS = (
    "km-mfp",  # Kyocera Mita MFP (POC Britimp .200.249)
    "kyocera",  # Kyocera generic
    "ecosys",  # Kyocera ECOSYS series
    "taskalfa",  # Kyocera TASKalfa
    "hp-chai",  # HP ChaiSOE (LaserJet)
    "hp http server",  # HP LaserJet generic
    "lexmark",  # Lexmark
    "brother",  # Brother
    "canon http server",  # Canon imageRUNNER
    "xerox",  # Xerox WorkCentre
    "konica minolta",  # Konica Minolta bizhub
    "ricoh",  # Ricoh Aficio
    "samsung sps",  # Samsung Printer SyncThru
    "epson",  # Epson WorkForce
    "sharp mfp",  # Sharp MX series
    "oce",  # Oce ColorWave
    "jetdirect",  # HP JetDirect explicit
)

# F202.P — HTTP body / path markers diagnostic of MFP web admin
_PRINTER_BODY_MARKERS = (
    "/wlmesp/",  # Kyocera/Olivetti (POC Britimp .200.249)
    "/web/guest/en/websys/",  # Sharp MX-series
    "/webconfig",  # Brother / HP common
    "/hp/device/webaccess",  # HP LaserJet admin
    "/cgi-bin/syncthru",  # Samsung SyncThru
    "command center",  # Kyocera Command Center RX
    "printer status",  # generic
    "lexmark embedded web server",
    "ricoh smart device monitor",
)

# F202.P — Port combinations. JetDirect :9100 is the strongest signal
# (raw print port, almost exclusively used by printers). Combined with
# any web port confirms an MFP.
_PRINTER_PORT_COMBOS: tuple[frozenset[int], ...] = (
    frozenset({80, 9100}),  # HTTP admin + JetDirect raw print
    frozenset({443, 9100}),  # HTTPS admin + JetDirect
    frozenset({80, 9100, 9220}),  # + IPP (printer)
    frozenset({80, 631}),  # IPP / CUPS print server
    frozenset({443, 631}),
    frozenset({80, 515}),  # LPD print queue
    frozenset({9100, 9220, 9290}),  # all jetdirect variants
)


def _detect_device_families(services: list[DiscoveredService]) -> list[str]:
    """Heuristic: classify a target into one or more device families based
    on banners and canonical management ports. Returns a list of family
    ids (e.g. ['proxmox', 'linux'] — many real targets match more than
    one because a Proxmox host IS a Linux server too).
    """
    families: list[str] = []

    def _add(fam: str) -> None:
        if fam not in families:
            families.append(fam)

    has_ssh = False
    open_ports: set[int] = set()
    for s in services:
        product = (s.product or "").lower()
        if s.state == "open":
            open_ports.add(s.port)
        # Proxmox VE — detect by banner (pve-api-daemon / Proxmox) OR
        # by canonical web port 8006. Port 3128 alone is NOT enough:
        # Squid proxy, Tinyproxy, and other HTTP proxies also use 3128.
        # F199.K refined this after the Britimp POC pilot showed both
        # Proxmox (real, banner "pve-api-daemon/3.0") and the risk
        # that .200's Squid sibling would also be misclassified.
        if "proxmox" in product or "pve-api" in product or s.port == 8006:
            _add("proxmox")
        elif s.port == 3128 and ("pve" in product.lower() or "proxmox" in product.lower()):
            # Port 3128 promoted to Proxmox only with banner confirmation.
            _add("proxmox")
        # FortiGate — banner-only after F199.P. Port 10443/8443 alone
        # was too aggressive: UniFi Controller, Tomcat-HTTPS, Sophos
        # XG, and any nginx with HTTPS-alt config use 8443 too. The
        # 10443 canonical SSL-VPN port keeps detecting FortiGate
        # without banner confirmation because no other product
        # commonly sits on 10443.
        if "fortigate" in product or "fortinet" in product or "fortios" in product or s.port == 10443:
            _add("fortigate")
        # F199.P — UniFi Controller (Ubiquiti). Detection by banner
        # OR by canonical Inform protocol port 8080 (the controller
        # listens on 8080 for AP heartbeat) PLUS port 8443 (web).
        # Banner is the strong signal; port-only would FP on any
        # Tomcat-like 8080+8443 combo.
        if "unifi" in product or "ubiquiti" in product or "unifi-controller" in product:
            _add("unifi")
        # Windows AD — only AD-specific ports trigger this family.
        # F202.I (POC Britimp 2026-05-18 .101): 135 + 139 + 445 were
        # in this list previously, but those are open on EVERY Windows
        # server / workstation. Result: 9 AD-* compliance FPs fired
        # against .101 (member server, no Kerberos, no LDAP, no GC).
        # AD-specific ports:
        #   88   Kerberos KDC
        #   389  LDAP
        #   636  LDAPS
        #   3268 Global Catalog
        #   3269 Global Catalog SSL
        # F202.I.B (POC Britimp 2026-05-18 .10 PBX): the host had
        # OpenLDAP on :389 (for Asterisk auth) + MIT krb5 setup —
        # nmap reports "OpenLDAP 2.2.X - 2.3.X" in product. Port 389
        # alone triggered windows_ad and 9 AD-* FPs fired against a
        # Linux PBX. AD CIS controls (Domain Password Policy, KRBTGT
        # rotation, SMB Signing, LAPS) do NOT apply to OpenLDAP /
        # MIT krb5 / Heimdal.
        # Banner discrimination: if the product on an AD-port reveals
        # a non-AD KDC / directory server, SKIP windows_ad for that
        # service. Real AD will say "Microsoft Windows Active
        # Directory LDAP" or "Microsoft Windows Kerberos".
        non_ad_directory_markers = (
            "openldap",
            "389-ds",  # 389 Directory Server (Red Hat)
            "freeipa",  # FreeIPA — Linux IPA, NOT Windows AD
            "samba",  # only when not "samba ad dc" — see below
            "apache directory",
            "opendj",
            "novell edirectory",
            "ibm tivoli directory",
            "oracle directory",
        )
        non_ad_kerberos_markers = (
            "mit krb5",
            "mit kerberos",
            "heimdal",
            "shishi",
        )
        # FreeIPA / Samba-AD ARE AD-compatible — banner contains
        # "samba ad dc" or "ipa". Don't blanket-suppress them.
        is_non_ad_directory = (
            any(m in product for m in non_ad_directory_markers) and "samba ad" not in product and "ipa" not in product
        )
        is_non_ad_kdc = any(m in product for m in non_ad_kerberos_markers)
        if s.port in (88, 389, 636, 3268, 3269):
            if not (is_non_ad_directory or is_non_ad_kdc):
                _add("windows_ad")
        # Asterisk / VoIP — SIP 5060/5061, AMI 5038, ARI 8088/8089
        if "asterisk" in product or s.port in (5060, 5061, 5038, 8088, 8089):
            _add("asterisk")
        # Windows host (SMB/RPC/RDP/WinRM signature). 'windows_ad' already
        # covers DCs above; this one catches member servers / workstations
        # where AD ports are absent but SMB/RDP/WinRM are open.
        if "windows" in product or "microsoft" in product or s.port in (5985, 5986):
            _add("windows")
        elif s.port in (3389,) and "windows_ad" not in families:
            _add("windows")
        # F199.E — BMC / out-of-band management. Detected by banner string
        # in any service product field (works for SSH mpSSH, HTTP "iLO web
        # interface", HTTPS, IPMI 623/udp). Also pinned by canonical iLO
        # Federation port 17988 if present.
        if any(m in product for m in _BMC_BANNER_MARKERS) or s.port in (623, 17988, 17990, 17993):
            _add("bmc")
        # F201.A — DVR / IP camera / NVR. Banner-based detection first
        # (Hikvision/Dahua/Axis sometimes leak vendor strings in HTTP
        # server / RTSP banner). Port-combo detection below covers the
        # common case where the banner is anonymized (Hikvision ships
        # `Server: -` by default).
        if any(m in product for m in _DVR_BANNER_MARKERS):
            _add("dvr")
        # F202.P — Network printer / MFP. Banner check first (Kyocera
        # KM-MFP, HP-ChaiSOE, Lexmark, Brother, Canon, Xerox, etc.).
        if any(m in product for m in _PRINTER_BANNER_MARKERS):
            _add("printer")
        # F200.A — Apache Tomcat. Triggered by Coyote/Tomcat banner OR
        # AJP port 8009. Note: 8080 alone is NOT enough (many non-Tomcat
        # apps run on 8080 — Tomcat-specific check needs the banner).
        if "tomcat" in product or "coyote" in product or s.port == 8009:
            _add("tomcat")
        # Track SSH presence — Linux CIS checks need SSH access. We only
        # tag the target as 'linux' when SSH is open AND the banner does
        # NOT scream "FortiOS" / "Cisco IOS" / "PVE" / "iLO" (those have
        # their own family above; running generic CIS Linux against them
        # would emit noisy false positives).
        if s.port == 22 and s.state == "open":
            has_ssh = True

    # F201.A — DVR detection by port combo. Hikvision NVR/DVR typically
    # exposes 554/tcp (RTSP) + 7070/tcp (Real Networks RTSP) + optional
    # 8081/tcp; Dahua DVRs use 554 + 37777. Banner is the strong signal,
    # but Hikvision anonymizes its HTTP banner so port-combo is the
    # only fallback when the body fetch hasn't run yet.
    if "dvr" not in families:
        for combo in _DVR_PORT_COMBOS:
            if combo.issubset(open_ports):
                _add("dvr")
                break

    # F201.A — DVR detection by HTTP body markers (Hikvision CSP). The
    # body fetch is cheap (one curl against :80 or :443), runs only when
    # we still haven't classified the host. Catches the case where
    # banner is `Server: -` and the port combo is partial.
    if "dvr" not in families:
        for s in services:
            if s.state != "open" or s.port not in (80, 443, 8080, 8081):
                continue
            scheme = "https" if s.port in (443, 8443) else "http"
            url = f"{scheme}://{s.host}:{s.port}/"
            try:
                _code, body = _http_get(url, timeout_s=4)
            except Exception:
                continue
            body_lower = body.lower()
            if any(m in body_lower for m in _DVR_BODY_MARKERS):
                _add("dvr")
                break

    # F202.P — Network printer / MFP detection.
    # Port-combo first (JetDirect :9100 + web port = strong signal).
    if "printer" not in families:
        for combo in _PRINTER_PORT_COMBOS:
            if combo.issubset(open_ports):
                _add("printer")
                break

    # F202.P — Body marker fallback (HTTP root contains
    # /wlmesp/, /webconfig, Lexmark embedded web server, etc).
    if "printer" not in families:
        for s in services:
            if s.state != "open" or s.port not in (80, 443, 8080, 9090):
                continue
            scheme = "https" if s.port in (443, 8443) else "http"
            url = f"{scheme}://{s.host}:{s.port}/"
            try:
                _code, body = _http_get(url, timeout_s=4)
            except Exception:
                continue
            body_lower = body.lower()
            if any(m in body_lower for m in _PRINTER_BODY_MARKERS):
                _add("printer")
                break

    if has_ssh:
        # Only auto-add 'linux' when there's no appliance / non-Linux
        # signature already in the family list. Proxmox IS Linux
        # underneath so we DO want CIS Linux checks alongside PVE —
        # it's intentionally absent from the exclusion set.
        # F199.E added 'bmc' (HP iLO / Dell iDRAC / Supermicro IPMI)
        # so vendor management firmware no longer mis-fires 7 Linux
        # CIS FAILs.
        # F199.I added 'windows' / 'windows_ad' so OpenSSH-for-Windows
        # hosts (sshd.exe shipped with Windows Server 2019+) don't
        # spuriously add 'linux' on top of windows_ad.
        # F201.A added 'dvr' — Hikvision NVRs running on Windows or
        # Linux still expose SSH but the OS is sealed vendor firmware.
        # F202.P added 'printer' — MFPs sometimes run embedded Linux
        # with SSH for service tech access, but the OS is sealed vendor
        # firmware (cannot apply CIS Linux hardening).
        appliance_families = {"fortigate", "bmc", "windows", "windows_ad", "dvr", "printer"}
        if not any(f in appliance_families for f in families):
            _add("linux")

    # F201.A — when DVR is detected, scrub windows + windows_ad. NVRs
    # frequently run a Hikvision-customized Windows under the hood
    # (SMB/RPC/RDP are open) but Windows CIS / AD policies do NOT apply
    # to a sealed appliance — registry edits, GPO, audit logging are
    # all locked down by the vendor. Same rationale as BMC.
    if "dvr" in families:
        for fam in ("windows", "windows_ad"):
            if fam in families:
                families.remove(fam)

    return families


def _run_device_compliance(
    console,
    *,
    family: str,
    host: str,
    ssh_target: str | None,
    ssh_key: str | None,
) -> list[Finding]:
    """Run the deterministic checks for a specific device family via the
    compliance runner. Promotes FAIL/ERROR verdicts to engage Findings.

    `family` must be a key in `_DEVICE_FAMILIES`. Silent skip when the
    package can't be imported (fresh checkout). Phase 2 deterministic +
    agent dive remain the fallback surfaces.
    """
    family_row = next((row for row in _DEVICE_FAMILIES if row[0] == family), None)
    if family_row is None:
        console.print(f"  [dim]unknown device family: {family}[/dim]")
        return []
    _, import_paths, prefixes, pretty_name = family_row

    try:
        import importlib

        for path in import_paths:
            importlib.import_module(path)  # side-effect registers checks
        from kryon.compliance.checks.base import CheckContext
        from kryon.compliance.runner import run_all
    except Exception as exc:
        console.print(f"  [dim]{pretty_name} compliance skipped: {exc}[/dim]")
        return []

    ssh_user = "root"
    ssh_port = 22
    target_host = host
    if ssh_target:
        user, _, host_port = ssh_target.partition("@")
        ssh_user = user or "root"
        host_only, _, port = host_port.partition(":")
        target_host = host_only or host
        ssh_port = int(port) if port else 22

    # FortiGate audits typically use a dedicated non-root admin (`admin`,
    # `audit`, etc); accept whatever the operator passed in --ssh.
    ctx = CheckContext(
        host=target_host,
        ssh_user=ssh_user,
        ssh_key_path=ssh_key or "",
        ssh_port=ssh_port,
        transport="ssh",
    )

    # Filter results to the family's control_id prefixes so we never
    # bleed other frameworks (e.g. a prior _run_compliance pass) into
    # engage's findings table. CIS Linux uses numeric dotted ids
    # ("2.2.7"), so `prefixes` is a tuple.
    all_results = run_all(ctx)
    family_results = [r for r in all_results if any(r.control_id.upper().startswith(p.upper()) for p in prefixes)]

    findings: list[Finding] = []
    for r in family_results:
        if r.verdict not in ("FAIL", "ERROR"):
            continue
        sev = (r.severity or "MEDIUM").upper()
        if sev not in _SEV_RANK:
            sev = "MEDIUM"
        evidence = (r.evidence_stdout or r.evidence_stderr or "")[:600]
        findings.append(
            Finding(
                cwe="CWE-0",  # device-specific checks don't map 1:1 to CWE
                severity=sev,
                host=f"{ssh_user}@{target_host}",
                rule_id=r.control_id,
                message=r.control_title or r.control_id,
                evidence=evidence,
                remediation=(r.remediation_static or "")[:400],
                target_host=f"{ssh_user}@{target_host}",
                severity_rank=_SEV_RANK[sev],
            )
        )
    if findings:
        # `prefixes[0].rstrip('-')` gives us a nice short tag — "PVE",
        # "FGT", "2.", "AD" — for the operator banner.
        short_tag = prefixes[0].rstrip("-").rstrip(".")
        console.print(
            f"  [green]{pretty_name} compliance:[/green] {len(findings)} FAIL/ERROR "
            f"(de {len(family_results)} controles {short_tag})"
        )
    return findings


# -----------------------------------------------------------------------------
# Orchestration
# -----------------------------------------------------------------------------


def _banner(console, text: str) -> None:
    console.print()
    console.print(f"[bold cyan]▸[/bold cyan] [bold]{text}[/bold]")


def _parse_ssh_arg(raw: str) -> tuple[str, str]:
    """'admin@host:2222' -> ('admin@host', '2222'). Default port 22."""
    m = re.match(r"^(\S+?)(?::(\d+))?$", raw)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid --ssh: {raw}")
    return m.group(1), m.group(2) or "22"


def run_engage(args: argparse.Namespace) -> int:
    """Entry point from the CLI dispatcher."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    # F85.B — Budget hardening: propagate CLI overrides into env so the
    # CostTracker (which reads KRYON_PRICE_LIMIT lazily) and the SDK
    # runner (which reads KRYON_MAX_TURNS at import) honor them. Only
    # write when the operator passed an explicit value — env defaults
    # remain authoritative otherwise.
    if args.max_turns is not None:
        os.environ["KRYON_MAX_TURNS"] = str(args.max_turns)
    if args.max_cost is not None:
        os.environ["KRYON_PRICE_LIMIT"] = str(args.max_cost)

    target = args.target
    scope = args.scope or target
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    engagement_id = args.engagement_id or (f"engagement-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}")

    # F159 — Surface --deep-reasoning into env so the policy gate
    # (F153) and the phase preamble both see it. Operator's explicit
    # env value wins.
    if getattr(args, "deep_reasoning", False):
        os.environ.setdefault("KRYON_DEEP_REASONING", "true")

    # F153 — Pre-flight policy gate. Resolve the active policy
    # (model + temperature + strict/grounding/cve/redact gates),
    # auto-enable strict + grounding when the model is a reasoning
    # variant (or when --deep-reasoning is set), and surface the
    # banner so the operator sees exactly what they're about to run.
    try:
        from kryon.policy import apply_policy_to_env, resolve_policy

        _preflight_policy = resolve_policy()
        apply_policy_to_env(_preflight_policy)
        console.print(f"[bold cyan]▸[/bold cyan] {_preflight_policy.banner()}")
    except Exception as exc:  # pragma: no cover
        console.print(f"[dim]policy gate skipped: {exc}[/dim]")

    # F136 — Resume from checkpoint. When --resume <eng_id> is set, the
    # orchestrator re-uses the saved findings + plan state and skips
    # Phase 1 (nmap) + Phase 2 (deterministic checks). Goal-driven
    # plan adaptation already ran the first time; on resume we trust
    # the previous plan and pick up at the first PENDING phase.
    resumed_checkpoint = None
    if getattr(args, "resume", ""):
        try:
            from kryon.state.checkpoint import load_checkpoint

            resumed_checkpoint = load_checkpoint(args.resume)
            if resumed_checkpoint is None:
                console.print(f"[red]--resume {args.resume}: checkpoint not found[/red]")
                return 2
            console.print(
                f"[cyan]↻ resume[/cyan] engagement_id={resumed_checkpoint.engagement_id} "
                f"target={resumed_checkpoint.target} ({len(resumed_checkpoint.findings)} findings, "
                f"first pending phase: {resumed_checkpoint.first_pending_phase_index()})"
            )
            # Carry forward target/scope/engagement_id from the checkpoint
            # so we don't second-guess the original engagement.
            target = resumed_checkpoint.target
            scope = resumed_checkpoint.scope or target
            engagement_id = resumed_checkpoint.engagement_id
        except Exception as exc:  # pragma: no cover
            console.print(f"[red]--resume failed: {exc}[/red]")
            return 2

    # F132 — Engagement deduplication. Skip the run entirely if the
    # operator passed --no-recent N and the last run against this target
    # finished less than N minutes ago. Logs the dedup hit so the
    # scheduling layer can tell "already ran" from "fresh execution".
    previous_findings_for_diff: list = []
    if getattr(args, "no_recent", 0) and args.no_recent > 0:
        try:
            from kryon.state.engagement_state import minutes_since, read_state

            prev = read_state(target)
            if prev is not None:
                elapsed = minutes_since(prev)
                if elapsed is not None and elapsed < args.no_recent:
                    console.print(
                        f"  [yellow]↺[/yellow] dedup: {target} scanned "
                        f"{elapsed:.1f} min ago (< --no-recent={args.no_recent}); "
                        f"reusing previous findings ({prev.finding_count} items, "
                        f"engagement_id={prev.last_engagement_id})"
                    )
                    return 0
        except Exception as exc:  # pragma: no cover
            console.print(f"  [dim]dedup check skipped: {exc}[/dim]")

    # F133 — Load previous findings (if any) for baseline diffing.
    # Independent of the dedup gate above — this runs even when the
    # operator did NOT pass --no-recent, so every engagement gets a
    # diff section comparing against the last known state.
    try:
        from kryon.state.baseline_diff import load_previous_findings
        from kryon.state.engagement_state import read_state as _read_state_for_diff

        prev_state = _read_state_for_diff(target)
        if prev_state is not None:
            previous_findings_for_diff = load_previous_findings(prev_state.findings_path)
    except Exception as exc:  # pragma: no cover
        console.print(f"  [dim]previous-findings load skipped: {exc}[/dim]")

    # Security hygiene: prefer `SSHPASS` env over --ssh-password argv.
    # Passing the password as a CLI argument to `kryon engage` leaves
    # the plaintext in /proc/<pid>/cmdline of the Kryon process itself
    # (visible to every local process). Warn if that's how we got it;
    # fall back to SSHPASS env when the flag is absent.
    pwd_from_argv = bool(args.ssh_password)
    if not args.ssh_password and os.environ.get("SSHPASS"):
        args.ssh_password = os.environ["SSHPASS"]
    if pwd_from_argv:
        console.print(
            "[yellow]⚠  --ssh-password in argv is visible in /proc. "
            "Prefer: `export SSHPASS=... && kryon engage ...` (drop the flag) "
            "or use an SSH key.[/yellow]"
        )

    # F202.W — promote --db-user / --db-password CLI args to env vars so
    # that _check_mysql_deep (which reads KRYON_DB_USER / KRYON_DB_PASSWORD)
    # picks them up. Same /proc warning rationale as --ssh-password.
    if args.db_user:
        os.environ["KRYON_DB_USER"] = args.db_user
    if args.db_password:
        os.environ["KRYON_DB_PASSWORD"] = args.db_password
        console.print(
            "[yellow]⚠  --db-password in argv is visible in /proc. "
            "Prefer: `export KRYON_DB_PASSWORD=... && kryon engage ...`.[/yellow]"
        )

    # --- Phase 1: discovery -----------------------------------------------
    # F136 — On --resume we trust the checkpoint and skip nmap + Phase 2
    # deterministic checks. Findings are seeded from the saved snapshot.
    open_svcs: list[DiscoveredService] = []
    findings: list[Finding] = []
    if resumed_checkpoint is not None:
        _banner(console, "Fase 1 — RESUMED (skipping nmap, seeding from checkpoint)")
        # Re-hydrate findings from the checkpoint as plain dataclass instances.
        for f in resumed_checkpoint.findings:
            if isinstance(f, dict):
                try:
                    findings.append(
                        Finding(
                            cwe=str(f.get("cwe", "CWE-0")),
                            severity=str(f.get("severity", "INFO")),
                            host=str(f.get("host", target)),
                            rule_id=str(f.get("rule_id", "agent-finding")),
                            message=str(f.get("message", "")),
                            evidence=str(f.get("evidence", "")),
                            remediation=str(f.get("remediation", "")),
                            severity_rank=_SEV_RANK.get(str(f.get("severity", "INFO")).upper(), 99),
                            confidence=float(f.get("confidence", 1.0) or 1.0),
                            needs_verification=bool(f.get("needs_verification", False)),
                        )
                    )
                except (KeyError, ValueError, TypeError):
                    continue
        console.print(f"  [green]✓[/green] resumed with {len(findings)} findings from checkpoint")
    else:
        _banner(console, f"Fase 1 — descubrimiento ({target})")
        xml = _run_nmap(target, timeout_s=args.nmap_timeout, ports=getattr(args, "ports", ""))
        services = _parse_nmap_xml(xml, target)
        open_svcs = [s for s in services if s.state == "open"]
        console.print(f"  [green]{len(open_svcs)}[/green] puertos abiertos en {target}")
        for s in open_svcs[:10]:
            console.print(f"    {s.port:>5}/{s.state}  {s.service} {s.product or ''} {s.version or ''}")

    # --- Phase 2: service checks ------------------------------------------
    if resumed_checkpoint is not None:
        _banner(console, "Fase 2 — RESUMED (skipping deterministic checks; using checkpoint findings)")
    else:
        _banner(console, "Fase 2 — evaluación por servicio")
    for svc in open_svcs:
        if svc.service in ("http", "http-proxy", "https") or svc.port in (80, 443, 8080, 8443):
            findings.extend(_check_http(svc))
            # F199.J — Run the Python http.server detector on the same
            # service. It only fires when the Server header explicitly
            # says SimpleHTTP/Python, so it's cheap to call on every
            # HTTP service.
            python_finding = _check_python_simplehttp_exposed(svc)
            if python_finding:
                findings.append(python_finding)
            # F202.U — cookie security flags (HttpOnly, Secure, SameSite).
            # Banking-critical: missing HttpOnly = XSS session takeover.
            findings.extend(_check_http_cookie_flags(svc))
            # Full F57 web sweep (crawl + surface discovery + injection +
            # headless cookie/PP/DOM-XSS + nuclei) on web services — ACTIVE
            # only (KRYON_RED_TEAM), so banca-safe engagements are unchanged.
            # Reuses the investigate phase to map BankingFinding → engage.Finding.
            if os.environ.get("KRYON_RED_TEAM", "").strip().lower() in ("1", "true", "yes"):
                _scheme = "https" if (svc.service == "https" or svc.port in (443, 8443)) else "http"
                _base = f"{_scheme}://{svc.host}:{svc.port}"
                try:
                    from kryon.cli.investigate import _run_webexploit_phase

                    _wx = _run_webexploit_phase(_base, enable_nuclei=True) or []
                    if _wx:
                        console.print(f"    🕸 webexploit sweep: {len(_wx)} findings en {_base}")
                        findings.extend(_wx)
                except Exception as exc:  # noqa: BLE001 — never break the engagement
                    console.print(f"[yellow]    webexploit sweep warning ({_base}): {exc}[/yellow]")
        if svc.service == "ssh" or svc.port == 22 or svc.port == 2222:
            findings.extend(_check_ssh(svc, args.ssh, args.ssh_password))
        if svc.service in (
            "mysql",
            "postgresql",
            "mongodb",
            "redis",
            # F202.J — Microsoft SQL Server (ms-sql-s = TDS service,
            # ms-sql = generic, ms-sql-m = Browser UDP/TCP 1434).
            "ms-sql-s",
            "ms-sql",
            "ms-sql-m",
            # F202.K — Oracle DB TNS Listener (oracle-tns = canonical
            # nmap name, tns = legacy alias).
            "oracle-tns",
            "tns",
        ) or svc.port in (
            3306,
            33060,
            5432,
            27017,
            6379,
            # F202.J — TDS 1433 + Browser 1434
            1433,
            1434,
            # F202.K — TNS Listener default + alternate
            1521,
            1522,
        ):
            findings.extend(_check_mysql(svc))
            # F202.W — Deep MySQL audit con creds (graceful skip si no
            # hay KRYON_DB_USER + KRYON_DB_PASSWORD env vars).
            if svc.port in (3306, 33060):
                findings.extend(_check_mysql_deep(svc))
        # F202.A — DNS open resolver. Surfaced by .205 (DC britimp.com.py
        # responded to recursive queries from the operator VPN). If the
        # perimeter firewall allows UDP/53 from internet, this is an
        # amplification DDoS vector.
        if svc.service == "domain" or svc.port == 53:
            dns_finding = _check_dns_open_resolver(svc)
            if dns_finding:
                findings.append(dns_finding)
            # F202.B — DNS zone transfer (AXFR). Runs on the same gate;
            # exposes full zone records (hostnames, SPF/DMARC, TXT
            # secrets) when unrestricted.
            axfr_finding = _check_dns_zone_transfer(svc)
            if axfr_finding:
                findings.append(axfr_finding)
            # F202.C — CHAOS class info disclosure (version.bind,
            # hostname.bind, id.server). BIND / Unbound / PowerDNS
            # default behavior; Microsoft DNS is immune.
            chaos_finding = _check_dns_chaos_leak(svc)
            if chaos_finding:
                findings.append(chaos_finding)
            # F202.D — DNS cache snooping (privacy leak via +norecurse
            # +cd probes of curated SaaS / banking / social domains).
            snoop_finding = _check_dns_cache_snoop(svc)
            if snoop_finding:
                findings.append(snoop_finding)
            # F202.E — DNSSEC validation status. Query dnssec-failed.org
            # (Verisign broken-DNSSEC test domain). Validating resolver
            # MUST return SERVFAIL; resolver that returns the IP is
            # vulnerable to cache poisoning + MITM injection.
            dnssec_finding = _check_dnssec_validation(svc)
            if dnssec_finding:
                findings.append(dnssec_finding)
            # F202.F — Reverse zone enumeration. PTR walking exposes
            # internal hostname conventions even when AXFR is blocked.
            # Sample 10 IPs of the /24; elevates to HIGH on banking /
            # DB / production keywords.
            ptr_finding = _check_reverse_dns_enum(svc)
            if ptr_finding:
                findings.append(ptr_finding)
            # F202.G — RFC 2136 dynamic UPDATE without TSIG / GSS-TSIG.
            # Banking impact: MX rewrite / phishing infra / mail
            # interception. Probe is a no-op delete (record doesn't
            # exist); zone state is never modified.
            update_finding = _check_dns_dynamic_update(svc)
            if update_finding:
                findings.append(update_finding)
        # F202.N — BGP (TCP/179) exposed to data plane. Read-only TCP
        # connect probe; no BGP OPEN sent. Banca-safe.
        if svc.service == "bgp" or svc.port == 179:
            bgp_finding = _check_bgp_exposure(svc)
            if bgp_finding:
                findings.append(bgp_finding)
        # F202.Q — SMB anonymous share listing. smbclient -L -N (read-
        # only enumeration, no file access). Banca-safe.
        if svc.service in ("microsoft-ds", "netbios-ssn") or svc.port == 445:
            smb_finding = _check_smb_anonymous_shares(svc)
            if smb_finding:
                findings.append(smb_finding)

    # F202.R — SIEM agent activity check (CWE-778). Per-host, requires
    # SSH creds. Surfaced POC Britimp: Wazuh VM apagado -> agents
    # quedan installed pero inactive en hosts del cluster. Read-only:
    # `systemctl is-active wazuh-agent filebeat auditd ...`. Banca-safe.
    if args.ssh:
        siem_finding = _check_siem_activity(
            host=target,
            ssh_target=args.ssh,
            ssh_key=args.ssh_key,
            ssh_password=args.ssh_password,
        )
        if siem_finding:
            findings.append(siem_finding)

    findings.sort(key=lambda f: f.severity_rank)
    console.print(f"  [yellow]{len(findings)}[/yellow] hallazgos detectados")

    # --- Phase 2b: compliance sweep (F77.A) -------------------------------
    framework_results: dict[str, list[dict]] = {}
    frameworks = [fw.strip().lower() for fw in (args.framework or "").split(",") if fw.strip()]
    if frameworks:
        _banner(console, f"Fase 2b — compliance ({', '.join(frameworks)})")
        try:
            framework_results = _run_compliance(
                frameworks,
                host=target,
                ssh_target=args.ssh,
                ssh_password=args.ssh_password,
                ssh_key=args.ssh_key,
            )
            for fw, results in framework_results.items():
                fail = sum(1 for r in results if r.get("verdict") == "FAIL")
                console.print(f"  [cyan]{fw}[/cyan]: {len(results)} controls, [red]{fail} FAIL[/red]")
        except Exception as exc:
            console.print(f"  [red]compliance runner failed:[/red] {exc}")

    # --- Phase 2b' — device-family deterministic compliance --------------
    # Auto-detect which device family/families the target belongs to and
    # invoke the matching `c_<fam>_*` compliance checks. Promotes FAIL /
    # ERROR verdicts to engagement findings. Currently covers Proxmox VE
    # and FortiGate; adding a family means editing `_DEVICE_FAMILIES` and
    # making sure its check package `__init__.py` imports its submodules.
    detected_families = _detect_device_families(services)
    for fam in detected_families:
        _banner(console, f"Fase 2b' — {fam} deterministic checks")
        fam_findings = _run_device_compliance(
            console,
            family=fam,
            host=target,
            ssh_target=args.ssh,
            ssh_key=args.ssh_key,
        )
        if fam_findings:
            findings.extend(fam_findings)
            findings.sort(key=lambda f: (f.severity_rank, f.host, f.rule_id))

    # --- Phase 2c: optional agent deepening (F77.A / F85.D / F85.F) -------
    agent_observations: list[str] = []
    orchestrated = args.orchestrated or os.environ.get("KRYON_ORCHESTRATED", "").lower() in {"1", "true", "yes"}

    # F118 — Parse declarative objective once, hand structured goal to orchestrator.
    declared_goal = None
    objective_text = (getattr(args, "objective", "") or os.environ.get("KRYON_OBJECTIVE", "")).strip()
    if objective_text:
        try:
            from kryon.tools.autonomous.engagement_goal import parse_objective

            declared_goal = parse_objective(objective_text)
        except Exception as exc:  # pragma: no cover
            console.print(f"  [yellow]objective parse failed: {exc}[/yellow]")

    engagement_verdict_info: dict | None = None  # F122
    if args.use_agent or os.environ.get("KRYON_ENGAGE_AGENT", "").lower() in {"1", "true", "yes"} or orchestrated:
        if orchestrated:
            _banner(console, "Fase 2c' — orquestador multi-fase (F85.F)")
            agent_observations, agent_findings, engagement_verdict_info = _invoke_orchestrated_engagement(
                console,
                target=target,
                scope=scope,
                findings=findings,
                families=detected_families,
                goal=declared_goal,
            )
        else:
            _banner(console, "Fase 2c — agente Kryon (deep-dive)")
            # F85.D — pass detected_families so the agent's skill set
            # gets re-ranked against the actual target profile before
            # the LLM turn (mid-engagement skill swap).
            agent_observations, agent_findings = _invoke_agent_deepening(
                console,
                target=target,
                scope=scope,
                findings=findings,
                families=detected_families,
            )
        if agent_findings:
            findings.extend(agent_findings)
            findings.sort(key=lambda f: (f.severity_rank, f.host, f.rule_id))
            console.print(f"  [green]agent findings:[/green] +{len(agent_findings)} estructurados desde el LLM")
        if agent_observations:
            console.print(f"  [green]✓[/green] agente produjo {len(agent_observations)} observaciones")

    # F134 — Cross-tool validation: score every finding's confidence
    # based on whether a deterministic finding corroborates the LLM one.
    # LLM findings without corroboration get needs_verification=True so
    # the report can flag them as "review before client handoff".
    try:
        from kryon.scoring.confidence import annotate_confidence

        annotate_confidence(findings)
        needs_review = sum(1 for f in findings if f.needs_verification)
        if needs_review:
            console.print(f"  [yellow]⚠[/yellow] {needs_review} finding(s) marked needs_verification")
    except Exception as exc:  # pragma: no cover
        console.print(f"  [dim]confidence scoring skipped: {exc}[/dim]")

    # F152 — Tool-output grounding. Findings whose narration doesn't
    # cite a concrete tool output (call_id, step N, "según output de X")
    # get their confidence capped + flagged for verification. Auto-on
    # for reasoning models via F153 (KRYON_REQUIRE_GROUNDING).
    try:
        from kryon.validation.grounding import apply_grounding

        penalised = apply_grounding(findings)
        if penalised:
            console.print(
                f"  [yellow]⚠[/yellow] {penalised} finding(s) penalised by F152 grounding "
                "(no tool citation in narration)"
            )
    except Exception as exc:  # pragma: no cover
        console.print(f"  [dim]grounding check skipped: {exc}[/dim]")

    # F133 — Compute baseline diff against previous engagement state.
    baseline_diff = None
    if previous_findings_for_diff:
        try:
            from kryon.state.baseline_diff import compute_diff, format_diff_summary

            baseline_diff = compute_diff(previous_findings_for_diff, findings)
            console.print(f"  [cyan]Δ[/cyan] {format_diff_summary(baseline_diff)}")
        except Exception as exc:  # pragma: no cover
            console.print(f"  [dim]baseline diff skipped: {exc}[/dim]")

    # --- Phase 3: findings table ------------------------------------------
    _banner(console, "Fase 3 — resumen")
    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("#", style="dim", width=3)
    tbl.add_column("Severity", width=10)
    tbl.add_column("CWE", width=10)
    tbl.add_column("Host", width=30)
    tbl.add_column("Rule")
    for i, f in enumerate(findings, 1):
        tbl.add_row(str(i), f.severity, f.cwe, f.host, f.rule_id)
    console.print(tbl)

    # --- Phase 4: remediation -------------------------------------------
    applied_findings: list[str] = []
    if not args.dry_run_only and args.ssh:
        _banner(console, "Fase 4 — proponiendo remediación")
        actions = [
            {
                "command": f.remediation_command,
                "purpose": f.remediation or f.message,
                "severity": f.severity.lower(),
                "reversible": True,
                "target_host": f.target_host,
            }
            for f in findings
            if f.remediation_command and f.target_host
        ]
        if actions:
            from kryon.repl.ui.approval import (
                ApprovalRequest,
                ApprovalResult,
                ProposedAction,
                Severity,
                ask_approval,
            )

            sev_map = {
                "critical": Severity.DESTRUCTIVE,
                "high": Severity.MODIFY,
                "medium": Severity.MODIFY,
                "low": Severity.READ,
                "info": Severity.READ,
            }
            req = ApprovalRequest(
                title=f"Aplicar {len(actions)} correcciones en {args.ssh}",
                subtitle=f"Engagement: {engagement_id}",
                actions=[
                    ProposedAction(
                        command=a["command"],
                        purpose=a["purpose"],
                        severity=sev_map.get(a["severity"], Severity.MODIFY),
                        reversible=a["reversible"],
                        target_host=a["target_host"],
                    )
                    for a in actions
                ],
                impact_notes=[
                    "Backup de config previo (sed --in-place), reload sshd tras cada cambio.",
                    "Re-auditoría automática al final.",
                ],
                dry_run=False,
            )
            if args.auto_approve:
                verdict = ApprovalResult.YES
                console.print("[yellow]⚠ KRYON_AUTO_APPROVE — demo mode[/yellow]")
            else:
                verdict = ask_approval(req, console=console, default=ApprovalResult.NO)

            if verdict == ApprovalResult.YES:
                for a in actions:
                    user_host, port = _parse_ssh_arg(a["target_host"])
                    user, _, host = user_host.partition("@")
                    base = [
                        "ssh",
                        # F202.S security hardening — accept-new pin
                        # vs MITM en redes internas.
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        "-p",
                        port,
                        f"{user}@{host}",
                    ]
                    # SSHPASS env instead of `-p <password>` — argv stays
                    # clean for anyone watching `ps auxf`.
                    env = None
                    if args.ssh_password:
                        env = {**os.environ, "SSHPASS": args.ssh_password}
                        base = ["sshpass", "-e"] + base
                    console.print(f"  [dim]$[/dim] {a['command'][:90]}")
                    try:
                        r = subprocess.run(
                            base + [a["command"]],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            check=False,
                            env=env,
                        )
                        if r.returncode == 0:
                            console.print("  [green]✓[/green] applied")
                            applied_findings.append(a["purpose"])
                        else:
                            console.print(f"  [red]✗[/red] exit {r.returncode}: {r.stderr[:120]}")
                    except Exception as exc:
                        console.print(f"  [red]✗[/red] {exc}")
            else:
                console.print(f"[yellow]veredicto: {verdict.value} — nada aplicado[/yellow]")
        else:
            console.print("  [dim]sin acciones con comando de remediación[/dim]")

    # --- Phase 5: re-audit (when remediation applied) ---------------------
    if applied_findings and not args.skip_reaudit:
        _banner(console, "Fase 5 — re-auditoría")
        xml2 = _run_nmap(target, timeout_s=args.nmap_timeout)
        services2 = _parse_nmap_xml(xml2, target)
        console.print(
            f"  [dim]re-scan:[/dim] {sum(1 for s in services2 if s.state == 'open')} puertos abiertos tras aplicar"
        )

    # --- Phase 6: report --------------------------------------------------
    _banner(console, "Fase 6 — reporte")
    findings_dict = [
        {
            **{k: v for k, v in asdict(f).items() if k != "severity_rank"},
        }
        for f in findings
    ]

    paths: dict[str, str] = {}
    if framework_results:
        # Multi-framework consolidated PDF (F44) — the banking-grade output.
        from kryon.reporting.multi_framework_pdf import (
            render_multi_framework_html,
            render_multi_framework_pdf,
        )

        html_path = out_dir / f"kryon-{engagement_id}-consolidated.html"
        pdf_path = out_dir / f"kryon-{engagement_id}-consolidated.pdf"
        html_path.write_text(
            render_multi_framework_html(
                framework_results,
                host=scope,
                client_name=args.client or "",
            ),
            encoding="utf-8",
        )
        paths["html_multi"] = str(html_path)
        try:
            render_multi_framework_pdf(
                framework_results,
                str(pdf_path),
                host=scope,
                client_name=args.client or "",
            )
            paths["pdf_multi"] = str(pdf_path)
        except ImportError as exc:
            console.print(f"  [yellow]PDF skipped — weasyprint unavailable: {exc}[/yellow]")

    # Always emit the demo_report as a secondary deliverable so the
    # deterministic surface is documented even when compliance ran.
    from kryon.reporting.demo_report import render_demo_report

    ctx = {
        "client_name": args.client or "",
        "engagement_id": engagement_id,
        "target_scope": scope,
        "auditor": args.auditor or "SkyVanguard / Kryon",
        "applied": applied_findings,
        "agent_observations": agent_observations,
        # F122 — Surface the engagement verdict so the demo_report can
        # render it next to the findings table.
        "engagement_verdict": engagement_verdict_info,
    }
    demo_paths = render_demo_report(
        findings_dict,
        ctx,
        output_dir=out_dir,
        filename_stem=f"kryon-{engagement_id}",
    )
    paths.update(demo_paths)
    for k, v in paths.items():
        console.print(f"  [green]{k}[/green] → {v}")

    # F132 — Persist per-target state so the next run can dedup.
    try:
        from kryon.state.engagement_state import write_state

        findings_json_path = paths.get("json", "")
        write_state(
            target,
            engagement_id=engagement_id,
            findings_path=str(findings_json_path),
            finding_count=len(findings),
        )
    except Exception as exc:  # pragma: no cover
        console.print(f"  [dim]state write skipped: {exc}[/dim]")

    # F137 — Auto-ticket-on-engage. The default provider is Noop so this
    # is safe-by-default: only when KRYON_TICKET_PROVIDER is explicitly
    # set (jira/linear/github) and the matching creds env vars are
    # populated does this actually file tickets.
    try:
        from kryon.tickets.routing import create_tickets_for_findings

        tickets = create_tickets_for_findings(findings, engagement_id=engagement_id)
        if tickets:
            opened = [t for t in tickets if t.ok and not t.dry_run]
            dry = [t for t in tickets if t.dry_run]
            errored = [t for t in tickets if not t.ok]
            if opened:
                console.print(f"  [green]✓[/green] opened {len(opened)} ticket(s):")
                for t in opened[:10]:
                    console.print(f"      [green]{t.provider}[/green] {t.ticket_id} {t.url}".rstrip())
            if dry:
                console.print(
                    f"  [dim]ticket dry-run: {len(dry)} finding(s) would open tickets (provider={dry[0].provider})[/dim]"
                )
            if errored:
                console.print(f"  [yellow]⚠[/yellow] {len(errored)} ticket creation(s) failed")
    except Exception as exc:  # pragma: no cover
        console.print(f"  [dim]ticket integration skipped: {exc}[/dim]")

    return 0


# -----------------------------------------------------------------------------
# CLI wiring
# -----------------------------------------------------------------------------


def add_engage_subparser(subparsers) -> argparse.ArgumentParser:
    """Called from kryon.cli._original.main() to register the subcommand."""
    p = subparsers.add_parser(
        "engage",
        help="Run an end-to-end engagement against a target (demo orchestrator)",
    )
    p.add_argument("target", help="host / IP / CIDR to assess")
    p.add_argument("--scope", help="human-readable scope string for the report")
    p.add_argument("--ssh", help="SSH target as user@host[:port]")
    p.add_argument(
        "--ssh-password",
        help=("SSH password (passed to sshpass via SSHPASS env, NOT as argv). Prefer --ssh-key for production."),
    )
    p.add_argument("--out", default="./kryon-reports", help="output directory for the report")
    p.add_argument("--client", default="", help="client name for the report header")
    p.add_argument("--engagement-id", default="", help="engagement identifier")
    p.add_argument("--auditor", default="", help="auditor name (default: SkyVanguard / Kryon)")
    p.add_argument("--dry-run-only", action="store_true", help="skip remediation even if --ssh provided")
    p.add_argument("--auto-approve", action="store_true", help="skip approval prompt (lab / demo only — NEVER prod)")
    p.add_argument("--nmap-timeout", type=int, default=600, help="nmap wall-clock timeout in seconds (default: 600)")
    p.add_argument(
        "--ports",
        default="",
        help="F202.T — comma-separated port list (e.g. '22,80,2222,8080,33060'). "
        "Replaces the default `--top-ports 100`. Util para lab/POC con "
        "puertos no-canonicos OR para focused scan a un subset de targets "
        "(evita FPs cuando el operador corre engage contra localhost con "
        "varios containers Docker exposed).",
    )
    p.add_argument(
        "--framework",
        default="",
        help="comma-separated compliance frameworks to audit "
        "(e.g. 'pci_dss,bcp_py,swift_csp'). Produces the "
        "multi-framework consolidated PDF.",
    )
    p.add_argument(
        "--use-agent",
        action="store_true",
        help="invoke the unified Kryon agent after Phase 2 to deepen coverage (KRYON_ENGAGE_AGENT env also works)",
    )
    p.add_argument(
        "--orchestrated",
        action="store_true",
        help="F85.F — invoke PentestPlanner multi-phase orchestration instead of "
        "a single-shot LLM dive. Each detected device family gets a "
        "dedicated audit phase (proxmox/fortigate/unifi/AD); plan adapts "
        "between phases based on accumulated findings. KRYON_ORCHESTRATED "
        "env var also works. Implies --use-agent.",
    )
    p.add_argument("--ssh-key", default="", help="SSH private key path for compliance runner")
    # F202.W — DB creds opcionales para deep audit MySQL (config interna
    # via SHOW VARIABLES). Sin esto solo se emite el rule_id genérico
    # "mysql-exposed". Banking: NUNCA hardcodear; usar var KRYON_DB_PASSWORD
    # en CI o `--db-password $(read -s -p 'DB password: ')` interactivo.
    p.add_argument(
        "--db-user",
        default="",
        help="F202.W — MySQL/MariaDB read-only user for deep audit (or set KRYON_DB_USER env). "
        "Habilita _check_mysql_deep: CWE-668 bind, CWE-319 TLS, CWE-200 local_infile, CWE-1104 EOL.",
    )
    p.add_argument(
        "--db-password",
        default="",
        help="F202.W — MySQL/MariaDB password (or set KRYON_DB_PASSWORD env). "
        "argv-visible — prefiere env var en producción.",
    )
    p.add_argument("--skip-reaudit", action="store_true", help="skip the post-remediation re-scan (Phase 5)")
    # F132 — Engagement deduplication. When set, the orchestrator
    # checks the per-target state file and reuses the previous findings
    # if the last run was less than --no-recent minutes ago. Useful for
    # avoiding duplicate scans when scheduled jobs overlap.
    p.add_argument(
        "--no-recent",
        type=int,
        default=0,
        help="Skip the run if this target was already scanned in the last N minutes "
        "(reuses the previous findings.json). 0 (default) disables the check.",
    )
    # F159 — Activate Qwen3 dense's opt-in thinking mode on base
    # instruct models (kryon-14b). The preamble prepends ``/think`` and
    # the policy gate (F153) auto-enables strict + grounding.
    p.add_argument(
        "--deep-reasoning",
        action="store_true",
        help="F159 — Activate Qwen3 /think mode (chain-of-thought) on the base "
        "instruct model. Slower per phase but produces auditable reasoning and "
        "auto-enables F148 adversarial-strict + F152 grounding. KRYON_DEEP_REASONING "
        "env also works.",
    )
    # F136 — Checkpoint + resume. When --resume is set, the orchestrator
    # loads the saved checkpoint for that engagement_id and continues
    # from the first PENDING phase instead of starting over.
    p.add_argument(
        "--resume",
        default="",
        help="Resume a previously interrupted engagement by ID. The checkpoint must "
        "exist at .kryon/checkpoints/<engagement_id>.json (or KRYON_CHECKPOINT_PATH/...).",
    )
    # F118 — Goal-directed reasoning. The operator declares what success
    # looks like; the orchestrator terminates early on satisfaction and
    # emits a final verdict (SATISFIED/PARTIAL/NOT_MET) at the end.
    p.add_argument(
        "--objective",
        default="",
        help='engagement objective in natural language, e.g. "audit PCI-DSS '
        'compliance for cashbox" or "find RCE on the admin panel". Parsed by '
        "engagement_goal.parse_objective into a structured goal; the orchestrator "
        "checks progress after each phase and stops early on success.",
    )
    # F85.B — Budget hardening. Both flags are also readable from env
    # (KRYON_MAX_TURNS, KRYON_PRICE_LIMIT) so containerised runs can be
    # capped without touching the CLI invocation.
    p.add_argument(
        "--max-turns",
        type=int,
        default=None,
        help="hard cap on LLM turns per run (default: 40 from KRYON_MAX_TURNS). "
        "Prevents a stuck agent from looping until the API key runs out.",
    )
    p.add_argument(
        "--max-cost",
        type=float,
        default=None,
        help="hard cap on USD spent per run (default: 5.0 from KRYON_PRICE_LIMIT). "
        "CostTracker aborts the chat-completions call path when exceeded.",
    )
    # F85.H — Cover page + branding flags. Empty defaults keep current
    # demo/CI outputs visually identical (only triggered when set).
    p.add_argument(
        "--brand-logo",
        default="",
        help="path to client logo (PNG/JPG/SVG) for the report cover. "
        "Empty falls back to client_name as text placeholder.",
    )
    p.add_argument(
        "--brand-color",
        default="",
        help='accent color hex for the report cover, e.g. "#0070d2". Empty keeps the Kryon default blue.',
    )
    p.add_argument(
        "--classification",
        default="INTERNAL",
        choices=["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
        help="document classification banner shown on the cover and footer.",
    )
    return p
