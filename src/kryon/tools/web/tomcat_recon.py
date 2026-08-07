"""F200.A — Apache Tomcat recon (version + endpoint exposure + AJP probe).

Banca-safe by design: read-only HTTP/TCP probes against the Tomcat
container. No exploit attempts, no credential bruteforcing.

What this detects (without authentication):
  - Exact Tomcat version via 404 error page banner.
  - Manager / Host Manager / Examples / Docs endpoint reachability.
  - AJP/1.3 listener on TCP 8009 (Ghostcat CVE-2020-1938 precondition).
  - Server header value ("Apache-Coyote/X.Y" or "Apache Tomcat/X.Y.Z").

Surfaced during internal testing against a Tomcat host
(Tomcat 7.0.34 — EOL since March 2021, vulnerable to Ghostcat
+ a dozen other public CVEs).
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool

_HTTP_TIMEOUT_S = 5
_AJP_TIMEOUT_S = 3


@dataclass(frozen=True)
class TomcatFingerprint:
    """Outcome of a single Tomcat recon probe."""

    host: str
    port: int
    scheme: str = "http"
    is_tomcat: bool = False
    version: str = ""  # e.g. "7.0.34"
    server_header: str = ""  # e.g. "Apache-Coyote/1.1"
    manager_status: int = 0  # HTTP status of /manager/html (0 = not probed)
    host_manager_status: int = 0
    docs_status: int = 0
    examples_status: int = 0
    ajp_open: bool = False  # AJP/1.3 listener on TCP 8009 reachable
    error_page_leaks_version: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# HTTP probes
# ---------------------------------------------------------------------------


def _http_probe(url: str, *, timeout_s: int = _HTTP_TIMEOUT_S) -> tuple[int, str, str]:
    """Return (status_code, server_header, body[:8192]).

    Never raises — network errors collapse to (0, '', '').
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "kryon/tomcat-recon"})
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            server = resp.headers.get("Server", "")
            return resp.status, server, body
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = (exc.fp.read(8192) or b"").decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        server = exc.headers.get("Server", "") if exc.headers else ""
        return exc.code, server, body
    except (TimeoutError, urllib.error.URLError, OSError, ssl.SSLError):
        return 0, "", ""


_TOMCAT_VERSION_RE = re.compile(r"Apache Tomcat/(\d+\.\d+\.\d+)", re.IGNORECASE)
_COYOTE_RE = re.compile(r"Apache-Coyote/(\d+\.\d+)", re.IGNORECASE)


def _extract_tomcat_version(*sources: str) -> str:
    """Search the provided strings for an Apache Tomcat version banner."""
    for src in sources:
        if not src:
            continue
        m = _TOMCAT_VERSION_RE.search(src)
        if m:
            return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# AJP/1.3 probe (TCP 8009 default)
# ---------------------------------------------------------------------------


def _ajp_probe(host: str, port: int = 8009) -> bool:
    """Return True when an AJP/1.3 listener appears reachable.

    AJP/1.3 always starts with magic bytes 0x1234. We send a minimal
    AJP CPing packet (0x1234 0x0001 0x0A) and consider the port "AJP
    open" if the TCP handshake succeeds — we don't send the full
    Ghostcat exploit payload (read-only auditor).
    """
    try:
        with socket.create_connection((host, port), timeout=_AJP_TIMEOUT_S) as s:
            # CPing: AJP magic + length 1 + type 0x0A
            s.sendall(b"\x12\x34\x00\x01\x0a")
            try:
                resp = s.recv(8)
            except (TimeoutError, OSError):
                resp = b""
            # A real AJP/1.3 connector answers CPing with CPong, whose packet starts with
            # the server->container magic "AB" (0x41 0x42). Require it: the old
            # `len(resp) > 0 or True` was ALWAYS True, so ANY service listening on 8009
            # (or even a bare TCP accept) was reported as Ghostcat CVE-2020-1938 CRITICAL.
            return len(resp) >= 2 and resp[0] == 0x41 and resp[1] == 0x42
    except (TimeoutError, OSError, ConnectionRefusedError):
        return False


# ---------------------------------------------------------------------------
# Composite
# ---------------------------------------------------------------------------


def _fingerprint_one(host: str, port: int, scheme: str = "http") -> TomcatFingerprint:
    base = f"{scheme}://{host}:{port}"

    # 1. Root probe — captures Server header and any redirect.
    root_code, server, root_body = _http_probe(f"{base}/")

    # 2. Force an error page to extract the version (Tomcat ships an
    #    HTML error page that includes "Apache Tomcat/X.Y.Z" in the
    #    title — works even when manager is hidden).
    err_code, _, err_body = _http_probe(f"{base}/kryon-recon-noexistente-{port}")
    version = _extract_tomcat_version(err_body, root_body, server)
    error_page_leaks = bool(_TOMCAT_VERSION_RE.search(err_body))

    # 3. Endpoint reachability — manager / host-manager / examples / docs.
    manager_code, _, _ = _http_probe(f"{base}/manager/html")
    host_manager_code, _, _ = _http_probe(f"{base}/host-manager/html")
    docs_code, _, _ = _http_probe(f"{base}/docs/")
    examples_code, _, _ = _http_probe(f"{base}/examples/")

    # 4. AJP probe — only meaningful when Tomcat detected (avoid noise
    #    on non-Tomcat hosts that happen to listen on 8009).
    is_tomcat = bool(version) or "tomcat" in server.lower() or "coyote" in server.lower()
    ajp_open = _ajp_probe(host) if is_tomcat else False

    return TomcatFingerprint(
        host=host,
        port=port,
        scheme=scheme,
        is_tomcat=is_tomcat,
        version=version,
        server_header=server,
        manager_status=manager_code,
        host_manager_status=host_manager_code,
        docs_status=docs_code,
        examples_status=examples_code,
        ajp_open=ajp_open,
        error_page_leaks_version=error_page_leaks,
    )


# ---------------------------------------------------------------------------
# Public function-tool
# ---------------------------------------------------------------------------


@function_tool
@cache_scan_result(scan_type="tomcat_fingerprint", ttl=14400)
def tomcat_recon(target: str, port: int = 8080, scheme: str = "http") -> str:
    """Fingerprint a target as Apache Tomcat — version + endpoint exposure + AJP.

    Read-only HTTP/TCP probes. No authentication, no exploit attempts.

    Args:
        target: IP or hostname of the suspected Tomcat server.
        port: Tomcat HTTP connector port (default 8080).
        scheme: "http" or "https" (default http).

    Returns:
        Human-readable summary + machine-parseable `[parsed]` tail line
        (is_tomcat=, version=, manager=, ajp=).
    """
    fp = _fingerprint_one(target, port, scheme)

    lines = [f"Tomcat recon for {target}:{port}/{scheme}:"]
    if not fp.is_tomcat:
        lines.append("  → no Apache Tomcat detected (banner does not match)")
        if fp.server_header:
            lines.append(f"  Server header: {fp.server_header}")
        return "\n".join(lines)

    flavour = f"Apache Tomcat {fp.version}" if fp.version else "Apache Tomcat (version unknown)"
    lines.append(f"  → {flavour}")
    if fp.server_header:
        lines.append(f"  Server header: {fp.server_header}")
    if fp.error_page_leaks_version:
        lines.append("  ⚠ error pages disclose exact version (information leak)")

    def _status_label(code: int) -> str:
        if code == 200:
            return "200 OPEN (auth not required)"
        if code in (301, 302, 307, 308):
            return f"{code} redirect"
        if code == 401:
            return "401 auth required (Basic/Digest configured)"
        if code == 403:
            return "403 forbidden (access restricted)"
        if code == 404:
            return "404 not deployed"
        if code == 0:
            return "no response / blocked"
        return f"{code}"

    lines.append(f"  /manager/html       → {_status_label(fp.manager_status)}")
    lines.append(f"  /host-manager/html  → {_status_label(fp.host_manager_status)}")
    lines.append(f"  /docs/              → {_status_label(fp.docs_status)}")
    lines.append(f"  /examples/          → {_status_label(fp.examples_status)}")
    lines.append(
        f"  AJP 8009            → {'OPEN (Ghostcat CVE-2020-1938 risk)' if fp.ajp_open else 'closed / filtered'}"
    )

    lines.append(
        f"\n[parsed] is_tomcat={fp.is_tomcat} version={fp.version or '-'} manager={fp.manager_status} ajp={fp.ajp_open}"
    )
    return "\n".join(lines)


__all__ = ["tomcat_recon", "TomcatFingerprint"]
