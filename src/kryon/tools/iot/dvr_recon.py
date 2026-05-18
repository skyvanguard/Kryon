"""F197 — DVR vendor fingerprinting (Dahua / Hikvision / ONVIF generic).

Banca-safe by design: read-only HTTP probes against the DVR's web UI
and admin endpoints. No auth, no exploit attempts. Returns vendor +
best-effort model/firmware + which markers triggered.

Used by:
  - `kryon engage` Phase 2b' device family detection — routes DVR
    targets to the `dvr-audit` skill instead of the generic web flow.
  - The `dvr-audit` skill itself, narrating findings.

Vendor markers (HTTP-only, no authentication required):
  Hikvision: "App-WebS" Server header; presence of `/doc/page/login.asp`;
             "Hikvision" string in HTML title or favicon hash.
  Dahua:     "Webs" or "Boa/0.94.14" Server header; presence of
             `/RPC2_Login` endpoint; "Dahua" string in HTML title.
  ONVIF:     SOAP envelope response from `/onvif/device_service`
             (POST GetDeviceInformation, no auth).

References:
  - CVE-2017-7921 — Hikvision auth bypass (target marker: `/Security/users?auth=...`)
  - CVE-2021-33044 / CVE-2021-33045 — Dahua auth bypass on `/RPC2_Login`
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool

_HTTP_TIMEOUT_S = 5


@dataclass(frozen=True)
class DvrFingerprint:
    """Outcome of a single-host DVR fingerprint probe."""

    host: str
    port: int
    scheme: str = "http"
    vendor: str = "unknown"  # hikvision / dahua / onvif / generic-dvr / unknown
    model: str = ""
    firmware: str = ""
    markers: list[str] = field(default_factory=list)
    server_header: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _http_get(url: str, *, timeout_s: int = _HTTP_TIMEOUT_S) -> tuple[int, str, str]:
    """Plain HTTP GET. Returns (status_code, server_header, body[:4096]).

    Never raises — network errors collapse to (0, "", "").
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "kryon/dvr-recon"})
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            server = resp.headers.get("Server", "")
            return resp.status, server, body
    except urllib.error.HTTPError as exc:
        # 401/403/404 still tell us the server is alive — keep the headers.
        body = ""
        try:
            body = (exc.fp.read(4096) or b"").decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — best-effort body capture
            pass
        server = exc.headers.get("Server", "") if exc.headers else ""
        return exc.code, server, body
    except (TimeoutError, urllib.error.URLError, OSError, ssl.SSLError):
        return 0, "", ""


def _http_post_xml(url: str, body: str, *, timeout_s: int = _HTTP_TIMEOUT_S) -> tuple[int, str]:
    """POST a SOAP envelope. Returns (status_code, body[:4096]).

    Used for ONVIF GetDeviceInformation probe (no auth).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            headers={
                "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"',
                "User-Agent": "kryon/dvr-recon",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, (exc.fp.read(4096) or b"").decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return exc.code, ""
    except (TimeoutError, urllib.error.URLError, OSError, ssl.SSLError):
        return 0, ""


# ---------------------------------------------------------------------------
# Vendor markers (regex)
# ---------------------------------------------------------------------------

_HIKVISION_MARKERS = (
    (re.compile(r"App-WebS", re.IGNORECASE), "server-header-App-WebS"),
    (re.compile(r"<title>[^<]*Hikvision", re.IGNORECASE), "title-Hikvision"),
    (re.compile(r'href="/doc/page/login\.asp"', re.IGNORECASE), "path-doc-page-login"),
    (re.compile(r"DS-\d{4}", re.IGNORECASE), "model-DS-XXXX"),
)

_DAHUA_MARKERS = (
    (re.compile(r"^Webs$", re.IGNORECASE), "server-header-Webs"),
    (re.compile(r"^Boa/0\.94\.14", re.IGNORECASE), "server-header-Boa-0.94.14"),
    (re.compile(r"<title>[^<]*Dahua", re.IGNORECASE), "title-Dahua"),
    (re.compile(r"dh-ipc|DHI-\w+|DH-\w+", re.IGNORECASE), "model-Dahua-DH"),
)

_FIRMWARE_RE = re.compile(r"firmware[^\d]+(\d+\.\d+\.\d+)", re.IGNORECASE)
_MODEL_RE = re.compile(r"(?:DS-[\w-]+|DHI-[\w-]+|DH-[\w-]+)", re.IGNORECASE)


def _fingerprint_one(host: str, port: int, scheme: str) -> DvrFingerprint:
    """Probe a single host:port:scheme combination."""
    url_root = f"{scheme}://{host}:{port}/"
    code, server, body = _http_get(url_root)

    markers: list[str] = []
    vendor = "unknown"
    model = ""
    firmware = ""

    if code == 0:
        return DvrFingerprint(host=host, port=port, scheme=scheme)

    # Hikvision detection
    for rx, name in _HIKVISION_MARKERS:
        if rx.search(server) or rx.search(body):
            markers.append(name)
            vendor = "hikvision"

    # Dahua detection (only if Hikvision didn't already hit)
    if vendor != "hikvision":
        for rx, name in _DAHUA_MARKERS:
            if rx.search(server) or rx.search(body):
                markers.append(name)
                vendor = "dahua"

    # Hikvision deep probe — /doc/page/login.asp existence
    if vendor == "hikvision" or "DS-" in server + body:
        code2, _, body2 = _http_get(f"{scheme}://{host}:{port}/doc/page/login.asp")
        if code2 in (200, 401, 403):
            markers.append("hikvision-login-asp-present")
            vendor = "hikvision"
            if not model:
                m = _MODEL_RE.search(body2 or body)
                if m:
                    model = m.group(0).upper()

    # Dahua deep probe — /RPC2_Login existence
    if vendor == "dahua" or "Boa" in server:
        code2, _, body2 = _http_get(f"{scheme}://{host}:{port}/RPC2_Login")
        if code2 in (200, 401, 405):
            markers.append("dahua-rpc2-login-present")
            vendor = "dahua"

    # Generic-DVR fallback — common ports + RTSP banner suggest a DVR
    if vendor == "unknown" and port in (80, 81, 8000, 8080, 8081):
        if "Server: " in body or server:
            # If server header has something but no marker matched, tag generic
            # so the engage flow still routes it to dvr-audit recon.
            if any(s in (server.lower() + body.lower()) for s in ("dvr", "ipc", "camera", "nvr")):
                vendor = "generic-dvr"
                markers.append("generic-dvr-keyword")

    # Firmware extraction (best effort)
    m_fw = _FIRMWARE_RE.search(body)
    if m_fw:
        firmware = m_fw.group(1)

    return DvrFingerprint(
        host=host,
        port=port,
        scheme=scheme,
        vendor=vendor,
        model=model,
        firmware=firmware,
        markers=markers,
        server_header=server,
    )


def _try_onvif(host: str) -> tuple[bool, str]:
    """Probe ONVIF GetDeviceInformation on the standard port (no auth).

    Returns (is_onvif, evidence_xml_snippet).
    """
    onvif_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        "<s:Body>"
        '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
        "</s:Body></s:Envelope>"
    )
    for port in (80, 8080, 8000):
        for scheme in ("http",):
            url = f"{scheme}://{host}:{port}/onvif/device_service"
            code, body = _http_post_xml(url, onvif_body)
            if code in (200, 400, 401, 500) and ("onvif" in body.lower() or "soap" in body.lower()):
                return True, body[:2048]
    return False, ""


# ---------------------------------------------------------------------------
# Public function-tool
# ---------------------------------------------------------------------------


@function_tool
@cache_scan_result(scan_type="dvr_fingerprint", ttl=14400)  # 4 hours
def dvr_fingerprint(target: str, ports: str = "80,443,8000,8080") -> str:
    """Fingerprint a target as Dahua, Hikvision, ONVIF, generic-DVR, or unknown.

    Read-only HTTP probes. No authentication. No exploit attempts.

    Args:
        target: IP address or hostname of the suspected DVR / NVR / IP camera.
        ports: Comma-separated TCP ports to probe (default common DVR ports).

    Returns:
        Human-readable summary + machine-parseable lines (vendor=, model=,
        firmware=, markers=, server=).

    Examples:
        dvr_fingerprint(target="192.168.1.100")
        dvr_fingerprint(target="10.0.0.50", ports="80,443")
    """
    port_list: list[int] = []
    for p in ports.split(","):
        p = p.strip()
        if not p:
            continue
        try:
            port_list.append(int(p))
        except ValueError:
            continue

    if not port_list:
        return f"dvr_fingerprint: no valid ports in '{ports}'"

    results: list[DvrFingerprint] = []
    for port in port_list:
        scheme = "https" if port in (443, 8443) else "http"
        fp = _fingerprint_one(target, port, scheme)
        if fp.vendor != "unknown" or fp.server_header:
            results.append(fp)

    # ONVIF check is independent of the HTTP markers above
    is_onvif, onvif_evidence = _try_onvif(target)

    # Build the human-readable summary
    if not results and not is_onvif:
        return f"dvr_fingerprint: target {target} did not respond on {ports}"

    lines = [f"DVR fingerprint for {target}:"]
    for fp in results:
        lines.append(
            f"  port {fp.port}/{fp.scheme}: vendor={fp.vendor} "
            f"model={fp.model or '-'} firmware={fp.firmware or '-'} "
            f"server={fp.server_header[:80] or '-'}"
        )
        if fp.markers:
            lines.append(f"    markers: {', '.join(fp.markers)}")

    if is_onvif:
        lines.append("  ONVIF service: present on /onvif/device_service (no auth)")
        lines.append(f"    evidence: {onvif_evidence[:160]}...")

    # Tail machine-parseable line for downstream code
    if results:
        best = max(results, key=lambda f: len(f.markers))
        lines.append(f"\n[parsed] vendor={best.vendor} model={best.model} firmware={best.firmware} onvif={is_onvif}")
    else:
        lines.append(f"\n[parsed] vendor=onvif onvif={is_onvif}")

    return "\n".join(lines)


__all__ = ["dvr_fingerprint", "DvrFingerprint"]
