"""Batch O — edge VPN / remote-access appliance exposure. Fortinet SSL-VPN,
Citrix NetScaler/Gateway, Palo Alto GlobalProtect, Pulse/Ivanti Connect Secure.
These are the most-exploited perimeter products (CISA KEV / ransomware entry).

STRICTLY READ-ONLY and banca-safe: we GET the PUBLIC portal path and fingerprint
the product by title/cookie/markers. We NEVER send the exploit primitive
(Citrix-Bleed malformed Host, Pulse path traversal, GlobalProtect cmd-injection).
The finding flags an exposed appliance whose patch level must be verified against
its known CVEs — not a confirmed exploit.

Self-contained HTTP helper (captures Set-Cookie + disables redirects, which the
shared _http_get can't), so no dependency beyond stdlib. Imports _f from
service_probes (one-way; engage imports the probe modules lazily, no cycle).
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f

_T = 5.0


class _NoRedirect:
    """urllib redirect handler that stops at the 3xx so we can read its cookies."""

    def http_error_302(self, req, fp, code, msg, headers):  # noqa: D401, ANN001
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_302


def _vpn_get(host: str, port: int, path: str, scheme: str) -> tuple[int, str, str] | None:
    """GET path; return (status, set_cookie_joined_lower, body) or None. No redirects."""
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    handlers: list = [_NoRedirect()]
    if scheme == "https":
        import ssl  # noqa: PLC0415

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(f"{scheme}://{host}:{port}{path}", headers={"User-Agent": "Mozilla/5.0 kryon-probe"})
    try:
        with opener.open(req, timeout=_T) as r:  # noqa: S310 — fixed scheme, read-only GET
            cookies = " ".join(v for k, v in r.headers.items() if k.lower() == "set-cookie").lower()
            return r.status, cookies, r.read(6000).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        try:
            cookies = " ".join(v for k, v in (e.headers or {}).items() if k.lower() == "set-cookie").lower()
            return e.code, cookies, e.read(4000).decode("latin-1", "replace")
        except Exception:  # noqa: BLE001
            return e.code, "", ""
    except (OSError, ValueError):
        return None


def _appliance(svc: DiscoveredService, rule_id: str, product: str, cve: str, evidence: str) -> Finding:
    return _f(
        svc, "CWE-1395", "HIGH", rule_id,
        f"{product} expuesto en {svc.host}:{svc.port} — verificar nivel de parche contra {cve}.",
        evidence,
        f"Restringir el portal a IPs/MFA conocidas; aplicar los parches de {cve}; monitorear IOCs de explotación.",
    )


def _check_fortinet(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _vpn_get(svc.host, svc.port, "/remote/login?lang=en", scheme)
    if not r or r[0] not in (200, 401, 403):
        return None
    body = r[2].lower()
    if any(m in body for m in ("/sslvpn/", "logincheck", "fgt_lang", "fortinet")) or "svpncookie" in r[1]:
        return _appliance(svc, "fortinet-sslvpn-exposed", "FortiGate SSL-VPN",
                          "CVE-2024-21762 / CVE-2022-42475 / CVE-2018-13379",
                          "GET /remote/login → portal SSL-VPN de Fortinet (markers logincheck/sslvpn/SVPNCOOKIE)")
    return None


def _check_citrix(svc: DiscoveredService, scheme: str) -> Finding | None:
    for path in ("/vpn/index.html", "/logon/LogonPoint/tmindex.html", "/"):
        r = _vpn_get(svc.host, svc.port, path, scheme)
        if not r:
            continue
        body = r[2].lower()
        if "nsc_" in r[1] or "ns-cache" in body or "citrix" in body or "netscaler" in body or "/vpn/js/" in body:
            return _appliance(svc, "citrix-netscaler-exposed", "Citrix NetScaler/Gateway",
                              "CVE-2023-4966 (Citrix Bleed) / CVE-2023-3519 / CVE-2019-19781",
                              f"GET {path} → NetScaler/Gateway (cookie NSC_ / marcador Citrix)")
    return None


def _check_globalprotect(svc: DiscoveredService, scheme: str) -> Finding | None:
    for path in ("/global-protect/login.esp", "/sslvpn/login.esp"):
        r = _vpn_get(svc.host, svc.port, path, scheme)
        if not r or r[0] not in (200, 302):
            continue
        body = r[2].lower()
        if "globalprotect" in body or "global-protect" in body or "/global-protect/" in body:
            return _appliance(svc, "paloalto-globalprotect-exposed", "Palo Alto GlobalProtect",
                              "CVE-2024-3400 / CVE-2021-3064",
                              f"GET {path} → portal GlobalProtect")
    return None


def _check_pulse_ivanti(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _vpn_get(svc.host, svc.port, "/dana-na/auth/url_default/welcome.cgi", scheme)
    if not r or r[0] not in (200, 302):
        return None
    body = r[2].lower()
    if any(c in r[1] for c in ("dsid", "dssigninurl", "dslastaccess")) or "pulse" in body or "ivanti" in body or "dana-na" in body:
        return _appliance(svc, "pulse-ivanti-exposed", "Pulse/Ivanti Connect Secure",
                          "CVE-2024-21887 / CVE-2023-46805 / CVE-2019-11510",
                          "GET /dana-na/.../welcome.cgi → Pulse/Ivanti (cookie DSID / marcador dana-na)")
    return None


_VPN_PROBES = (_check_fortinet, _check_citrix, _check_globalprotect, _check_pulse_ivanti)


def run_vpn_probes(svc: DiscoveredService, scheme: str = "https") -> list[Finding]:
    """Fingerprint exposed edge-VPN appliances (read-only). Never raises."""
    out: list[Finding] = []
    for probe in _VPN_PROBES:
        try:
            f = probe(svc, scheme)
            if f:
                out.append(f)
        except Exception:  # noqa: BLE001
            continue
    return out
