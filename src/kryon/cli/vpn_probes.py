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


def _vpn_get(host: str, port: int, path: str, scheme: str) -> tuple[int, str, str] | None:
    """GET path; return (status, set_cookie_joined_lower, body) or None. No redirects."""
    from kryon.cli.probe_http import request  # noqa: PLC0415

    r = request(host, port, path, scheme=scheme, follow_redirects=False, timeout=_T,
                max_body=6000, user_agent="Mozilla/5.0 kryon-probe")
    return (r.status, r.cookies, r.body) if r else None


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
