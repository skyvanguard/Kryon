"""edge VPN / remote-access appliance exposure. Fortinet SSL-VPN,
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
from kryon.cli.probe_base import _f, run_table

_T = 5.0


def _vpn_get(host: str, port: int, path: str, scheme: str) -> tuple[int, str, str] | None:
    """GET path; return (status, set_cookie_joined_lower, body) or None. No redirects."""
    from kryon.cli.probe_http import request  # noqa: PLC0415

    r = request(host, port, path, scheme=scheme, follow_redirects=False, timeout=_T,
                max_body=6000, user_agent="Mozilla/5.0 kryon-probe")
    return (r.status, r.cookies, r.body) if r else None


def _appliance(svc: DiscoveredService, rule_id: str, product: str, cve: str, evidence: str) -> Finding:
    # F210 — the EXPOSURE is confirmed by the fingerprint, but the specific-CVE
    # vulnerability is INFERRED from product identity (patch level not read).
    # Every appliance finding literally says "verificar nivel de parche", so it
    # belongs in the report's "requiere verificación" band, not ground truth.
    return _f(
        svc, "CWE-1395", "HIGH", rule_id,
        f"{product} expuesto en {svc.host}:{svc.port} — verificar nivel de parche contra {cve}.",
        evidence,
        f"Restringir el portal a IPs/MFA conocidas; aplicar los parches de {cve}; monitorear IOCs de explotación.",
        verification_level="heuristic",
    )


def _check_fortinet(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _vpn_get(svc.host, svc.port, "/remote/login?lang=en", scheme)
    if not r or r[0] not in (200, 401, 403):
        return None
    body = r[2].lower()
    if any(m in body for m in ("/sslvpn/", "logincheck", "fgt_lang", "fortinet")) or "svpncookie" in r[1]:
        return _appliance(svc, "fortinet-sslvpn-exposed", "FortiGate SSL-VPN",
                          "CVE-2025-24472 / CVE-2024-55591 / CVE-2024-21762 / CVE-2022-42475 / CVE-2018-13379",
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
                          "CVE-2025-22457 / CVE-2025-0282 / CVE-2024-21887 / CVE-2023-46805 / CVE-2019-11510",
                          "GET /dana-na/.../welcome.cgi → Pulse/Ivanti (cookie DSID / marcador dana-na)")
    return None


def _check_sonicwall(svc: DiscoveredService, scheme: str) -> Finding | None:
    for path in ("/cgi-bin/welcome", "/sonicui/7/login/", "/auth.html"):
        r = _vpn_get(svc.host, svc.port, path, scheme)
        if not r or r[0] not in (200, 302, 401, 403):
            continue
        body = r[2].lower()
        if "sonicwall" in body or "swap" in r[1] or "/sonicui/" in body or "sslvpnclient" in body:
            return _appliance(svc, "sonicwall-sslvpn-exposed", "SonicWall SMA/SSL-VPN",
                              "CVE-2024-40766 / CVE-2021-20038 / CVE-2021-20016",
                              f"GET {path} → portal SonicWall (marcador sonicwall/sonicui/SWAP)")
    return None


def _check_cisco_asa(svc: DiscoveredService, scheme: str) -> Finding | None:
    for path in ("/+CSCOE+/logon.html", "/+CSCOU+/", "/+webvpn+/index.html"):
        r = _vpn_get(svc.host, svc.port, path, scheme)
        if not r or r[0] not in (200, 302):
            continue
        body = r[2].lower()
        if "webvpn" in r[1] or "+cscoe+" in body or "anyconnect" in body or ("cisco" in body and "vpn" in body):
            return _appliance(svc, "cisco-asa-webvpn-exposed", "Cisco ASA/AnyConnect WebVPN",
                              "CVE-2023-20269 / CVE-2020-3452 / CVE-2018-0101",
                              f"GET {path} → portal WebVPN de Cisco ASA (cookie webvpn / marcador +CSCOE+/AnyConnect)")
    return None


def _check_f5_bigip(svc: DiscoveredService, scheme: str) -> Finding | None:
    for path in ("/my.policy", "/tmui/login.jsp", "/mgmt/shared/authn/login"):
        r = _vpn_get(svc.host, svc.port, path, scheme)
        if not r or r[0] not in (200, 302, 401):
            continue
        body = r[2].lower()
        cookies = r[1]
        if any(c in cookies for c in ("mrhsession", "lastmrh_session", "f5_st", "bigipserver")) or "/tmui/" in body or "f5 networks" in body:
            return _appliance(svc, "f5-bigip-exposed", "F5 BIG-IP (APM/TMUI)",
                              "CVE-2023-46747 / CVE-2022-1388 / CVE-2021-22986",
                              f"GET {path} → F5 BIG-IP (cookie MRHSession/F5_ST o consola TMUI)")
    return None


def _check_cisco_iosxe(svc: DiscoveredService, scheme: str) -> Finding | None:
    # CVE-2023-20198/20273 — IOS XE Web UI implant (KEV, decenas de miles comprometidos).
    # Fingerprint del login ONLY; NUNCA tocamos el primitivo de priv-esc/config.
    r = _vpn_get(svc.host, svc.port, "/webui/", scheme)
    if not r or r[0] not in (200, 302, 401, 403):
        return None
    body = r[2].lower()
    if "cisco ios xe" in body or "/webui/logoutredirect" in body or "webui_internal" in body or ("cisco" in body and "webui" in body):
        return _appliance(svc, "cisco-iosxe-webui-exposed", "Cisco IOS XE Web UI",
                          "CVE-2023-20198 / CVE-2023-20273",
                          "GET /webui/ → Web UI de IOS XE (implante masivo Oct-2023; no debe exponerse a internet)")
    return None


def _check_checkpoint(svc: DiscoveredService, scheme: str) -> Finding | None:
    # CVE-2024-24919 — Check Point Security Gateway / Mobile Access (KEV, directiva CISA).
    # Fingerprint del portal ONLY; NUNCA enviamos el POST de path-traversal que filtra secretos.
    for path in ("/", "/sslvpn/Login/Login", "/clients/"):
        r = _vpn_get(svc.host, svc.port, path, scheme)
        if not r or r[0] not in (200, 302, 401, 403):
            continue
        body = r[2].lower()
        # F210 — markers must be SPECIFIC to Check Point. The bare word
        # "checkpoint" (no space) matched Vercel's "Vercel Security
        # Checkpoint" anti-bot challenge page → FP HIGH+CVE on a Vercel
        # site (example.com). The real vendor spelling is "Check
        # Point" (with space) / the cvpnd VPN cookie / the /sslvpn/ portal
        # path — none of which appear on the Vercel challenge.
        if "check point" in body or "cvpnd" in r[1] or "/sslvpn/" in body:
            return _appliance(svc, "checkpoint-gateway-exposed", "Check Point Security Gateway / Mobile Access",
                              "CVE-2024-24919",
                              f"GET {path} → portal Check Point (verificar parche CVE-2024-24919; no se envió el traversal)")
    return None


_VPN_PROBES = (
    _check_fortinet, _check_citrix, _check_globalprotect, _check_pulse_ivanti,
    _check_sonicwall, _check_cisco_asa, _check_f5_bigip,
    _check_cisco_iosxe, _check_checkpoint,
)


def run_vpn_probes(svc: DiscoveredService, scheme: str = "https") -> list[Finding]:
    """Fingerprint exposed edge-VPN appliances (read-only). Never raises."""
    return run_table(svc, _VPN_PROBES, scheme)
