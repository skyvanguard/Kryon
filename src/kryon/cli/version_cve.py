"""Deterministic version → CVE → exploit-availability correlation. The probe
layer produces rich version banners (OpenSSH_9.6, Apache Tomcat/7.0.34,
vsftpd 2.3.4, …); this maps a (product, version) pair to the well-known CVEs that
affect it and flags whether a public exploit (Metasploit/ExploitDB) exists.

Pure + offline: a curated table of high-signal, exploit-backed CVEs — no network,
no LLM. Findings are emitted with ``needs_verification`` semantics in the wording
(banners are spoofable and distros backport fixes).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from kryon.cli.engage import Finding, make_finding
from kryon.scoring.confidence import _VERIFICATION_BANDS

_Ver = tuple[int, ...]


def parse_version(text: str) -> _Ver | None:
    """Extract the first dotted numeric version from a banner → tuple of ints."""
    m = re.search(r"(\d+(?:\.\d+){1,3})", text)
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def _pad(a: _Ver, b: _Ver) -> tuple[_Ver, _Ver]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def _in_range(v: _Ver, lo: _Ver, hi: _Ver) -> bool:
    vl, lol = _pad(v, lo)
    vh, hih = _pad(v, hi)
    return lol <= vl and vh <= hih


@dataclass(frozen=True)
class CVEHit:
    product: str
    cve: str
    severity: str
    exploit: bool  # public exploit (Metasploit/ExploitDB) known
    name: str


# (product keyword [lowercased substring of banner], vmin, vmax, cve, severity, has_exploit, name)
_CVE_DB: tuple[tuple[str, _Ver, _Ver, str, str, bool, str], ...] = (
    # OpenSSH
    ("openssh", (8, 5), (9, 7), "CVE-2024-6387", "HIGH", True, "regreSSHion — unauth RCE (root)"),
    ("openssh", (2, 3), (7, 7), "CVE-2018-15473", "MEDIUM", True, "username enumeration"),
    ("openssh", (6, 2), (8, 7), "CVE-2023-38408", "HIGH", True, "ssh-agent PKCS#11 RCE"),
    # Apache Tomcat
    ("tomcat", (6, 0), (9, 0, 30), "CVE-2020-1938", "HIGH", True, "Ghostcat — AJP file read/include → RCE"),
    ("tomcat", (7, 0), (9, 0, 0), "CVE-2017-12617", "HIGH", True, "JSP upload RCE (PUT + readonly=false)"),
    # Apache httpd
    ("apache", (2, 4, 49), (2, 4, 49), "CVE-2021-41773", "CRITICAL", True, "path traversal → RCE"),
    ("apache", (2, 4, 50), (2, 4, 50), "CVE-2021-42013", "CRITICAL", True, "path traversal → RCE (41773 bypass)"),
    # FTP servers
    ("vsftpd", (2, 3, 4), (2, 3, 4), "CVE-2011-2523", "CRITICAL", True, "vsftpd 2.3.4 backdoor (Metasploit)"),
    ("proftpd", (1, 3, 5), (1, 3, 5), "CVE-2015-3306", "CRITICAL", True, "mod_copy unauth file read/write → RCE"),
    # Mail
    ("exim", (4, 87), (4, 91), "CVE-2019-10149", "CRITICAL", True, "The Return of the WIZard — RCE"),
    # Web / app
    ("jenkins", (1, 0), (2, 56), "CVE-2017-1000353", "HIGH", True, "Java deserialization RCE"),
    ("confluence", (1, 0), (8, 5, 3), "CVE-2023-22515", "CRITICAL", True, "broken access control — admin takeover"),
    ("webmin", (1, 0), (1, 920), "CVE-2019-15107", "CRITICAL", True, "password_change.cgi unauth RCE"),
    ("phpmyadmin", (4, 8, 0), (4, 8, 1), "CVE-2018-12613", "HIGH", True, "LFI → RCE"),
    ("grafana", (8, 0, 0), (8, 3, 0), "CVE-2021-43798", "HIGH", True, "plugin path traversal (arbitrary file read)"),
    ("gitlab", (16, 0), (16, 5, 1), "CVE-2023-7028", "CRITICAL", True, "account takeover via password reset"),
    # SMB / Windows
    ("samba", (3, 5, 0), (4, 6, 4), "CVE-2017-7494", "CRITICAL", True, "SambaCry — is_known_pipename RCE"),
)


def correlate(product_banner: str) -> list[CVEHit]:
    """Match a raw banner against the curated CVE DB. Deterministic. The version is
    parsed from the text AFTER the product keyword (so 'SSH-2.0-OpenSSH_9.6' uses
    9.6, not the 2.0 protocol version)."""
    low = product_banner.lower()
    out: list[CVEHit] = []
    for kw, lo, hi, cve, sev, exploit, name in _CVE_DB:
        idx = low.find(kw)
        if idx < 0:
            continue
        ver = parse_version(low[idx + len(kw) :])
        if ver is not None and _in_range(ver, lo, hi):
            out.append(CVEHit(kw, cve, sev, exploit, name))
    return out


def to_findings(hits: list[CVEHit], host: str, port: int, banner: str) -> list[Finding]:
    out: list[Finding] = []
    for h in hits:
        exp = " · exploit público disponible (Metasploit/ExploitDB)" if h.exploit else ""
        out.append(
            make_finding(
                "CWE-1395",
                h.severity,
                host,
                h.cve.lower(),  # rule_id = "cve-2024-6387" (no double prefix)
                f"{h.cve} aplicable en {host}:{port} — {h.name}{exp}.",
                evidence=f"Banner '{banner[:80]}' en rango afectado por {h.cve} "
                "(verificar: el banner es spoofeable y puede tener fix backported)",
                remediation=f"Actualizar el componente fuera del rango de {h.cve}; confirmar el parche real (no solo el banner).",
                # F210 — banner-only version→CVE mapping is INFERRED, not
                # probed: banners are spoofable and distros backport fixes.
                # Put the uncertainty in the data (not just the wording) so
                # the reporting layer routes it to "requiere verificación"
                # and confidence scoring can't promote it to ground truth.
                verification_level="inferred",
                confidence=_VERIFICATION_BANDS["inferred"],
                needs_verification=True,
            )
        )
    return out


def correlate_banner(banner: str, host: str, port: int) -> list[Finding]:
    """One-shot: banner → applicable-CVE findings. Never raises."""
    try:
        return to_findings(correlate(banner), host, port, banner)
    except Exception:  # noqa: BLE001
        return []


def correlate_services(services) -> list[Finding]:
    """T4-A4: run the curated banner→CVE table over EVERY discovered service.

    The only caller of ``correlate_banner`` was the SSH probe, so vsftpd/ProFTPd/
    Samba/Jenkins/Confluence/GitLab on their real ports never triggered a known-CVE
    finding — the high-value one-shots were effectively dead for their own services.
    """
    out: list[Finding] = []
    for svc in services or []:
        product = (getattr(svc, "product", "") or "").strip()
        version = (getattr(svc, "version", "") or "").strip()
        banner = f"{product} {version}".strip()
        if not banner:
            continue
        host = getattr(svc, "host", "") or ""
        port = getattr(svc, "port", 0) or 0
        out.extend(correlate_banner(banner, host, port))
    return out
