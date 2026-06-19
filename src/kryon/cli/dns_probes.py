"""Deterministic DNS / email-security findings — SPF / DMARC / DKIM posture and
subdomain-takeover candidates. Domain-keyed (run against the target domain),
READ-ONLY DNS lookups, graceful. High value: missing/weak SPF+DMARC is the root of
e-mail spoofing/phishing risk, and is a recurring compliance gap.
"""

from __future__ import annotations

from kryon.cli.engage import _SEV_RANK, Finding

# Known services whose dangling CNAME enables subdomain takeover (non-exhaustive).
_TAKEOVER_FINGERPRINTS = (
    "github.io", "herokudns.com", "herokuapp.com", "s3.amazonaws.com", "cloudfront.net",
    "azurewebsites.net", "cloudapp.net", "trafficmanager.net", "fastly.net", "ghost.io",
    "pantheonsite.io", "wpengine.com", "zendesk.com", "readthedocs.io", "surge.sh",
    "bitbucket.io", "shopify.com", "myshopify.com", "unbouncepages.com", "helpscoutdocs.com",
)

_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "dkim", "mail", "smtp", "s1", "s2")


def _df(domain: str, cwe: str, sev: str, rule_id: str, msg: str, evidence: str, fix: str) -> Finding:
    return Finding(cwe=cwe, severity=sev, host=domain, rule_id=rule_id, message=msg,
                   evidence=evidence, remediation=fix, severity_rank=_SEV_RANK[sev])


def _txt(name: str) -> list[str]:
    try:
        import dns.resolver  # noqa: PLC0415

        ans = dns.resolver.resolve(name, "TXT", lifetime=5)
        return ["".join(s.decode() if isinstance(s, bytes) else str(s) for s in r.strings) for r in ans]
    except Exception:  # noqa: BLE001 — NXDOMAIN / timeout / no dnspython → treat as "no record"
        return []


def _cname(name: str) -> str | None:
    try:
        import dns.resolver  # noqa: PLC0415

        ans = dns.resolver.resolve(name, "CNAME", lifetime=5)
        return str(ans[0].target).rstrip(".").lower()
    except Exception:  # noqa: BLE001
        return None


def _check_spf(domain: str) -> Finding | None:
    spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
    if not spf:
        return _df(domain, "CWE-1390", "MEDIUM", "spf-missing",
                   f"El dominio {domain} no tiene registro SPF — permite spoofing del remitente.",
                   "Sin TXT 'v=spf1' en el apex",
                   "Publicar un SPF restrictivo (v=spf1 include:... -all).")
    record = spf[0].lower()
    if "+all" in record or record.rstrip().endswith(" all"):
        return _df(domain, "CWE-1390", "MEDIUM", "spf-permissive",
                   f"SPF permisivo (+all) en {domain} — cualquier servidor puede mandar correo como el dominio.",
                   f"SPF: {spf[0][:80]}",
                   "Cambiar +all por -all (hard fail) o ~all (soft fail).")
    return None


def _check_dmarc(domain: str) -> Finding | None:
    dmarc = [t for t in _txt(f"_dmarc.{domain}") if "v=dmarc1" in t.lower()]
    if not dmarc:
        return _df(domain, "CWE-1390", "MEDIUM", "dmarc-missing",
                   f"El dominio {domain} no tiene registro DMARC — sin política anti-spoofing/visibilidad.",
                   "Sin TXT 'v=DMARC1' en _dmarc",
                   "Publicar DMARC (empezar con p=none + rua para monitorear, luego p=quarantine/reject).")
    policy = ""
    for part in dmarc[0].lower().split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part[2:].strip()
    if policy in ("none", ""):
        return _df(domain, "CWE-1390", "LOW", "dmarc-policy-none",
                   f"DMARC en {domain} con política p=none — solo monitorea, no bloquea el spoofing.",
                   f"DMARC: {dmarc[0][:80]}",
                   "Endurecer a p=quarantine y luego p=reject una vez validado el flujo legítimo.")
    return None


def _check_dkim(domain: str) -> Finding | None:
    for sel in _DKIM_SELECTORS:
        for t in _txt(f"{sel}._domainkey.{domain}"):
            if "v=dkim1" in t.lower() or "k=rsa" in t.lower() or "p=" in t.lower():
                return None  # at least one common selector has DKIM → fine
    return _df(domain, "CWE-1390", "LOW", "dkim-not-found",
               f"No se encontró DKIM en {domain} (selectores comunes) — correo sin firma criptográfica.",
               f"Sin TXT DKIM en {'/'.join(_DKIM_SELECTORS[:5])}._domainkey",
               "Configurar DKIM (firmar el correo saliente) y alinearlo con SPF/DMARC.")


def _caa(name: str) -> list[str]:
    try:
        import dns.resolver  # noqa: PLC0415

        ans = dns.resolver.resolve(name, "CAA", lifetime=5)
        return [str(r) for r in ans]
    except Exception:  # noqa: BLE001 — no CAA / timeout
        return []


def _has_mx(domain: str) -> bool:
    try:
        import dns.resolver  # noqa: PLC0415

        return len(dns.resolver.resolve(domain, "MX", lifetime=5)) > 0
    except Exception:  # noqa: BLE001
        return False


def _check_caa(domain: str) -> Finding | None:
    if _caa(domain):
        return None
    return _df(domain, "CWE-295", "LOW", "caa-missing",
               f"El dominio {domain} no tiene registro CAA — cualquier CA puede emitir certificados.",
               "Sin RR CAA en el apex",
               "Publicar CAA restringiendo la emisión a la(s) CA(s) autorizada(s) (issue \"letsencrypt.org\").")


def _check_mta_sts(domain: str) -> Finding | None:
    if not _has_mx(domain):
        return None  # no email → MTA-STS not applicable
    if any("v=stsv1" in t.lower() for t in _txt(f"_mta-sts.{domain}")):
        return None
    return _df(domain, "CWE-319", "LOW", "mta-sts-missing",
               f"El dominio {domain} recibe correo pero no tiene MTA-STS — el SMTP entrante puede degradarse a texto plano.",
               "Sin TXT 'v=STSv1' en _mta-sts",
               "Publicar el TXT _mta-sts + la policy HTTPS (mode: enforce) para forzar TLS en el correo entrante.")


def _check_tls_rpt(domain: str) -> Finding | None:
    if not _has_mx(domain):
        return None
    if any("v=tlsrptv1" in t.lower() for t in _txt(f"_smtp._tls.{domain}")):
        return None
    return _df(domain, "CWE-778", "LOW", "tls-rpt-missing",
               f"El dominio {domain} recibe correo pero no tiene TLS-RPT — sin visibilidad de fallos de TLS en SMTP.",
               "Sin TXT 'v=TLSRPTv1' en _smtp._tls",
               "Publicar TLS-RPT (_smtp._tls TXT con rua=mailto:) para recibir reportes de fallos de entrega TLS.")


def _check_subdomain_takeover(domain: str) -> Finding | None:
    target = _cname(domain)
    if not target:
        return None
    hit = next((fp for fp in _TAKEOVER_FINGERPRINTS if fp in target), None)
    if hit:
        # The CNAME points at a takeover-able service. If the apex A-record no longer
        # resolves (the service is unclaimed), this is a strong takeover candidate.
        import socket  # noqa: PLC0415

        try:
            socket.getaddrinfo(domain, None)
            unresolved = False
        except OSError:
            unresolved = True
        sev = "HIGH" if unresolved else "LOW"
        note = "el destino no resuelve (servicio sin reclamar = takeover probable)" if unresolved else "verificar si el recurso está reclamado"
        return _df(domain, "CWE-350", sev, "subdomain-takeover-candidate",
                   f"{domain} apunta (CNAME) a {hit} — candidato a subdomain takeover.",
                   f"CNAME → {target}; {note}",
                   f"Remover el CNAME colgante o reclamar el recurso en {hit}.")
    return None


def run_dns_probes(domain: str) -> list[Finding]:
    """SPF/DMARC/DKIM posture + subdomain-takeover for a domain. Never raises.
    Skips IP literals (no email/DNS posture to assess)."""
    import ipaddress  # noqa: PLC0415

    try:
        ipaddress.ip_address(domain)
        return []  # an IP, not a domain
    except ValueError:
        pass
    if "." not in domain or domain.endswith(".local"):
        return []
    out: list[Finding] = []
    for fn in (_check_spf, _check_dmarc, _check_dkim, _check_caa, _check_mta_sts, _check_tls_rpt, _check_subdomain_takeover):
        try:
            f = fn(domain)
            if f:
                out.append(f)
        except Exception:  # noqa: BLE001
            continue
    return out
