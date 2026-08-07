"""Scope & methodology section — what was assessed, how, and what was out of scope.

A technical reader needs to know the boundaries of the engagement: the targets, the date, the kind of
checks run (and that they were deterministic / non-intrusive), and what was explicitly NOT tested. All
fields are derived from the findings + config so the section stays honest per engagement.
"""

from __future__ import annotations

from kryon.intelligence.models import Finding

# Map a finding (by rule_id / title keywords) to a human technique label for "qué se evaluó".
_TECHNIQUE_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("Cabeceras y políticas de seguridad HTTP (CSP, HSTS, cookies, CSRF)", ("csp", "hsts", "csrf", "referrer", "cookie", "header", "x-frame", "cors")),
    ("Higiene de DNS y correo (DMARC, SPF, DKIM, CAA, MTA-STS, TLS-RPT)", ("dmarc", "spf", "dkim", "caa", "mta-sts", "tls-rpt", "dnssec", "mx")),
    ("Configuración TLS/SSL del servicio", ("tls", "ssl", "cipher", "certificate", "cert")),
    ("Exposición y configuración de servicios de red", ("smb", "redis", "ssh", "ftp", "snmp", "rdp", "port", "banner")),
    ("Vulnerabilidades de aplicación web", ("sqli", "xss", "rce", "ssrf", "lfi", "idor", "injection", "traversal")),
]


def render_scope_methodology(
    findings: list[Finding],
    client_name: str = "",
    scope: str = "",
    date: str = "",
) -> str:
    """Render the scope & methodology block."""
    from kryon.reporting.sections.findings_table import _escape  # noqa: PLC0415

    hosts = sorted({_host(f.affected_asset) for f in findings if f.affected_asset})
    techniques = _techniques_present(findings)
    tools = sorted({f.tool_source for f in findings if f.tool_source})

    hosts_html = ", ".join(f"<code>{_escape(h)}</code>" for h in hosts) or "—"
    tools_html = ", ".join(_escape(t) for t in tools) or "Kryon (detección determinista)"
    tech_items = "".join(f"<li>{t}</li>" for t in techniques) or "<li>Evaluación de configuración y exposición.</li>"

    target = _escape(scope) if scope else hosts_html
    client_line = f"<div><strong>Cliente</strong>{_escape(client_name)}</div>" if client_name else ""
    date_line = f"<div><strong>Fecha de evaluación</strong>{_escape(date)}</div>" if date else ""

    return f"""
    <div class="scope-methodology">
        <h2>Alcance y metodología</h2>
        <div class="scope-grid">
            <div><strong>Objetivo evaluado</strong>{target}</div>
            <div><strong>Activos</strong>{hosts_html}</div>
            {client_line}
            {date_line}
            <div><strong>Herramientas</strong>{tools_html}</div>
            <div><strong>Enfoque</strong>Detección determinista y reproducible (no intrusiva)</div>
        </div>

        <h3>Qué se evaluó</h3>
        <ul>{tech_items}</ul>

        <h3>Consideraciones</h3>
        <p>Los hallazgos provienen de detectores deterministas de Kryon: cada uno se basa en evidencia
        observada directamente (cabeceras, registros DNS, banners de servicio), por lo que son
        reproducibles y verificables. No se ejecutaron pruebas intrusivas, de denegación de servicio ni
        explotación activa salvo autorización explícita; el alcance se limitó a la observación pasiva y la
        evaluación de configuración del objetivo indicado.</p>
    </div>"""


def _host(asset: str) -> str:
    if ":" in asset:
        head, _, tail = asset.rpartition(":")
        if head and tail.isdigit():
            return head
    return asset


def _techniques_present(findings: list[Finding]) -> list[str]:
    present: list[str] = []
    for label, keys in _TECHNIQUE_RULES:
        for f in findings:
            hay = f"{getattr(f, 'rule_id', '') or ''} {f.title}".lower()
            if any(k in hay for k in keys):
                present.append(label)
                break
    return present
