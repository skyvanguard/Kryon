"""Bridge deterministic engine/engage findings → ``intelligence.Finding``.

The engine emits findings shaped like ``engage.Finding`` / a namespace
(``cwe/rule_id/severity/host/message/evidence``). Persistence
(``CLIFindingsCollector.save_findings``) and the report generator both consume
``intelligence.Finding``. Without this bridge the engine's deterministic
findings were display-only — never saved to the DB, never in a PDF.

Deterministic findings are marked ``CONFIRMED`` (they were observed by a probe,
not hypothesised by the model).
"""

from __future__ import annotations

from typing import Any


def _severity(raw: Any):
    from kryon.intelligence.models import Severity

    m = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return m.get(str(raw or "info").strip().lower(), Severity.INFO)


# Fallback remediation by CWE for the common deterministic-engine findings, used
# only when the source finding didn't carry its own remediation text (so the
# report never ships an empty remediation column).
_CWE_REMEDIATION: dict[str, str] = {
    "CWE-79": "Escapar la salida controlada por el usuario según el contexto HTML y aplicar una CSP restrictiva (script-src sin unsafe-inline/eval).",
    "CWE-89": "Usar consultas parametrizadas / prepared statements; nunca concatenar entrada en SQL.",
    "CWE-352": "Agregar tokens anti-CSRF por formulario y SameSite=strict en las cookies de sesión.",
    "CWE-693": "Configurar los headers de seguridad faltantes (HSTS con includeSubDomains, CSP, X-Content-Type-Options).",
    "CWE-1021": "Endurecer la CSP: eliminar 'unsafe-inline'/'unsafe-eval' y declarar object-src 'none'.",
    "CWE-295": "Publicar un registro CAA restringiendo qué CAs pueden emitir certificados para el dominio.",
    "CWE-200": "Endurecer Referrer-Policy (strict-origin-when-cross-origin) y minimizar la información divulgada.",
    "CWE-1390": "Publicar registros SPF, DMARC (p=reject) y DKIM para prevenir spoofing del dominio de correo.",
    "CWE-284": "Restringir el acceso a paneles administrativos: autenticación fuerte + allowlist de IP.",
    "CWE-319": "Forzar TLS en todo el tráfico y redirigir HTTP→HTTPS; habilitar HSTS.",
}


def _cvss(severity: Any) -> float | None:
    try:
        from kryon.compliance.cvss import cvss_score_for_severity

        return cvss_score_for_severity(str(severity or "info"))
    except Exception:  # noqa: BLE001 — enrichment is best-effort
        return None


def engine_finding_to_intelligence(f: Any):
    """Convert one engine/engage finding into an ``intelligence.Finding``.

    Accepts both attribute shapes: ``cwe``/``cwe_id``, ``rule_id``/``probe_id``,
    ``message``/``title``, ``host``/``url``.
    """
    from kryon.intelligence.models import Finding, ValidationStatus

    cwe = str(getattr(f, "cwe", "") or getattr(f, "cwe_id", "") or "").strip()
    # Normalize a bare numeric cwe ("1390") to the canonical "CWE-1390" form.
    if cwe and cwe.isdigit():
        cwe = f"CWE-{cwe}"
    rule = str(getattr(f, "rule_id", "") or getattr(f, "probe_id", "") or "").strip()
    msg = str(getattr(f, "message", "") or getattr(f, "title", "") or rule or "Finding").strip()
    host = str(getattr(f, "host", "") or getattr(f, "url", "") or "unknown").strip() or "unknown"
    title = f"{cwe}: {msg}" if cwe and cwe.lower() not in msg.lower() else msg

    severity = _severity(getattr(f, "severity", "info"))
    remediation = str(getattr(f, "remediation", "") or "").strip() or _CWE_REMEDIATION.get(cwe, "")

    return Finding(
        title=title[:200] or "Finding",
        description=msg,
        severity=severity,
        cvss_score=_cvss(severity),
        affected_asset=host,
        evidence=str(getattr(f, "evidence", "") or "")[:1000],
        tool_source=rule or "deterministic_engine",
        remediation=remediation,
        validation_status=ValidationStatus.CONFIRMED,
        validation_method="deterministic_engine",
    )


def engine_findings_to_intelligence(findings: list) -> list:
    """Convert a list; skips any element that fails to convert (never raises)."""
    out: list = []
    for f in findings or []:
        try:
            out.append(engine_finding_to_intelligence(f))
        except Exception:  # noqa: BLE001 — one bad finding must not drop the rest
            continue
    return out


__all__ = ["engine_finding_to_intelligence", "engine_findings_to_intelligence"]
