"""F85.G — LLM-narrated executive summary for engagement reports.

The legacy ``sections.executive_summary.render_executive_summary`` is
pure template: counts findings by severity and lists top criticals.
A bank manager reading that gets numbers, not insight.

This module adds a real LLM call that produces 3 Spanish paragraphs
of business-impact analysis written for non-technical readers:

  1. Critical risks and business impact ("¿qué pasa si no arreglamos?")
  2. Patterns and tendencies ("¿qué clase de exposición vemos?")
  3. Prioritised recommendation ("¿qué arreglo primero?")

The output is plain text (no HTML); the renderer wraps it into the
report layout. Falls back to empty string on any LLM failure so the
PDF still ships with the deterministic template summary.

Pattern cloned from ``compliance_narrator.py`` — stdlib urllib so we
don't add an httpx/openai-client dependency to the reporting extra,
auth-token logic that picks Ollama-vs-external by endpoint.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)


_DEFAULT_MODEL = os.environ.get("KRYON_EXEC_NARRATOR_MODEL", "deepseek-chat")
_DEFAULT_ENDPOINT = os.environ.get("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
_DEFAULT_TIMEOUT_S = int(os.environ.get("KRYON_NARRATOR_TIMEOUT_S", "30"))


_PROMPT_TEMPLATE = """Eres un CISO redactando el resumen ejecutivo de una
auditoría de ciberseguridad para {client_name}.

Audiencia: gerencia bancaria NO técnica. Lenguaje: español rioplatense,
profesional, factual, sin alarmismo. NO uses jerga ("RCE", "CWE",
"buffer overflow") — traduce a impacto al negocio.

Alcance auditado: {scope}
Total de hallazgos: {total} ({critical} críticos, {high} altos,
{medium} medios, {low} bajos)

Hallazgos críticos principales:
{top_critical}

Patrón de exposición observado:
{exposure_pattern}

Escribe EXACTAMENTE 3 párrafos, cada uno con su etiqueta exacta:

PARRAFO_1_IMPACTO: [2-3 oraciones explicando qué riesgo de negocio
existe HOY. Ejemplos válidos: "exposición de datos de tarjeta-
habiente regulada por PCI-DSS", "acceso administrativo sin segundo
factor en infraestructura crítica", "falta de monitoreo central de
intentos de intrusión". NO listes los hallazgos uno por uno.]

PARRAFO_2_PATRON: [2-3 oraciones identificando el patrón sistémico
detrás de los hallazgos individuales. Ejemplos válidos: "déficit de
hardening sobre los servicios expuestos", "falta de gestión
centralizada de parches", "controles compensatorios PCI-DSS
incompletos". El patrón explica el tipo de inversión necesaria.]

PARRAFO_3_RECOMENDACION: [2-3 oraciones con la recomendación de PRIMERA
ACCIÓN priorizada. Ejemplos válidos: "habilitar 2FA en consolas
administrativas en las próximas 72 horas y derivar al equipo de
infraestructura las rotaciones de credenciales", "asignar un sprint
del equipo de plataforma para cerrar los puertos de gestión expuestos
a Internet". Concreto y accionable.]

NO inventes hallazgos que no estén en la lista. NO uses HTML.
"""


def _top_critical_summary(findings: list[Any], n: int = 5) -> str:
    """Format the top N critical/high findings as plain-text bullets."""
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _severity_rank(f),
            getattr(f, "host", ""),
            getattr(f, "rule_id", ""),
        ),
    )
    lines = []
    for f in sorted_findings[:n]:
        sev = _severity_str(f)
        if sev not in ("CRITICAL", "HIGH"):
            break
        # Support both Finding shapes (engage.py with .message,
        # intelligence.models with .title)
        label = getattr(f, "message", None) or getattr(f, "title", "") or getattr(f, "rule_id", "?")
        host = getattr(f, "host", "") or getattr(f, "affected_asset", "")
        lines.append(f"  - [{sev}] {label} ({host})")
    return "\n".join(lines) or "  (sin hallazgos críticos)"


def _exposure_pattern(findings: list[Any]) -> str:
    """Identify the dominant exposure pattern based on CWE / rule_id
    distribution. Cheap heuristic — the LLM does the real synthesis."""
    cwes = Counter(getattr(f, "cwe", "") for f in findings if getattr(f, "cwe", ""))
    rules = Counter(getattr(f, "rule_id", "") for f in findings if getattr(f, "rule_id", ""))
    top_cwes = ", ".join(f"{cwe}({n})" for cwe, n in cwes.most_common(5) if cwe)
    top_rules = ", ".join(f"{r}({n})" for r, n in rules.most_common(5) if r)
    parts = []
    if top_cwes:
        parts.append(f"CWE más frecuentes: {top_cwes}")
    if top_rules:
        parts.append(f"reglas que más se dispararon: {top_rules}")
    return "; ".join(parts) or "(sin patrón claro)"


def _severity_str(f: Any) -> str:
    sev = getattr(f, "severity", "")
    if hasattr(sev, "value"):
        return str(sev.value).upper()
    return str(sev).upper()


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _severity_rank(f: Any) -> int:
    return _SEV_ORDER.get(_severity_str(f), 99)


def _count_by_severity(findings: list[Any]) -> Counter:
    return Counter(_severity_str(f) for f in findings)


def _is_ollama(endpoint: str) -> bool:
    return "11434" in endpoint or "ollama" in endpoint.lower()


def generate_executive_narrative(
    findings: list[Any],
    *,
    client_name: str = "",
    scope: str = "",
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    endpoint: str | None = None,
    model: str | None = None,
) -> str:
    """Generate a 3-paragraph executive narrative via LLM call.

    Returns the raw narrative text (no HTML), or empty string on any
    LLM failure. The caller decides how to render: the
    ``render_executive_summary`` helper concatenates it on top of the
    deterministic counts; multi_framework_pdf places it inside the
    cover-page region.
    """
    endpoint = endpoint or _DEFAULT_ENDPOINT
    model = model or _DEFAULT_MODEL

    by_sev = _count_by_severity(findings)
    prompt = _PROMPT_TEMPLATE.format(
        client_name=client_name or "el cliente auditado",
        scope=scope or "no especificado",
        total=len(findings),
        critical=by_sev.get("CRITICAL", 0),
        high=by_sev.get("HIGH", 0),
        medium=by_sev.get("MEDIUM", 0),
        low=by_sev.get("LOW", 0),
        top_critical=_top_critical_summary(findings),
        exposure_pattern=_exposure_pattern(findings),
    )

    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "top_p": 1,
            "max_tokens": 900,
        }
    ).encode()
    auth_token = "ollama" if _is_ollama(endpoint) else os.environ.get("OPENAI_API_KEY", "")
    req = urllib.request.Request(
        f"{endpoint.rstrip('/')}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth_token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            doc = json.loads(r.read())
    except Exception as exc:
        logger.warning("exec_narrative LLM call failed (%s); falling back to template", exc)
        return ""

    text = (doc.get("choices") or [{}])[0].get("message", {}).get("content", "")
    # Verify the 3 paragraph tags are present. If not, drop — falls
    # back to template-only summary upstream.
    if not all(tag in text for tag in ("PARRAFO_1_IMPACTO", "PARRAFO_2_PATRON", "PARRAFO_3_RECOMENDACION")):
        logger.info("exec_narrative output missing required tags; falling back")
        return ""

    # Strip any HTML the model tried to inject (we'll wrap ourselves
    # in the renderer).
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def render_narrative_as_html(narrative: str) -> str:
    """Convert the tagged 3-paragraph narrative into a sanitised HTML
    block ready to splice into the executive_summary section.

    Returns empty string when narrative is empty.
    """
    if not narrative:
        return ""

    def _extract(tag: str) -> str:
        m = re.search(
            rf"{tag}:\s*(.+?)(?=\n[A-Z_]+:|$)",
            narrative,
            re.DOTALL,
        )
        if not m:
            return ""
        body = m.group(1).strip()
        # HTML-escape the body since we control the wrapper
        return body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    p1 = _extract("PARRAFO_1_IMPACTO")
    p2 = _extract("PARRAFO_2_PATRON")
    p3 = _extract("PARRAFO_3_RECOMENDACION")
    if not (p1 or p2 or p3):
        return ""

    return (
        '<div class="exec-narrative">\n'
        "  <h3>Análisis ejecutivo</h3>\n"
        f"  <p><strong>Impacto al negocio.</strong> {p1}</p>\n"
        f"  <p><strong>Patrón de exposición.</strong> {p2}</p>\n"
        f"  <p><strong>Recomendación prioritaria.</strong> {p3}</p>\n"
        "</div>"
    )
