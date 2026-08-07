"""Fase 2 — Human-readable drift report ("qué cambió anoche").

Turns a machine-shaped ``BaselineDiff`` into a Spanish, business-language
report a non-technical PyME owner can read in 30 seconds: a one-line verdict,
an action per finding (not a raw CWE), and "good news" for what got resolved.

This is the appliance's client-facing artifact — the operator forwards it to
the customer. The machine-readable ``delta.json`` feeds the SIEM; this feeds
the human. Pure (no I/O); the caller writes the markdown next to delta.json.
"""

from __future__ import annotations

from html import escape as _escape
from typing import Any

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Severity → what the owner should actually DO about it, in plain language.
# The point of the report is action, not a CWE number.
_ACTION_BY_SEV = {
    "CRITICAL": "Atención inmediata",
    "HIGH": "Atención inmediata",
    "MEDIUM": "A revisar",
    "LOW": "Informativo",
    "INFO": "Informativo",
}
_DEFAULT_ACTION = "A revisar"


def _plural(n: int, singular: str, plural: str) -> str:
    return singular if n == 1 else plural


def _sev(f: Any) -> str:
    return str((f or {}).get("severity", "")).upper()


def _title(f: Any) -> str:
    f = f or {}
    return str(f.get("message") or f.get("rule_id") or "hallazgo")


def _host(f: Any) -> str:
    return str((f or {}).get("host", "")).strip()


def _action(f: Any) -> str:
    return _ACTION_BY_SEV.get(_sev(f), _DEFAULT_ACTION)


def _by_severity(items: list[Any]) -> list[Any]:
    return sorted(items, key=lambda f: _SEV_RANK.get(_sev(f), 99))


def _finding_line(f: Any) -> str:
    host = _host(f)
    where = f" — {host}" if host else ""
    return f"- **{_action(f)}:** {_title(f)}{where}"


def _verdict(n_attention: int, n_gone: int) -> str:
    """The single line the owner reads first."""
    if n_attention == 0 and n_gone == 0:
        return "✓ Tu red está igual que en la última revisión. Nada nuevo que atender."
    if n_attention == 0 and n_gone > 0:
        resolved = f"{n_gone} {_plural(n_gone, 'problema resuelto', 'problemas resueltos')}"
        return f"✓ Buenas noticias: {resolved} desde la última revisión, y nada nuevo que atender."
    verb = _plural(n_attention, "requiere", "requieren")
    noun = _plural(n_attention, "novedad", "novedades")
    return f"⚠ {n_attention} {noun} {verb} tu atención."


def build_drift_report(diff: Any, *, target: str, client: str = "", date: str = "") -> str:
    """Render a ``BaselineDiff`` as a client-facing markdown report. Pure."""
    new = list(getattr(diff, "new", []) or [])
    gone = list(getattr(diff, "gone", []) or [])
    changed_raw = list(getattr(diff, "changed", []) or [])
    stable = list(getattr(diff, "stable", []) or [])
    # `changed` items are {"previous":.., "current":..}; report the current.
    changed = [c.get("current", c) if isinstance(c, dict) else c for c in changed_raw]

    n_new, n_changed, n_gone, n_stable = len(new), len(changed), len(gone), len(stable)
    attention = new + changed
    n_attention = len(attention)

    who = f" · {client}" if client else ""
    when = f" · {date}" if date else ""
    lines = [
        f"# Informe de novedades — {target}{who}{when}",
        "",
        _verdict(n_attention, n_gone),
        "",
        (
            f"**Resumen:** {n_new} {_plural(n_new, 'nueva', 'nuevas')} · "
            f"{n_changed} {_plural(n_changed, 'empeoró', 'empeoraron')} · "
            f"{n_gone} {_plural(n_gone, 'resuelto', 'resueltos')}"
        ),
        "",
    ]

    if attention:
        lines.append("## Requiere tu atención")
        lines.append("")
        for f in _by_severity(new):
            lines.append(_finding_line(f))
        for c in _by_severity(changed):
            lines.append(_finding_line(c) + " _(empeoró desde la última revisión)_")
        lines.append("")

    if gone:
        lines.append("## Buenas noticias — resuelto")
        lines.append("")
        for f in _by_severity(gone):
            host = _host(f)
            lines.append(f"- {_title(f)}" + (f" — {host}" if host else ""))
        lines.append("")

    if n_stable:
        lines.append(
            f"_El resto de tu red ({n_stable} {_plural(n_stable, 'punto vigilado', 'puntos vigilados')}) "
            "sigue igual que en la última revisión._"
        )

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# HTML renderer — same business logic (verdict/action/order), branded skin for
# the PDF. Findings come from tool/LLM output, so every dynamic value is
# HTML-escaped before it reaches the document.
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#c2410c",
    "MEDIUM": "#b45309",
    "LOW": "#4b5563",
    "INFO": "#4b5563",
}

_REPORT_CSS = """
* { box-sizing: border-box; }
body { font-family: 'Inter','Segoe UI',sans-serif; color:#1f2937; font-size:12pt; line-height:1.5; }
.drift { max-width: 720px; margin: 0 auto; }
.verdict { padding:16px 20px; border-radius:8px; font-size:15pt; font-weight:600; margin:8px 0 18px; }
.verdict--ok { background:#f0fdf4; color:#15803d; border-left:5px solid #15803d; }
.verdict--warn { background:#fffbeb; color:#b45309; border-left:5px solid #b45309; }
.verdict--alert { background:#fef2f2; color:#b91c1c; border-left:5px solid #b91c1c; }
.summary { color:#6b7280; font-size:11pt; margin-bottom:22px; }
.summary strong { color:#1f2937; }
h2 { font-size:13pt; border-bottom:1px solid #e5e7eb; padding-bottom:6px; margin-top:26px; }
.card { display:flex; gap:12px; align-items:baseline; padding:10px 0; border-bottom:1px solid #f3f4f6; }
.pill { color:#fff; font-size:9pt; font-weight:600; padding:3px 10px; border-radius:100px; white-space:nowrap; }
.desc { font-size:11.5pt; }
.host { color:#6b7280; font-size:10pt; }
.tag { background:#fef3c7; color:#92400e; font-size:8.5pt; padding:1px 6px; border-radius:4px; margin-left:6px; }
.resolved { color:#15803d; padding:9px 0; border-bottom:1px solid #f3f4f6; }
.reassure { color:#6b7280; font-size:10.5pt; font-style:italic; margin-top:22px; }
"""


def _tone(attention: list[Any]) -> str:
    """Verdict banner tone: alert if any critical/high needs attention, warn
    for lesser findings, ok when there's nothing to act on."""
    if not attention:
        return "ok"
    worst = min((_SEV_RANK.get(_sev(f), 99) for f in attention), default=99)
    return "alert" if worst <= _SEV_RANK["HIGH"] else "warn"


def _host_html(f: Any) -> str:
    host = _host(f)
    return f' <span class="host">— {_escape(host)}</span>' if host else ""


def _finding_card_html(f: Any, *, worsened: bool = False) -> str:
    color = _SEV_COLOR.get(_sev(f), "#4b5563")
    tag = '<span class="tag">empeoró</span>' if worsened else ""
    return (
        '<div class="card">'
        f'<span class="pill" style="background:{color}">{_escape(_action(f))}</span>'
        f'<span class="desc">{_escape(_title(f))}{tag}{_host_html(f)}</span>'
        "</div>"
    )


def build_drift_report_html(diff: Any, *, target: str, client: str = "", date: str = "") -> str:
    """Render a ``BaselineDiff`` as a branded HTML document for PDF export.
    Full ``<html>/<body>`` so ``apply_branding`` can inject header/footer. Pure."""
    new = list(getattr(diff, "new", []) or [])
    gone = list(getattr(diff, "gone", []) or [])
    changed_raw = list(getattr(diff, "changed", []) or [])
    stable = list(getattr(diff, "stable", []) or [])
    changed = [c.get("current", c) if isinstance(c, dict) else c for c in changed_raw]

    n_new, n_changed, n_gone, n_stable = len(new), len(changed), len(gone), len(stable)
    attention = new + changed

    meta = " · ".join(x for x in (_escape(client), _escape(date)) if x)
    meta_html = f" · {meta}" if meta else ""
    summary = (
        f"{n_new} {_plural(n_new, 'nueva', 'nuevas')} · "
        f"{n_changed} {_plural(n_changed, 'empeoró', 'empeoraron')} · "
        f"{n_gone} {_plural(n_gone, 'resuelto', 'resueltos')}"
    )

    parts = [
        '<div class="drift">',
        f'<div class="verdict verdict--{_tone(attention)}">{_escape(_verdict(len(attention), n_gone))}</div>',
        f'<p class="summary"><strong>{_escape(target)}</strong>{meta_html}<br>{summary}</p>',
    ]
    if attention:
        parts.append("<h2>Requiere tu atención</h2>")
        parts.extend(_finding_card_html(f) for f in _by_severity(new))
        parts.extend(_finding_card_html(c, worsened=True) for c in _by_severity(changed))
    if gone:
        parts.append("<h2>Buenas noticias — resuelto</h2>")
        parts.extend(f'<div class="resolved">✓ {_escape(_title(f))}{_host_html(f)}</div>' for f in _by_severity(gone))
    if n_stable:
        parts.append(
            f'<p class="reassure">El resto de tu red ({n_stable} '
            f"{_plural(n_stable, 'punto vigilado', 'puntos vigilados')}) sigue igual que en la última revisión.</p>"
        )
    parts.append("</div>")
    body = "\n".join(parts)

    return (
        "<!DOCTYPE html>\n"
        '<html lang="es"><head><meta charset="utf-8">'
        f"<title>Informe de novedades — {_escape(target)}</title>"
        f"<style>{_REPORT_CSS}</style></head>"
        f"<body>{body}</body></html>"
    )
