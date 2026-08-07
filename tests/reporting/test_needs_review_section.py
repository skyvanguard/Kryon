"""F210 Fase 5 — the demo report separates confirmed findings (ground
truth) from inferred/heuristic ones in a dedicated "requiere verificación"
section, instead of mixing them in one flat table."""

from __future__ import annotations

from kryon.reporting.demo_report import _render_review_section, render_html


def _f(rule_id, *, needs_verification=False, level="confirmed", sev="HIGH", host="10.0.0.11", msg="m"):
    return {
        "cwe": "CWE-0",
        "severity": sev,
        "host": host,
        "rule_id": rule_id,
        "message": msg,
        "needs_verification": needs_verification,
        "verification_level": level,
    }


# ---------------------------------------------------------------------------
# _render_review_section
# ---------------------------------------------------------------------------


def test_review_section_empty_when_no_review_items():
    assert _render_review_section([]) == ""


def test_review_section_lists_items_with_level_and_disclaimer():
    html = _render_review_section([_f("TOMCAT-1.1", needs_verification=True, level="heuristic")])
    assert "Requiere verificación (1)" in html
    assert "TOMCAT-1.1" in html
    assert "heuristic" in html
    # Disclaimer: makes clear these are NOT ground truth.
    assert "No son ground truth" in html
    assert "inferidas" in html


# ---------------------------------------------------------------------------
# render_html integration
# ---------------------------------------------------------------------------


def test_confirmed_findings_go_to_main_index_not_review():
    html = render_html(
        findings=[_f("PVE-2.3", needs_verification=False)],
        context={"engagement_id": "d1"},
    )
    assert "Índice de hallazgos" in html
    assert "PVE-2.3" in html
    # No review section when nothing is flagged.
    assert "Requiere verificación" not in html


def test_needs_review_findings_render_separately():
    html = render_html(
        findings=[
            _f("PVE-2.3", needs_verification=False),
            _f("cve-2024-6387", needs_verification=True, level="inferred", sev="CRITICAL"),
        ],
        context={"engagement_id": "d2"},
    )
    # Confirmed index present with the confirmed rule.
    assert "PVE-2.3" in html
    # Review section present with the inferred rule + its level.
    assert "Requiere verificación (1)" in html
    assert "cve-2024-6387" in html
    assert "inferred" in html


def test_all_findings_inferred_shows_empty_confirmed_index():
    html = render_html(
        findings=[_f("cve-2024-6387", needs_verification=True, level="inferred")],
        context={"engagement_id": "d3"},
    )
    assert "Sin hallazgos confirmados" in html
    assert "Requiere verificación (1)" in html


def test_empty_findings_has_no_review_section():
    html = render_html(findings=[], context={"engagement_id": "d4"})
    assert "Requiere verificación" not in html
