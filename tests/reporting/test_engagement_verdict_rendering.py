"""F122 — Engagement verdict banner in demo_report.

The orchestrator computes a SATISFIED/PARTIAL/NOT_MET verdict against
the declared --objective and we surface it in the demo PDF so the
client/auditor sees it alongside the findings, not only in console.
"""

from __future__ import annotations

from kryon.reporting.demo_report import _render_engagement_verdict, render_html


def test_render_verdict_none_returns_empty():
    assert _render_engagement_verdict(None) == ""
    assert _render_engagement_verdict({}) == ""


def test_render_verdict_satisfied_uses_green_palette():
    html = _render_engagement_verdict(
        {
            "verdict": "satisfied",
            "reasoning": "3 distinct services enumerated",
            "goal_kind": "recon",
            "goal_raw": "enumerate attack surface",
            "evidence_count": 3,
        }
    )
    assert "SATISFIED" in html
    assert "#22543d" in html or "#c6f6d5" in html  # green tones
    assert "3 distinct services enumerated" in html
    assert "Objetivo declarado" in html


def test_render_verdict_not_met_uses_red_palette():
    html = _render_engagement_verdict(
        {
            "verdict": "not_met",
            "reasoning": "no service-bearing findings yet",
            "goal_kind": "recon",
            "goal_raw": "enumerate",
            "evidence_count": 0,
        }
    )
    assert "NOT_MET" in html
    assert "#822727" in html or "#fed7d7" in html  # red tones


def test_render_verdict_partial_uses_yellow_palette():
    html = _render_engagement_verdict(
        {
            "verdict": "partial",
            "reasoning": "1/5 controls evaluated",
            "goal_kind": "compliance",
            "goal_raw": "audit PCI-DSS",
            "evidence_count": 1,
        }
    )
    assert "PARTIAL" in html
    assert "#744210" in html or "#fefcbf" in html  # yellow tones


def test_render_verdict_escapes_html_in_reasoning():
    html = _render_engagement_verdict(
        {
            "verdict": "partial",
            "reasoning": "<script>alert('xss')</script>",
            "goal_kind": "custom",
            "goal_raw": "<img src=x>",
            "evidence_count": 0,
        }
    )
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x>" not in html
    assert "&lt;img" in html


def test_render_html_includes_verdict_banner_when_provided():
    html = render_html(
        findings=[],
        context={
            "client_name": "example",
            "engagement_id": "demo-1",
            "target_scope": "www.example.com",
            "engagement_verdict": {
                "verdict": "satisfied",
                "reasoning": "goal met",
                "goal_kind": "recon",
                "goal_raw": "enumerate attack surface",
                "evidence_count": 2,
            },
        },
    )
    assert "Veredicto del engagement" in html
    assert "SATISFIED" in html
    assert "goal met" in html


def test_render_html_omits_verdict_when_absent():
    html = render_html(
        findings=[],
        context={
            "client_name": "example",
            "engagement_id": "demo-2",
            "target_scope": "www.example.com",
        },
    )
    # Banner heading should not appear when no verdict was supplied.
    assert "Veredicto del engagement" not in html
