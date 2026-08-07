"""Fase 2 — Human-readable drift report ("qué cambió anoche").

The BaselineDiff is machine-shaped (new/gone/changed buckets). This report
translates it into business language a non-technical PyME owner can read in
30 seconds: a one-line verdict, an action per finding (not a raw CWE), and
"good news" for what got resolved. Content is Spanish (the client-facing
audience); code/docstrings stay English per repo convention.
"""

from __future__ import annotations

from kryon.reporting.drift_report import build_drift_report, build_drift_report_html
from kryon.state.baseline_diff import compute_diff


def _f(rule_id, host="web01", severity="HIGH", message=""):
    return {
        "rule_id": rule_id,
        "host": host,
        "severity": severity,
        "message": message or f"{rule_id} issue",
    }


# ---------------------------------------------------------------------------
# Verdict — the one line the owner reads first
# ---------------------------------------------------------------------------


def test_no_changes_says_all_quiet():
    diff = compute_diff([_f("A")], [_f("A")])  # identical → stable
    report = build_drift_report(diff, target="10.0.0.1", client="example")
    assert "igual" in report.lower()
    # Must not raise a false alarm.
    assert "atención inmediata" not in report.lower()


def test_only_resolved_is_good_news():
    diff = compute_diff([_f("A"), _f("B")], [_f("A")])  # B resolved
    report = build_drift_report(diff, target="10.0.0.1")
    assert "buenas noticias" in report.lower()
    assert "resuelto" in report.lower()


def test_new_finding_demands_attention():
    diff = compute_diff([_f("A")], [_f("A"), _f("B", severity="CRITICAL", message="Puerto de base de datos expuesto")])
    report = build_drift_report(diff, target="10.0.0.1")
    assert "atención inmediata" in report.lower()
    assert "Puerto de base de datos expuesto" in report


def test_singular_vs_plural_in_verdict():
    one = build_drift_report(compute_diff([], [_f("A")]), target="t")
    two = build_drift_report(compute_diff([], [_f("A"), _f("B")]), target="t")
    assert "1 novedad" in one
    assert "2 novedades" in two


# ---------------------------------------------------------------------------
# Business translation — action, not raw CWE
# ---------------------------------------------------------------------------


def test_severity_maps_to_action_language():
    diff_hi = compute_diff([], [_f("H", severity="CRITICAL")])
    diff_lo = compute_diff([], [_f("L", severity="LOW")])
    assert "atención inmediata" in build_drift_report(diff_hi, target="t").lower()
    assert "informativo" in build_drift_report(diff_lo, target="t").lower()


def test_findings_ordered_by_severity():
    curr = [
        _f("low1", severity="LOW", message="cosa menor"),
        _f("crit1", severity="CRITICAL", message="cosa grave"),
    ]
    report = build_drift_report(compute_diff([], curr), target="t")
    # The critical one must appear before the low one in the body.
    assert report.index("cosa grave") < report.index("cosa menor")


def test_host_is_shown_in_plain_language():
    diff = compute_diff([], [_f("A", host="10.0.0.9", message="Servicio sin cifrar")])
    report = build_drift_report(diff, target="t")
    assert "10.0.0.9" in report


def test_changed_finding_reports_worsening():
    prev = [_f("A", severity="MEDIUM", message="Servicio X")]
    curr = [_f("A", severity="CRITICAL", message="Servicio X")]
    diff = compute_diff(prev, curr)
    report = build_drift_report(diff, target="t")
    assert "empeoró" in report.lower()
    assert "Servicio X" in report


# ---------------------------------------------------------------------------
# Header / metadata
# ---------------------------------------------------------------------------


def test_header_includes_target_client_and_date():
    diff = compute_diff([], [_f("A")])
    report = build_drift_report(diff, target="app.example.com", client="Example", date="2026-07-07")
    assert "app.example.com" in report
    assert "Example" in report
    assert "2026-07-07" in report


def test_report_is_markdown_with_heading():
    diff = compute_diff([], [_f("A")])
    report = build_drift_report(diff, target="t")
    assert report.lstrip().startswith("#")


def test_stable_count_mentioned_when_present():
    # 2 stable + 1 new: the report should reassure that the rest is unchanged.
    prev = [_f("A"), _f("B")]
    curr = [_f("A"), _f("B"), _f("C", message="nuevo hallazgo")]
    report = build_drift_report(compute_diff(prev, curr), target="t")
    assert "2" in report  # the stable count surfaces somewhere


# ---------------------------------------------------------------------------
# HTML renderer (for the branded PDF) — same business logic, different skin
# ---------------------------------------------------------------------------


def test_html_is_a_full_document_with_body():
    # apply_branding injects after <body> / before </body>, so both must exist.
    html = build_drift_report_html(compute_diff([], [_f("A")]), target="t")
    assert "<html" in html.lower()
    assert "<body" in html.lower() and "</body>" in html.lower()


def test_html_contains_verdict_and_finding():
    diff = compute_diff([_f("A")], [_f("A"), _f("B", severity="CRITICAL", message="Base de datos expuesta")])
    html = build_drift_report_html(diff, target="10.0.0.1", client="Example")
    assert "atención" in html.lower()
    assert "Base de datos expuesta" in html
    assert "Example" in html


def test_html_escapes_finding_text():
    # Findings come from tool/LLM output — must not inject raw HTML/JS.
    evil = "<script>alert(1)</script>"
    diff = compute_diff([], [_f("X", message=evil)])
    html = build_drift_report_html(diff, target="t")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_reflects_alert_tone_on_critical():
    ok = build_drift_report_html(compute_diff([_f("A")], [_f("A")]), target="t")
    alert = build_drift_report_html(compute_diff([], [_f("B", severity="CRITICAL")]), target="t")
    # The two must render differently (tone class differs) — a critical is not
    # styled like an all-quiet report.
    assert ok != alert


def test_html_shows_resolved_section():
    diff = compute_diff([_f("A"), _f("B", message="Puerto abierto")], [_f("A")])
    html = build_drift_report_html(diff, target="t")
    assert "Puerto abierto" in html
    assert "resuelto" in html.lower()
