"""Contract for the Ghost mood bus — the always-on eye that reacts to findings."""

from __future__ import annotations

import pytest

from kryon.repl.ui import ghost_state as gs


@pytest.fixture(autouse=True)
def _reset_ghost():
    gs.reset()
    yield
    gs.reset()


def test_idle_eye_is_a_diamond():
    glyph, color = gs.eye_style()
    assert glyph == "◆"
    assert color.startswith("#")
    assert gs.findings_count() == 0
    assert gs.peak_severity() is None


def test_react_finding_bumps_tally_and_peak():
    gs.react_finding("MEDIUM")
    gs.react_finding("HIGH")
    assert gs.findings_count() == 2
    assert gs.peak_severity() == "HIGH"


def test_peak_never_regresses_to_lower_severity():
    gs.react_finding("CRITICAL")
    gs.react_finding("LOW")
    assert gs.peak_severity() == "CRITICAL"


def test_fresh_critical_shows_alarmed_glyph():
    gs.react_finding("CRITICAL")
    glyph, _ = gs.eye_style()
    # CRITICAL/HIGH throb uses the seamed ◈ while fresh.
    assert glyph == "◈"


def test_nuclei_output_detected_at_highest_severity():
    out = "[info] foo\n[high] SQLi on /login\n[critical] RCE via upload\n"
    gs.note_tool_output("nuclei", out)
    assert gs.peak_severity() == "CRITICAL"
    assert gs.findings_count() == 3  # three tagged lines


def test_sqlmap_vulnerable_reacts_high():
    gs.note_tool_output("sqlmap", "parameter 'id' is vulnerable")
    assert gs.peak_severity() == "HIGH"


def test_no_signal_no_reaction():
    gs.note_tool_output("nmap", "22/tcp open ssh\n80/tcp open http")
    assert gs.findings_count() == 0
    assert gs.peak_severity() is None


def test_unknown_severity_falls_back_to_info():
    gs.react_finding("BOGUS")
    assert gs.peak_severity() == "INFO"


def test_detect_findings_returns_severity_and_detail():
    out = "[high] SQL injection in id param\n[low] verbose error page\n"
    found = gs.detect_findings("nuclei", out)
    assert [s for s, _ in found] == ["HIGH", "LOW"]
    assert "SQL injection" in found[0][1]


def test_note_tool_output_returns_detected_findings():
    found = gs.note_tool_output("nuclei", "[critical] RCE via upload")
    assert found == [("CRITICAL", "[critical] RCE via upload")]


def test_fresh_reaction_open_then_none_after_window():
    assert gs.fresh_reaction() is None
    gs.react_finding("HIGH")
    assert gs.fresh_reaction() == "HIGH"
    # Force the window closed and confirm it relaxes.
    with gs._lock:
        gs._state["fresh_until"] = 0.0
    assert gs.fresh_reaction() is None


def test_reset_clears_everything():
    gs.react_finding("CRITICAL")
    gs.reset()
    assert gs.findings_count() == 0
    assert gs.peak_severity() is None
    glyph, _ = gs.eye_style()
    assert glyph == "◆"
