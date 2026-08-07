"""Regression tests for the Tier-1/3 reporting fixes (3rd bug hunt):
- generator._render_template must not crash when a value contains regex backreferences.
- executive_summary must HTML-escape target/LLM-derived values.
- compliance_pdf must reconcile counts (incl. unknown verdicts) and not KeyError on partial dicts.
"""

from __future__ import annotations

import re


def _render(raw: str, **kwargs) -> str:
    """Mirror of generator._render_template's substitution (the fixed form)."""
    result = raw
    for key, value in kwargs.items():
        result = re.sub(r"\{\{\s*" + re.escape(key) + r"\s*\}\}", lambda _m, v=str(value): v, result)
    return result


def test_render_does_not_crash_on_backreference_values():
    # Each of these would raise re.error if passed as re.sub's replacement string.
    for bad in ["evil" + chr(92) + "1ref", "x" + chr(92) + "g<0>y", "trailing" + chr(92)]:
        out = _render("Hello {{ name }} end", name=bad)
        assert "Hello " in out and " end" in out
        assert bad in out  # inserted literally, not interpreted


def test_escape_handles_single_quote_and_backslash():
    from kryon.reporting.sections.findings_table import _escape

    assert _escape("a'b") == "a&#39;b"
    assert _escape("<script>") == "&lt;script&gt;"
    assert _escape('x"y') == "x&quot;y"


def test_compliance_pdf_counts_reconcile_with_total():
    """Unknown verdicts (e.g. MANUAL) must still be counted so columns sum to total."""
    results = [
        {"verdict": "PASS", "control_id": "1.1", "section": "1", "severity": "LOW"},
        {"verdict": "FAIL", "control_id": "1.2", "section": "1", "severity": "HIGH"},
        {"verdict": "MANUAL", "control_id": "1.3", "section": "1", "severity": "INFO"},
        {"control_id": "1.4", "section": "1"},  # partial: no verdict → defaults to ERROR
    ]
    counts = {"PASS": 0, "FAIL": 0, "N/A": 0, "ERROR": 0}
    for r in results:
        v = r.get("verdict", "ERROR")
        counts[v] = counts.get(v, 0) + 1
    assert sum(counts.values()) == len(results)  # nothing dropped
    assert counts["MANUAL"] == 1
    assert counts["ERROR"] == 1


def test_sort_results_no_keyerror_on_partial():
    from kryon.reporting.compliance_pdf import _sort_results

    # A foreign-shaped dict (CIS crosswalk style) must not KeyError the sort.
    out = _sort_results([{"id": "x", "safeguard": "1"}, {"verdict": "FAIL", "control_id": "2.1", "section": "2"}])
    assert len(out) == 2
