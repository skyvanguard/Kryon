"""Regression: the pentest verdict must sort by severity BEFORE truncating.

`sorted(findings[:25], ...)` sliced in scan order first, so a CRITICAL at
index 26+ was dropped before its severity was ever weighed — and since this
verdict closes the turn, nothing narrated the lost finding.
"""

from __future__ import annotations

from kryon.skills.unified_agent import _format_pentest_verdict


def test_critical_beyond_index_25_is_not_dropped() -> None:
    findings = [{"severity": "LOW", "cwe_id": "CWE-1", "title": f"low-{i}"} for i in range(25)]
    findings.append({"severity": "CRITICAL", "cwe_id": "CWE-89", "title": "critical-sqli"})
    payload = {
        "target": "http://t",
        "summary": {"findings_total": 26, "probes_executed": 5},
        "findings": findings,
    }
    out = _format_pentest_verdict(payload)
    assert "critical-sqli" in out
    assert "[CRITICAL]" in out
    # 26 findings, 25 shown → one overflow line, and the CRITICAL is not it.
    assert "+1 más" in out
