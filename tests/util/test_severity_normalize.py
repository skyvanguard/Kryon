"""normalize_severity maps arbitrary severity values to canonical labels instead of
dropping the finding. Regression: `if sev not in SEVERITY_RANK: continue` silently
lost a real CVE emitted as "9.8" or "informational"."""

from __future__ import annotations

import pytest

from kryon.util.severity import SEVERITY_RANK, normalize_severity


@pytest.mark.parametrize("canon", list(SEVERITY_RANK))
def test_canonical_passthrough(canon):
    assert normalize_severity(canon) == canon
    assert normalize_severity(canon.lower()) == canon


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ERROR", "CRITICAL"),
        ("crit", "CRITICAL"),
        ("warning", "MEDIUM"),
        ("moderate", "MEDIUM"),
        ("informational", "INFO"),
        ("none", "INFO"),
        ("minor", "LOW"),
        ("major", "HIGH"),
    ],
)
def test_aliases(raw, expected):
    assert normalize_severity(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("9.8", "CRITICAL"),
        ("7.0", "HIGH"),
        ("5.5", "MEDIUM"),
        ("2.1", "LOW"),
        ("0", "INFO"),
        ("Critical (CVSS 9.8)", "CRITICAL"),
        ("HIGH severity", "HIGH"),
    ],
)
def test_numeric_and_embedded(raw, expected):
    assert normalize_severity(raw) == expected


def test_unknown_defaults_to_medium_not_dropped():
    assert normalize_severity("banana") == "MEDIUM"
    assert normalize_severity("") == "MEDIUM"
    assert normalize_severity(None) == "MEDIUM"


def test_numeric_type_input():
    assert normalize_severity(9.8) == "CRITICAL"
    assert normalize_severity(3) == "LOW"
