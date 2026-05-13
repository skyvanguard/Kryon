"""F103 — TDD contract for the Open Redirect detector."""

from __future__ import annotations

import pytest

from kryon.tools.api.open_redirect import (
    ALL_OR_RULES,
    RedirectAnalysis,
    RedirectFinding,
    RedirectObservation,
    _classify_observation,
    _is_redirect_param,
    analyze_observations,
)


def _obs(
    url: str = "/login",
    param: str = "next",
    probe: str = "",
    status: int = 0,
    location: str = "",
    body: str = "",
) -> RedirectObservation:
    return RedirectObservation(
        url=url,
        parameter_name=param,
        probe_value=probe,
        response_status=status,
        response_location_header=location,
        response_body_snippet=body,
    )


# =====================================================================
# Parameter heuristics
# =====================================================================


@pytest.mark.parametrize(
    "name,expected",
    [
        ("next", True),
        ("return", True),
        ("returnUrl", True),
        ("return_url", True),
        ("redirect_uri", True),
        ("redirect-uri", True),
        ("REDIRECT_URI", True),
        ("destination", True),
        ("dest", True),
        ("checkout_url", True),
        ("user_id", False),
        ("token", False),
        ("password", False),
    ],
)
def test_is_redirect_param(name, expected):
    assert _is_redirect_param(name) is expected


def test_or_001_param_name_heuristic_low():
    findings = _classify_observation(_obs(param="next"))
    assert any(f.rule_id == "OR-001" and f.severity == "LOW" for f in findings)


def test_or_001_silent_on_non_redirect_param():
    findings = _classify_observation(_obs(param="username"))
    assert not any(f.rule_id == "OR-001" for f in findings)


# =====================================================================
# Behavioral: confirmed redirect via Location header
# =====================================================================


def test_or_002_confirmed_absolute_redirect_critical():
    findings = _classify_observation(
        _obs(
            probe="https://evil.example/x",
            status=302,
            location="https://evil.example/x",
        )
    )
    assert any(f.rule_id == "OR-002" and f.severity == "CRITICAL" for f in findings)


def test_or_002_silent_when_location_is_same_origin():
    findings = _classify_observation(
        _obs(
            probe="https://evil.example/x",
            status=302,
            location="/safe/path",
        )
    )
    assert not any(f.rule_id == "OR-002" for f in findings)


def test_or_003_confirmed_scheme_relative_redirect_high():
    findings = _classify_observation(
        _obs(
            probe="//evil.example/x",
            status=302,
            location="//evil.example/x",
        )
    )
    assert any(f.rule_id == "OR-003" and f.severity == "HIGH" for f in findings)


def test_or_004_meta_refresh_redirect():
    body = '<meta http-equiv="refresh" content="0; url=https://evil.example/x">'
    findings = _classify_observation(
        _obs(probe="https://evil.example/x", body=body)
    )
    assert any(f.rule_id == "OR-004" for f in findings)


def test_or_004_js_location_redirect():
    body = 'window.location = "https://evil.example/x";'
    findings = _classify_observation(
        _obs(probe="https://evil.example/x", body=body)
    )
    assert any(f.rule_id == "OR-004" for f in findings)


def test_or_005_oauth_redirect_uri_critical():
    findings = _classify_observation(
        _obs(
            param="redirect_uri",
            probe="https://evil.example/cb",
            status=302,
            location="https://evil.example/cb",
        )
    )
    ids = {f.rule_id for f in findings}
    assert "OR-002" in ids
    assert "OR-005" in ids
    assert any(f.rule_id == "OR-005" and f.severity == "CRITICAL" for f in findings)


def test_or_006_whitelist_bypass_via_at_sign():
    findings = _classify_observation(
        _obs(
            probe="https://legit.example@evil.example/",
            status=302,
            location="https://evil.example/",
        )
    )
    assert any(f.rule_id == "OR-006" and f.severity == "CRITICAL" for f in findings)


# =====================================================================
# Negative paths
# =====================================================================


def test_no_probe_no_behavioral_findings():
    """If operator didn't probe, only the heuristic OR-001 should fire."""
    findings = _classify_observation(_obs(param="next"))
    behavioral_ids = {"OR-002", "OR-003", "OR-004", "OR-005", "OR-006"}
    assert not any(f.rule_id in behavioral_ids for f in findings)


def test_safe_redirect_to_internal_silent():
    findings = _classify_observation(
        _obs(
            param="next",
            probe="/dashboard",
            status=302,
            location="/dashboard",
        )
    )
    # OR-001 fires (LOW heuristic) but no behavioral confirmation
    behavioral_ids = {"OR-002", "OR-003", "OR-004", "OR-005", "OR-006"}
    assert not any(f.rule_id in behavioral_ids for f in findings)


# =====================================================================
# Aggregation
# =====================================================================


def test_analyze_observations_sorts_by_severity():
    obs_list = [
        _obs(param="next"),  # OR-001 LOW
        _obs(
            param="redirect",
            probe="https://evil.example/",
            status=302,
            location="https://evil.example/",
        ),  # OR-002 CRITICAL
    ]
    analysis = analyze_observations(obs_list)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in analysis.findings]
    assert ranks == sorted(ranks)


def test_analyze_observations_empty():
    analysis = analyze_observations([])
    assert analysis.total_observations == 0
    assert analysis.findings == ()


# =====================================================================
# Pin + frozen
# =====================================================================


def test_all_rules_pinned():
    expected = {f"OR-{n:03d}" for n in range(1, 7)}
    assert expected == ALL_OR_RULES


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    obs = RedirectObservation(url="/x", parameter_name="next")
    with pytest.raises(FrozenInstanceError):
        obs.url = "/y"  # type: ignore[misc]
