"""Tests for business risk scoring."""

import pytest
from kryon.evaluation.business_risk import (
    BusinessRiskScorer, CRITICALITY_MULTIPLIERS, EXPOSURE_MULTIPLIERS, SEVERITY_SCORES,
)


@pytest.fixture
def scorer():
    return BusinessRiskScorer()


def test_contextual_risk_critical_public(scorer):
    finding = {"severity": "critical", "cvss_score": 9.8}
    score = scorer.calculate_contextual_risk(finding, "critical", "public")
    assert score > 30.0


def test_contextual_risk_low_isolated(scorer):
    finding = {"severity": "low", "cvss_score": 2.0}
    score = scorer.calculate_contextual_risk(finding, "low", "isolated")
    assert score < 1.0


def test_contextual_risk_default(scorer):
    finding = {"severity": "medium"}
    score = scorer.calculate_contextual_risk(finding)
    assert 2.0 <= score <= 5.0


def test_contextual_risk_bounds(scorer):
    finding = {"severity": "critical", "cvss_score": 10.0}
    score = scorer.calculate_contextual_risk(finding, "critical", "public")
    assert score <= 100.0


def test_categorize_data_breach(scorer):
    findings = [{"severity": "critical", "title": "SQL Injection data leak", "description": "Credential dump"}]
    impact = scorer.categorize_business_impact(findings)
    assert impact["data_breach"] > 0


def test_categorize_service_disruption(scorer):
    findings = [{"severity": "high", "title": "DoS vulnerability", "description": "Denial of service crash"}]
    impact = scorer.categorize_business_impact(findings)
    assert impact["service_disruption"] > 0


def test_categorize_empty(scorer):
    impact = scorer.categorize_business_impact([])
    for cat in ["data_breach", "service_disruption", "regulatory", "reputational"]:
        assert impact[cat] == 0


def test_categorize_multiple_impacts(scorer):
    findings = [
        {"severity": "critical", "title": "Data leak", "description": "credential dump"},
        {"severity": "high", "title": "DoS attack", "description": "service outage crash"},
        {"severity": "medium", "title": "GDPR violation", "description": "compliance audit failure"},
    ]
    impact = scorer.categorize_business_impact(findings)
    assert impact["data_breach"] > 0
    assert impact["service_disruption"] > 0
    assert impact["regulatory"] > 0


def test_severity_distribution(scorer):
    findings = [{"severity": "critical"}, {"severity": "critical"}, {"severity": "high"}, {"severity": "medium"}]
    dist = scorer._severity_dist(findings)
    assert dist["critical"] == 2
    assert dist["high"] == 1
    assert dist["medium"] == 1


def test_severity_scores_mapping():
    assert SEVERITY_SCORES["critical"] == 10.0
    assert SEVERITY_SCORES["info"] == 0.0


def test_multiplier_values():
    assert CRITICALITY_MULTIPLIERS["critical"] == 2.0
    assert EXPOSURE_MULTIPLIERS["public"] == 1.8
    assert EXPOSURE_MULTIPLIERS["isolated"] == 0.6
