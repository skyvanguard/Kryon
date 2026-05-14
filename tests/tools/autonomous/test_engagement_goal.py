"""F118 — Goal-directed reasoning.

EngagementGoal lets the operator declare *what success looks like* up
front so the orchestrator can stop early on success and emit a final
verdict on failure (instead of just running every phase blindly).
"""

from __future__ import annotations

from dataclasses import dataclass

from kryon.tools.autonomous.engagement_goal import (
    EngagementGoal,
    EngagementVerdict,
    GoalEvaluator,
    GoalKind,
    GoalProgress,
    parse_objective,
)


@dataclass
class _F:
    """Minimal finding shape compatible with engage.Finding +
    enterprise findings."""

    rule_id: str = ""
    severity: str = "INFO"
    message: str = ""
    title: str = ""
    description: str = ""


# ---------------------------------------------------------------------------
# parse_objective — natural language → EngagementGoal
# ---------------------------------------------------------------------------


def test_parse_compliance_pci_dss():
    goal = parse_objective("evaluar compliance PCI-DSS contra cashbox.britimp.com.py")
    assert goal.kind is GoalKind.COMPLIANCE
    assert "PCI-DSS" in goal.params.get("framework", "")


def test_parse_compliance_english():
    goal = parse_objective("audit PCI-DSS compliance for 1.2.3.4")
    assert goal.kind is GoalKind.COMPLIANCE
    assert goal.params.get("framework") == "PCI-DSS"


def test_parse_vuln_search_rce():
    goal = parse_objective("find RCE on the admin panel")
    assert goal.kind is GoalKind.VULN_SEARCH
    assert "rce" in [v.lower() for v in goal.params.get("vuln_types", [])]


def test_parse_vuln_search_multiple():
    goal = parse_objective("look for SQL injection or XSS on the login form")
    assert goal.kind is GoalKind.VULN_SEARCH
    vuln_types = [v.lower() for v in goal.params.get("vuln_types", [])]
    assert "sqli" in vuln_types or "sql injection" in vuln_types
    assert "xss" in vuln_types


def test_parse_recon_only():
    goal = parse_objective("enumerate the attack surface of 10.0.0.0/24")
    assert goal.kind is GoalKind.RECON
    assert goal.params.get("min_services", 0) >= 1


def test_parse_custom_falls_back_when_unknown():
    goal = parse_objective("do something interesting with this target")
    assert goal.kind is GoalKind.CUSTOM


def test_parse_objective_preserves_raw_text():
    raw = "find RCE on /upload"
    goal = parse_objective(raw)
    assert goal.raw == raw


# ---------------------------------------------------------------------------
# GoalEvaluator — COMPLIANCE
# ---------------------------------------------------------------------------


def test_compliance_satisfied_when_framework_findings_present():
    goal = EngagementGoal(
        kind=GoalKind.COMPLIANCE,
        raw="audit PCI-DSS",
        params={"framework": "PCI-DSS", "min_controls_evaluated": 2},
    )
    findings = [
        _F(rule_id="PCI-2.2.7", severity="MEDIUM"),
        _F(rule_id="PCI-6.3.4", severity="HIGH"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True
    assert progress.verdict is EngagementVerdict.SATISFIED


def test_compliance_partial_when_below_threshold():
    goal = EngagementGoal(
        kind=GoalKind.COMPLIANCE,
        raw="audit PCI-DSS",
        params={"framework": "PCI-DSS", "min_controls_evaluated": 5},
    )
    findings = [_F(rule_id="PCI-2.2.7", severity="MEDIUM")]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is False
    assert progress.verdict is EngagementVerdict.PARTIAL
    assert progress.controls_evaluated == 1


def test_compliance_not_met_with_no_framework_findings():
    goal = EngagementGoal(
        kind=GoalKind.COMPLIANCE,
        raw="audit PCI-DSS",
        params={"framework": "PCI-DSS", "min_controls_evaluated": 1},
    )
    progress = GoalEvaluator().evaluate(goal, [])
    assert progress.satisfied is False
    assert progress.verdict is EngagementVerdict.NOT_MET


# ---------------------------------------------------------------------------
# GoalEvaluator — VULN_SEARCH
# ---------------------------------------------------------------------------


def test_vuln_search_satisfied_with_matching_critical_finding():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find RCE",
        params={"vuln_types": ["rce"]},
    )
    findings = [_F(rule_id="WEB-001", severity="CRITICAL", message="RCE on /upload")]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True
    assert progress.verdict is EngagementVerdict.SATISFIED
    assert len(progress.evidence) == 1


def test_vuln_search_not_satisfied_when_severity_too_low():
    # vuln search defaults to requiring HIGH or CRITICAL
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find SQL injection",
        params={"vuln_types": ["sqli"]},
    )
    findings = [_F(rule_id="WEB-009", severity="LOW", message="possible sql injection in test param")]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is False
    assert progress.verdict is EngagementVerdict.PARTIAL  # found something but below severity gate


def test_vuln_search_matches_multiple_types():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find SQLi or XSS",
        params={"vuln_types": ["sqli", "xss"]},
    )
    findings = [_F(rule_id="WEB-002", severity="HIGH", message="reflected XSS on /search")]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True


def test_vuln_search_not_met_with_no_relevant_findings():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find RCE",
        params={"vuln_types": ["rce"]},
    )
    findings = [_F(rule_id="INFO-001", severity="INFO", message="banner disclosure")]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.verdict is EngagementVerdict.NOT_MET


# ---------------------------------------------------------------------------
# GoalEvaluator — RECON
# ---------------------------------------------------------------------------


def test_recon_satisfied_when_min_services_reached():
    goal = EngagementGoal(
        kind=GoalKind.RECON,
        raw="enumerate attack surface",
        params={"min_services": 3},
    )
    findings = [
        _F(rule_id="NMAP-001", message="open port 22/tcp ssh"),
        _F(rule_id="NMAP-002", message="open port 80/tcp http"),
        _F(rule_id="NMAP-003", message="open port 443/tcp https"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True
    assert progress.services_enumerated >= 3


def test_recon_partial_when_below_threshold():
    goal = EngagementGoal(
        kind=GoalKind.RECON,
        raw="enumerate attack surface",
        params={"min_services": 5},
    )
    findings = [_F(rule_id="NMAP-001", message="open port 22/tcp")]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is False
    assert progress.verdict is EngagementVerdict.PARTIAL


# ---------------------------------------------------------------------------
# GoalEvaluator — CUSTOM
# ---------------------------------------------------------------------------


def test_custom_satisfied_when_critical_finding_present():
    # CUSTOM default rule: any critical/high finding satisfies a custom goal
    goal = EngagementGoal(
        kind=GoalKind.CUSTOM,
        raw="do something interesting",
        params={},
    )
    findings = [_F(rule_id="X-001", severity="CRITICAL")]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True


def test_custom_not_met_with_no_severe_findings():
    goal = EngagementGoal(
        kind=GoalKind.CUSTOM,
        raw="anything",
        params={},
    )
    progress = GoalEvaluator().evaluate(goal, [_F(severity="INFO")])
    assert progress.satisfied is False


# ---------------------------------------------------------------------------
# Progress shape + early-termination signal
# ---------------------------------------------------------------------------


def test_progress_should_terminate_early_when_satisfied():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find RCE",
        params={"vuln_types": ["rce"]},
    )
    findings = [_F(rule_id="WEB-001", severity="CRITICAL", message="RCE")]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.should_terminate_early() is True


def test_progress_does_not_terminate_when_partial():
    goal = EngagementGoal(
        kind=GoalKind.COMPLIANCE,
        raw="audit PCI-DSS",
        params={"framework": "PCI-DSS", "min_controls_evaluated": 5},
    )
    progress = GoalEvaluator().evaluate(goal, [_F(rule_id="PCI-2.2.7")])
    assert progress.should_terminate_early() is False


def test_progress_summary_renders_human_readable():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find RCE",
        params={"vuln_types": ["rce"]},
    )
    findings = [_F(rule_id="WEB-001", severity="CRITICAL", message="RCE")]
    progress = GoalEvaluator().evaluate(goal, findings)
    summary = progress.summary()
    assert "satisfied" in summary.lower()
    assert "RCE" in summary or "rce" in summary.lower()


def test_evidence_contains_matched_findings():
    goal = EngagementGoal(
        kind=GoalKind.VULN_SEARCH,
        raw="find SQLi",
        params={"vuln_types": ["sqli"]},
    )
    findings = [
        _F(rule_id="WEB-001", severity="INFO", message="banner"),
        _F(rule_id="WEB-002", severity="HIGH", message="SQL injection in /login"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert len(progress.evidence) == 1
    assert progress.evidence[0].rule_id == "WEB-002"


# ---------------------------------------------------------------------------
# F125 — RECON with technology + endpoint sub-criteria
# ---------------------------------------------------------------------------


def test_recon_with_min_technologies_requires_tech_count():
    goal = EngagementGoal(
        kind=GoalKind.RECON,
        raw="enumerate tech stack",
        params={"min_services": 1, "min_technologies": 3},
    )
    findings = [
        _F(rule_id="NMAP-001", message="open port 80/tcp"),
        _F(rule_id="WW-001", message="Apache 2.4.50 with Bootstrap"),
        _F(rule_id="WW-002", message="cPanel detected"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True
    assert progress.technologies_detected >= 3


def test_recon_min_technologies_unmet_is_partial():
    goal = EngagementGoal(
        kind=GoalKind.RECON,
        raw="enumerate tech stack",
        params={"min_services": 1, "min_technologies": 5},
    )
    findings = [
        _F(rule_id="NMAP-001", message="open port 22"),
        _F(rule_id="WW-001", message="Apache"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is False
    assert progress.verdict is EngagementVerdict.PARTIAL


def test_recon_with_min_endpoints_counts_paths():
    goal = EngagementGoal(
        kind=GoalKind.RECON,
        raw="discover endpoints",
        params={"min_services": 1, "min_endpoints": 3},
    )
    findings = [
        _F(rule_id="NMAP", message="open port 443"),
        _F(rule_id="FFUF-1", message="/admin returned 200"),
        _F(rule_id="FFUF-2", message="/api/v1 returned 401"),
        _F(rule_id="FFUF-3", message="/webmail redirects to :2096"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True
    assert progress.endpoints_enumerated >= 3


def test_recon_combined_criteria_must_all_pass():
    goal = EngagementGoal(
        kind=GoalKind.RECON,
        raw="complete recon",
        params={"min_services": 3, "min_technologies": 2, "min_endpoints": 2},
    )
    findings = [
        _F(rule_id="NMAP", message="open port 22 ssh"),
        _F(rule_id="NMAP", message="open port 80 http"),
        _F(rule_id="NMAP", message="open port 443 https"),
        _F(rule_id="WW", message="Apache server with cPanel"),
        _F(rule_id="FFUF", message="/admin and /api/v1 found"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True


def test_recon_combined_criteria_one_missing_is_partial():
    goal = EngagementGoal(
        kind=GoalKind.RECON,
        raw="complete recon",
        params={"min_services": 3, "min_technologies": 2, "min_endpoints": 2},
    )
    findings = [
        _F(rule_id="NMAP", message="open port 22"),
        _F(rule_id="NMAP", message="open port 80"),
        _F(rule_id="NMAP", message="open port 443"),
        _F(rule_id="WW", message="Apache"),  # only 1 tech, need 2
        _F(rule_id="FFUF", message="/admin /api"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is False
    assert progress.verdict is EngagementVerdict.PARTIAL
    assert "techs" in progress.reasoning


def test_recon_default_still_services_only_for_backward_compat():
    # Without min_technologies/min_endpoints declared, behaviour is the
    # same as the F118 baseline — only count ports.
    goal = EngagementGoal(kind=GoalKind.RECON, raw="recon", params={"min_services": 2})
    findings = [
        _F(rule_id="NMAP", message="open port 22"),
        _F(rule_id="NMAP", message="open port 443"),
    ]
    progress = GoalEvaluator().evaluate(goal, findings)
    assert progress.satisfied is True
    # Technologies + endpoints counters present but zero (no extra criteria).
    assert progress.technologies_detected == 0
    assert progress.endpoints_enumerated == 0
