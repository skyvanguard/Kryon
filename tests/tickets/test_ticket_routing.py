"""F137 — Ticket routing tests."""

from __future__ import annotations

from dataclasses import dataclass

from kryon.tickets.providers import (
    CreatedTicket,
    GitHubProvider,
    JiraProvider,
    LinearProvider,
    NoopProvider,
)
from kryon.tickets.routing import (
    create_tickets_for_findings,
    default_provider_from_env,
    should_open_ticket,
)


@dataclass
class _F:
    severity: str = "HIGH"
    rule_id: str = "x"
    host: str = "h"
    message: str = ""
    cwe: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: float = 1.0
    needs_verification: bool = False


# ---------------------------------------------------------------------------
# should_open_ticket
# ---------------------------------------------------------------------------


def test_critical_opens_ticket():
    assert should_open_ticket(_F(severity="CRITICAL")) is True


def test_high_opens_ticket():
    assert should_open_ticket(_F(severity="HIGH")) is True


def test_low_does_not_open():
    assert should_open_ticket(_F(severity="LOW")) is False


def test_info_does_not_open():
    assert should_open_ticket(_F(severity="INFO")) is False


def test_medium_does_not_open_by_default(monkeypatch):
    monkeypatch.delenv("KRYON_TICKET_INCLUDE_MEDIUM", raising=False)
    assert should_open_ticket(_F(severity="MEDIUM")) is False


def test_medium_opens_when_env_enabled(monkeypatch):
    monkeypatch.setenv("KRYON_TICKET_INCLUDE_MEDIUM", "true")
    assert should_open_ticket(_F(severity="MEDIUM")) is True


def test_needs_verification_skipped_by_default(monkeypatch):
    monkeypatch.delenv("KRYON_TICKET_LOW_CONFIDENCE", raising=False)
    assert should_open_ticket(_F(severity="HIGH", needs_verification=True)) is False


def test_needs_verification_allowed_when_env_enabled(monkeypatch):
    monkeypatch.setenv("KRYON_TICKET_LOW_CONFIDENCE", "true")
    assert should_open_ticket(_F(severity="HIGH", needs_verification=True)) is True


# ---------------------------------------------------------------------------
# default_provider_from_env
# ---------------------------------------------------------------------------


def test_default_is_noop_without_env(monkeypatch):
    monkeypatch.delenv("KRYON_TICKET_PROVIDER", raising=False)
    p = default_provider_from_env()
    assert isinstance(p, NoopProvider)


def test_jira_provider_selected(monkeypatch):
    monkeypatch.setenv("KRYON_TICKET_PROVIDER", "jira")
    monkeypatch.setenv("KRYON_TICKET_API_URL", "https://acme.atlassian.net")
    monkeypatch.setenv("KRYON_TICKET_API_TOKEN", "tok")
    monkeypatch.setenv("KRYON_TICKET_PROJECT_KEY", "SEC")
    p = default_provider_from_env()
    assert isinstance(p, JiraProvider)


def test_linear_provider_selected(monkeypatch):
    monkeypatch.setenv("KRYON_TICKET_PROVIDER", "linear")
    monkeypatch.setenv("KRYON_TICKET_API_TOKEN", "lin")
    monkeypatch.setenv("KRYON_TICKET_PROJECT_KEY", "team-1")
    p = default_provider_from_env()
    assert isinstance(p, LinearProvider)


def test_github_provider_selected(monkeypatch):
    monkeypatch.setenv("KRYON_TICKET_PROVIDER", "github")
    monkeypatch.setenv("KRYON_TICKET_API_TOKEN", "gh")
    monkeypatch.setenv("KRYON_TICKET_PROJECT_KEY", "owner/repo")
    p = default_provider_from_env()
    assert isinstance(p, GitHubProvider)


# ---------------------------------------------------------------------------
# Provider dry-run behaviour
# ---------------------------------------------------------------------------


def test_noop_provider_returns_dry_run():
    p = NoopProvider()
    t = p.create_ticket(summary="x", body="y", severity="HIGH", source_ref="eng-1")
    assert t.dry_run is True
    assert t.ticket_id == "dry-run"


def test_jira_provider_dry_runs_without_config():
    p = JiraProvider()
    t = p.create_ticket(summary="x", body="y", severity="HIGH", source_ref="eng-1")
    assert t.dry_run is True
    assert "missing" in t.error.lower()


def test_linear_provider_dry_runs_without_config():
    p = LinearProvider()
    t = p.create_ticket(summary="x", body="y", severity="HIGH", source_ref="eng-1")
    assert t.dry_run is True


def test_github_provider_dry_runs_without_config():
    p = GitHubProvider()
    t = p.create_ticket(summary="x", body="y", severity="HIGH", source_ref="eng-1")
    assert t.dry_run is True


# ---------------------------------------------------------------------------
# create_tickets_for_findings
# ---------------------------------------------------------------------------


def test_only_critical_high_get_tickets(monkeypatch):
    monkeypatch.delenv("KRYON_TICKET_INCLUDE_MEDIUM", raising=False)
    findings = [
        _F(severity="CRITICAL", rule_id="A"),
        _F(severity="HIGH", rule_id="B"),
        _F(severity="MEDIUM", rule_id="C"),
        _F(severity="LOW", rule_id="D"),
        _F(severity="INFO", rule_id="E"),
    ]
    result = create_tickets_for_findings(findings, engagement_id="eng-1", provider=NoopProvider())
    assert len(result) == 2  # CRITICAL + HIGH only


def test_needs_verification_filtered_out(monkeypatch):
    monkeypatch.delenv("KRYON_TICKET_LOW_CONFIDENCE", raising=False)
    findings = [
        _F(severity="HIGH", rule_id="A", needs_verification=False),
        _F(severity="HIGH", rule_id="B", needs_verification=True),
    ]
    result = create_tickets_for_findings(findings, engagement_id="eng", provider=NoopProvider())
    assert len(result) == 1


def test_create_tickets_handles_provider_error_gracefully():
    class _BadProvider:
        name = "bad"

        def create_ticket(self, *, summary, body, severity, source_ref):
            raise RuntimeError("provider broke")

    result = create_tickets_for_findings([_F(severity="CRITICAL")], engagement_id="eng", provider=_BadProvider())
    assert len(result) == 1
    assert result[0].error == "provider broke"
    assert result[0].ok is False


def test_empty_findings_returns_empty():
    assert create_tickets_for_findings([], engagement_id="eng", provider=NoopProvider()) == []
