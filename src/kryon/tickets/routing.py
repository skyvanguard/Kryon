"""F137 — Decide which findings deserve a ticket + run the provider.

Routing rules (defaults, all env-tunable):

  - Severity CRITICAL/HIGH always opens a ticket.
  - MEDIUM opens a ticket only when ``KRYON_TICKET_INCLUDE_MEDIUM=true``.
  - LOW/INFO never open tickets.
  - Findings with ``needs_verification=True`` (F134 LLM-only without
    corroboration) are skipped unless ``KRYON_TICKET_LOW_CONFIDENCE=true``
    — banca-safe default: don't pollute the tracker with unverified
    LLM hallucinations.

The default ``KRYON_TICKET_PROVIDER`` is empty/unset, which routes
through ``NoopProvider`` (dry-run). This makes adding ticket
integration to an engagement risk-free: the operator turns it on
explicitly via env vars when ready.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from kryon.tickets.providers import (
    CreatedTicket,
    GitHubProvider,
    JiraProvider,
    LinearProvider,
    NoopProvider,
    TicketProvider,
)

logger = logging.getLogger(__name__)


def _env_true(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def should_open_ticket(finding: Any) -> bool:
    """Decide whether a single finding deserves a ticket."""
    severity = str(getattr(finding, "severity", "") or "").upper()
    include_medium = _env_true("KRYON_TICKET_INCLUDE_MEDIUM")
    allow_low_confidence = _env_true("KRYON_TICKET_LOW_CONFIDENCE")

    if severity not in {"CRITICAL", "HIGH", "MEDIUM"}:
        return False
    if severity == "MEDIUM" and not include_medium:
        return False
    if getattr(finding, "needs_verification", False) and not allow_low_confidence:
        return False
    return True


def default_provider_from_env() -> TicketProvider:
    """Resolve the ticket provider from environment. Returns
    ``NoopProvider`` when ``KRYON_TICKET_PROVIDER`` is unset/empty —
    safe-by-default."""
    name = os.environ.get("KRYON_TICKET_PROVIDER", "").strip().lower()
    if name == "jira":
        return JiraProvider(
            base_url=os.environ.get("KRYON_TICKET_API_URL", "").strip(),
            token=os.environ.get("KRYON_TICKET_API_TOKEN", "").strip(),
            project_key=os.environ.get("KRYON_TICKET_PROJECT_KEY", "").strip(),
        )
    if name == "linear":
        return LinearProvider(
            token=os.environ.get("KRYON_TICKET_API_TOKEN", "").strip(),
            team_id=os.environ.get("KRYON_TICKET_PROJECT_KEY", "").strip(),
        )
    if name == "github":
        return GitHubProvider(
            token=os.environ.get("KRYON_TICKET_API_TOKEN", "").strip(),
            repo=os.environ.get("KRYON_TICKET_PROJECT_KEY", "").strip(),
        )
    return NoopProvider()


def _format_summary(finding: Any) -> str:
    severity = str(getattr(finding, "severity", "") or "?")
    rule_id = str(getattr(finding, "rule_id", "") or "?")
    host = str(getattr(finding, "host", "") or "?")
    return f"[{severity}] {rule_id} on {host}"


def _format_body(finding: Any, engagement_id: str) -> str:
    lines: list[str] = []
    msg = str(getattr(finding, "message", "") or "")
    cwe = str(getattr(finding, "cwe", "") or "")
    evidence = str(getattr(finding, "evidence", "") or "")
    remediation = str(getattr(finding, "remediation", "") or "")
    confidence = getattr(finding, "confidence", None)
    if msg:
        lines.append(msg)
        lines.append("")
    if cwe:
        lines.append(f"**CWE**: {cwe}")
    if confidence is not None:
        lines.append(f"**Confidence**: {confidence:.2f}")
    if evidence:
        lines.append("")
        lines.append("**Evidence**:")
        lines.append("```")
        lines.append(evidence[:2000])
        lines.append("```")
    if remediation:
        lines.append("")
        lines.append(f"**Remediation**: {remediation}")
    lines.append("")
    lines.append(f"_Opened by Kryon engagement {engagement_id}._")
    return "\n".join(lines)


def create_tickets_for_findings(
    findings: list[Any],
    *,
    engagement_id: str,
    provider: TicketProvider | None = None,
) -> list[CreatedTicket]:
    """Walk ``findings`` and open a ticket for every entry that passes
    ``should_open_ticket``. Returns the list of CreatedTicket results
    (one per filed ticket, including dry-run rows). Never raises — a
    provider error just marks that single ticket as ``error=...``."""
    prov = provider or default_provider_from_env()
    out: list[CreatedTicket] = []
    for f in findings:
        if not should_open_ticket(f):
            continue
        try:
            ticket = prov.create_ticket(
                summary=_format_summary(f),
                body=_format_body(f, engagement_id),
                severity=str(getattr(f, "severity", "") or "MEDIUM"),
                source_ref=engagement_id,
            )
        except Exception as exc:  # pragma: no cover
            ticket = CreatedTicket(provider=prov.name, ticket_id="", error=str(exc))
        out.append(ticket)
    return out
