"""F137 — Ticket provider implementations.

Each provider conforms to ``TicketProvider`` protocol: a single
``create_ticket(summary, body, severity, source_ref) -> CreatedTicket``
method that performs the HTTP call (or returns a dry-run record when
credentials are absent).

Pure stdlib + ``urllib.request`` for the HTTP layer — no heavy SDK
deps so this module loads even in container images that strip
``requests``. Failures are explicit (raise on auth error, return
dry-run on missing config); never silent.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass
class CreatedTicket:
    """Outcome of opening a ticket."""

    provider: str
    ticket_id: str
    url: str = ""
    dry_run: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@runtime_checkable
class TicketProvider(Protocol):
    """Minimal interface a ticket backend must implement."""

    name: str

    def create_ticket(self, *, summary: str, body: str, severity: str, source_ref: str) -> CreatedTicket: ...


def _post_json(url: str, *, headers: dict[str, str], payload: dict) -> dict:
    """Stdlib POST helper. Raises urllib.error.HTTPError on non-2xx."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        text = resp.read().decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


@dataclass
class NoopProvider:
    """Default fallback. Logs the intended ticket but never opens one.
    Used when ``KRYON_TICKET_PROVIDER`` is unset or empty."""

    name: str = "noop"

    def create_ticket(self, *, summary: str, body: str, severity: str, source_ref: str) -> CreatedTicket:
        logger.info("noop ticket: [%s] %s (source=%s)", severity, summary, source_ref)
        return CreatedTicket(provider=self.name, ticket_id="dry-run", dry_run=True)


@dataclass
class JiraProvider:
    """Jira Cloud REST v3 — POST /rest/api/3/issue.

    Env: KRYON_TICKET_API_URL (e.g. https://acme.atlassian.net),
         KRYON_TICKET_API_TOKEN (base64 email:token),
         KRYON_TICKET_PROJECT_KEY (e.g. SEC).
    """

    name: str = "jira"
    base_url: str = ""
    token: str = ""
    project_key: str = ""

    def create_ticket(self, *, summary: str, body: str, severity: str, source_ref: str) -> CreatedTicket:
        if not (self.base_url and self.token and self.project_key):
            return CreatedTicket(
                provider=self.name,
                ticket_id="dry-run",
                dry_run=True,
                error="missing JIRA env vars (URL/token/project)",
            )
        url = f"{self.base_url.rstrip('/')}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary,
                "issuetype": {"name": "Bug"},
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": body}],
                        }
                    ],
                },
                "labels": [f"kryon-severity-{severity.lower()}", "kryon"],
            }
        }
        try:
            resp = _post_json(url, headers={"Authorization": f"Basic {self.token}"}, payload=payload)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
            return CreatedTicket(provider=self.name, ticket_id="", error=str(exc))
        key = str(resp.get("key", ""))
        return CreatedTicket(
            provider=self.name,
            ticket_id=key,
            url=f"{self.base_url.rstrip('/')}/browse/{key}" if key else "",
        )


@dataclass
class LinearProvider:
    """Linear GraphQL — POST /graphql with mutation issueCreate.

    Env: KRYON_TICKET_API_TOKEN (Linear API key),
         KRYON_TICKET_PROJECT_KEY (Linear team ID).
    """

    name: str = "linear"
    token: str = ""
    team_id: str = ""

    def create_ticket(self, *, summary: str, body: str, severity: str, source_ref: str) -> CreatedTicket:
        if not (self.token and self.team_id):
            return CreatedTicket(
                provider=self.name,
                ticket_id="dry-run",
                dry_run=True,
                error="missing LINEAR env vars (token/team)",
            )
        query = (
            "mutation IssueCreate($input: IssueCreateInput!) { "
            "issueCreate(input: $input) { success issue { id identifier url } } }"
        )
        payload = {
            "query": query,
            "variables": {
                "input": {
                    "teamId": self.team_id,
                    "title": summary,
                    "description": body,
                    "priority": _linear_priority(severity),
                }
            },
        }
        try:
            resp = _post_json(
                "https://api.linear.app/graphql",
                headers={"Authorization": self.token},
                payload=payload,
            )
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
            return CreatedTicket(provider=self.name, ticket_id="", error=str(exc))
        issue = resp.get("data", {}).get("issueCreate", {}).get("issue", {}) or {}
        ident = str(issue.get("identifier", ""))
        return CreatedTicket(
            provider=self.name,
            ticket_id=ident,
            url=str(issue.get("url", "")),
        )


def _linear_priority(severity: str) -> int:
    """Linear priority enum: 1=Urgent, 2=High, 3=Medium, 4=Low, 0=No priority."""
    return {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 0}.get(severity.upper(), 0)


@dataclass
class GitHubProvider:
    """GitHub Issues — POST /repos/{owner}/{repo}/issues.

    Env: KRYON_TICKET_API_TOKEN (PAT),
         KRYON_TICKET_PROJECT_KEY (owner/repo, e.g. "skyvanguard/Kryon").
    """

    name: str = "github"
    token: str = ""
    repo: str = ""  # owner/repo

    def create_ticket(self, *, summary: str, body: str, severity: str, source_ref: str) -> CreatedTicket:
        if not (self.token and self.repo):
            return CreatedTicket(
                provider=self.name,
                ticket_id="dry-run",
                dry_run=True,
                error="missing GITHUB env vars (token/repo)",
            )
        url = f"https://api.github.com/repos/{self.repo}/issues"
        payload = {
            "title": summary,
            "body": body,
            "labels": [f"kryon-severity-{severity.lower()}", "security"],
        }
        try:
            resp = _post_json(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                },
                payload=payload,
            )
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
            return CreatedTicket(provider=self.name, ticket_id="", error=str(exc))
        number = resp.get("number")
        return CreatedTicket(
            provider=self.name,
            ticket_id=str(number) if number else "",
            url=str(resp.get("html_url", "")),
        )
