"""F140 — Engagement notifications.

End-of-engagement notification routed via:

  - **Slack**: POST JSON to ``KRYON_SLACK_WEBHOOK``. Standard incoming-
    webhook payload (``text`` field).
  - **Email**: SMTP via stdlib ``smtplib``. ``KRYON_EMAIL_SMTP_HOST``,
    ``KRYON_EMAIL_SMTP_PORT``, ``KRYON_EMAIL_FROM``, ``KRYON_EMAIL_TO``,
    optional ``KRYON_EMAIL_SMTP_USER`` + ``KRYON_EMAIL_SMTP_PASSWORD``.
  - **Stdout**: default fallback. Prints the notification body. Safe-
    by-default — no external side effects unless an env var is set.

Trigger conditions (built into ``notify_engagement_complete``):

  - Verdict NOT_MET → notify (the goal failed, operator should know).
  - Verdict SATISFIED with CRITICAL findings present → notify.
  - Verdict SATISFIED with only LOW/INFO findings → no notification.

Per-engagement env override: ``KRYON_NOTIFY=always|on-critical|off``.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass
class NotificationResult:
    provider: str
    ok: bool
    detail: str = ""
    dry_run: bool = False


@runtime_checkable
class NotificationProvider(Protocol):
    name: str

    def send(self, *, subject: str, body: str) -> NotificationResult: ...


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


@dataclass
class StdoutProvider:
    """Default safe-by-default sink. Prints the notification body."""

    name: str = "stdout"

    def send(self, *, subject: str, body: str) -> NotificationResult:
        print(f"[KRYON NOTIFY] {subject}")
        print(body)
        return NotificationResult(provider=self.name, ok=True, dry_run=True)


@dataclass
class SlackProvider:
    name: str = "slack"
    webhook_url: str = ""

    def send(self, *, subject: str, body: str) -> NotificationResult:
        if not self.webhook_url:
            return NotificationResult(provider=self.name, ok=False, detail="missing KRYON_SLACK_WEBHOOK", dry_run=True)
        payload = json.dumps({"text": f"*{subject}*\n{body}"}).encode("utf-8")
        req = urllib.request.Request(self.webhook_url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                ok = 200 <= resp.status < 300
                return NotificationResult(provider=self.name, ok=ok, detail=f"status {resp.status}")
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
            return NotificationResult(provider=self.name, ok=False, detail=str(exc))


@dataclass
class EmailProvider:
    name: str = "email"
    smtp_host: str = ""
    smtp_port: int = 587
    sender: str = ""
    recipients: str = ""  # comma-separated
    smtp_user: str = ""
    smtp_password: str = ""

    def send(self, *, subject: str, body: str) -> NotificationResult:
        if not (self.smtp_host and self.sender and self.recipients):
            return NotificationResult(
                provider=self.name,
                ok=False,
                detail="missing SMTP host / from / to env",
                dry_run=True,
            )
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = self.recipients
        msg.set_content(body)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as smtp:
                smtp.ehlo()
                try:
                    smtp.starttls()
                    smtp.ehlo()
                except (smtplib.SMTPNotSupportedError, OSError):
                    # Server doesn't support STARTTLS; continue plain.
                    pass
                if self.smtp_user and self.smtp_password:
                    smtp.login(self.smtp_user, self.smtp_password)
                smtp.send_message(msg)
            return NotificationResult(provider=self.name, ok=True, detail=f"sent to {self.recipients}")
        except (smtplib.SMTPException, OSError) as exc:
            return NotificationResult(provider=self.name, ok=False, detail=str(exc))


# ---------------------------------------------------------------------------
# Resolve provider from env
# ---------------------------------------------------------------------------


def default_provider_from_env() -> NotificationProvider:
    if os.environ.get("KRYON_SLACK_WEBHOOK", "").strip():
        return SlackProvider(webhook_url=os.environ["KRYON_SLACK_WEBHOOK"].strip())
    if os.environ.get("KRYON_EMAIL_SMTP_HOST", "").strip():
        return EmailProvider(
            smtp_host=os.environ.get("KRYON_EMAIL_SMTP_HOST", "").strip(),
            smtp_port=int(os.environ.get("KRYON_EMAIL_SMTP_PORT", "587") or "587"),
            sender=os.environ.get("KRYON_EMAIL_FROM", "").strip(),
            recipients=os.environ.get("KRYON_EMAIL_TO", "").strip(),
            smtp_user=os.environ.get("KRYON_EMAIL_SMTP_USER", "").strip(),
            smtp_password=os.environ.get("KRYON_EMAIL_SMTP_PASSWORD", "").strip(),
        )
    return StdoutProvider()


# ---------------------------------------------------------------------------
# High-level helper
# ---------------------------------------------------------------------------


def _env_notify_mode() -> str:
    return os.environ.get("KRYON_NOTIFY", "on-critical").strip().lower() or "on-critical"


def _has_critical(findings: list[Any]) -> bool:
    for f in findings:
        sev = str(getattr(f, "severity", "") or "").upper()
        if sev in {"CRITICAL", "HIGH"}:
            return True
    return False


def should_notify(*, verdict: str | None, findings: list[Any]) -> bool:
    mode = _env_notify_mode()
    if mode == "off":
        return False
    if mode == "always":
        return True
    # on-critical (default)
    v = (verdict or "").lower()
    if v == "not_met":
        return True
    if v == "satisfied" and _has_critical(findings):
        return True
    if v == "partial" and _has_critical(findings):
        return True
    return False


def build_engagement_message(
    *,
    engagement_id: str,
    target: str,
    verdict: str | None,
    findings: list[Any],
) -> tuple[str, str]:
    """Build (subject, body) for the engagement-end notification."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = str(getattr(f, "severity", "") or "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
    verdict_label = (verdict or "—").upper()
    subject = f"Kryon engagement {engagement_id} — verdict {verdict_label}"
    body_lines = [
        f"Engagement: {engagement_id}",
        f"Target:     {target}",
        f"Verdict:    {verdict_label}",
        f"Findings:   total={len(findings)}",
        f"            CRITICAL={sev_counts['CRITICAL']}, HIGH={sev_counts['HIGH']}, "
        f"MEDIUM={sev_counts['MEDIUM']}, LOW={sev_counts['LOW']}, INFO={sev_counts['INFO']}",
    ]
    # Top 3 critical/high findings with rule_id + host.
    severe = [f for f in findings if str(getattr(f, "severity", "") or "").upper() in {"CRITICAL", "HIGH"}]
    if severe:
        body_lines.append("")
        body_lines.append("Top severe findings:")
        for f in severe[:3]:
            rule = getattr(f, "rule_id", "?")
            host = getattr(f, "host", "?")
            msg = (getattr(f, "message", "") or "")[:120]
            body_lines.append(f"  - [{getattr(f, 'severity', '?')}] {rule} on {host}")
            if msg:
                body_lines.append(f"      {msg}")
    return subject, "\n".join(body_lines)


def notify_engagement_complete(
    *,
    engagement_id: str,
    target: str,
    verdict: str | None,
    findings: list[Any],
    provider: NotificationProvider | None = None,
) -> NotificationResult | None:
    """Send the engagement-end notification if the trigger conditions
    are met. Returns the provider result, or None when notify was
    suppressed."""
    if not should_notify(verdict=verdict, findings=findings):
        return None
    subject, body = build_engagement_message(
        engagement_id=engagement_id, target=target, verdict=verdict, findings=findings
    )
    prov = provider or default_provider_from_env()
    return prov.send(subject=subject, body=body)
