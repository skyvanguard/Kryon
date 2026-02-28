"""Notification channel implementations — Email, Slack, Teams, PagerDuty, Webhook."""

from __future__ import annotations

import json
import logging
import smtplib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


class NotificationChannel(ABC):
    """Base class for notification channels."""

    channel_type: str = "base"

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    async def send(self, subject: str, body: str, payload: dict | None = None) -> bool:
        """Send notification. Returns True on success."""

    def _format_timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()


class EmailChannel(NotificationChannel):
    """SMTP email notifications with HTML support."""

    channel_type = "email"

    async def send(self, subject: str, body: str, payload: dict | None = None) -> bool:
        host = self.config.get("smtp_host", "localhost")
        port = int(self.config.get("smtp_port", 587))
        username = self.config.get("smtp_username", "")
        password = self.config.get("smtp_password", "")
        from_addr = self.config.get("from_address", "kryon@localhost")
        to_addrs = self.config.get("to_addresses", [])
        use_tls = self.config.get("use_tls", True)

        if not to_addrs:
            logger.warning("EmailChannel: no recipients configured")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[KRYON] {subject}"
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)

        html = f"""<html><body style="font-family:sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px">
<h2 style="color:#00d4ff">{subject}</h2>
<div style="background:#16213e;padding:15px;border-radius:8px;border-left:4px solid #00d4ff">
{body}
</div>
<p style="color:#666;font-size:12px;margin-top:20px">KRYON Security Platform &mdash; {self._format_timestamp()}</p>
</body></html>"""

        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html, "html"))

        try:
            server = smtplib.SMTP(host, port, timeout=10)
            if use_tls:
                server.starttls()
            if username:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
            logger.info("Email sent to %s: %s", to_addrs, subject)
            return True
        except Exception:
            logger.warning("Email send failed", exc_info=True)
            return False


class SlackChannel(NotificationChannel):
    """Slack webhook notifications with blocks formatting."""

    channel_type = "slack"

    async def send(self, subject: str, body: str, payload: dict | None = None) -> bool:
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url:
            logger.warning("SlackChannel: no webhook_url configured")
            return False

        severity = (payload or {}).get("severity", "info")
        color_map = {"critical": "#FF0000", "high": "#FF6600", "medium": "#FFCC00", "low": "#00CC00", "info": "#0066FF"}
        color = color_map.get(severity, "#999999")

        slack_payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {"type": "header", "text": {"type": "plain_text", "text": f"KRYON: {subject}"}},
                        {"type": "section", "text": {"type": "mrkdwn", "text": body}},
                        {
                            "type": "context",
                            "elements": [{"type": "mrkdwn", "text": f"Severity: *{severity}* | {self._format_timestamp()}"}],
                        },
                    ],
                }
            ]
        }

        return await self._post(webhook_url, slack_payload)

    async def _post(self, url: str, data: dict) -> bool:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json=data)
                resp.raise_for_status()
                logger.info("Slack notification sent")
                return True
        except Exception:
            logger.warning("Slack send failed", exc_info=True)
            return False


class TeamsChannel(NotificationChannel):
    """Microsoft Teams webhook with adaptive cards."""

    channel_type = "teams"

    async def send(self, subject: str, body: str, payload: dict | None = None) -> bool:
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url:
            logger.warning("TeamsChannel: no webhook_url configured")
            return False

        severity = (payload or {}).get("severity", "info")
        color_map = {"critical": "attention", "high": "warning", "medium": "accent", "low": "good", "info": "default"}
        style = color_map.get(severity, "default")

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": f"KRYON: {subject}", "style": style},
                            {"type": "TextBlock", "text": body, "wrap": True},
                            {"type": "FactSet", "facts": [
                                {"title": "Severity", "value": severity},
                                {"title": "Time", "value": self._format_timestamp()},
                            ]},
                        ],
                    },
                }
            ],
        }

        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(webhook_url, json=card)
                resp.raise_for_status()
                logger.info("Teams notification sent")
                return True
        except Exception:
            logger.warning("Teams send failed", exc_info=True)
            return False


class PagerDutyChannel(NotificationChannel):
    """PagerDuty Events API v2 integration."""

    channel_type = "pagerduty"

    async def send(self, subject: str, body: str, payload: dict | None = None) -> bool:
        routing_key = self.config.get("routing_key", "")
        if not routing_key:
            logger.warning("PagerDutyChannel: no routing_key configured")
            return False

        severity = (payload or {}).get("severity", "info")
        pd_severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}

        event = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"KRYON: {subject}",
                "source": "kryon-security-platform",
                "severity": pd_severity_map.get(severity, "info"),
                "custom_details": {"body": body, **(payload or {})},
            },
        }

        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post("https://events.pagerduty.com/v2/enqueue", json=event)
                resp.raise_for_status()
                logger.info("PagerDuty event triggered")
                return True
        except Exception:
            logger.warning("PagerDuty send failed", exc_info=True)
            return False


class WebhookChannel(NotificationChannel):
    """Generic HTTP POST webhook."""

    channel_type = "webhook"

    async def send(self, subject: str, body: str, payload: dict | None = None) -> bool:
        url = self.config.get("url", "")
        if not url:
            logger.warning("WebhookChannel: no url configured")
            return False

        headers = self.config.get("headers", {})
        data = {
            "event": subject,
            "body": body,
            "timestamp": self._format_timestamp(),
            **(payload or {}),
        }

        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json=data, headers=headers)
                resp.raise_for_status()
                logger.info("Webhook delivered to %s", url)
                return True
        except Exception:
            logger.warning("Webhook delivery failed to %s", url, exc_info=True)
            return False


_CHANNEL_REGISTRY: dict[str, type[NotificationChannel]] = {
    "email": EmailChannel,
    "slack": SlackChannel,
    "teams": TeamsChannel,
    "pagerduty": PagerDutyChannel,
    "webhook": WebhookChannel,
}


def get_channel(channel_type: str, config: dict) -> NotificationChannel:
    """Create a notification channel by type."""
    cls = _CHANNEL_REGISTRY.get(channel_type)
    if cls is None:
        raise ValueError(f"Unknown channel type: {channel_type}. Available: {list(_CHANNEL_REGISTRY.keys())}")
    return cls(config)
