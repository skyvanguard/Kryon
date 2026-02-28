"""Multi-channel notification system."""

from kryon.notifications.channels import (
    EmailChannel,
    NotificationChannel,
    PagerDutyChannel,
    SlackChannel,
    TeamsChannel,
    WebhookChannel,
    get_channel,
)
from kryon.notifications.digest import DigestAggregator
from kryon.notifications.rules import evaluate_rules

__all__ = [
    "NotificationChannel",
    "EmailChannel",
    "SlackChannel",
    "TeamsChannel",
    "PagerDutyChannel",
    "WebhookChannel",
    "get_channel",
    "evaluate_rules",
    "DigestAggregator",
]
