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
from kryon.notifications.notify import (
    EmailProvider,
    NotificationProvider,
    NotificationResult,
    SlackProvider,
    StdoutProvider,
    build_engagement_message,
    default_provider_from_env,
    notify_engagement_complete,
    should_notify,
)
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
    # F140 engagement-end notifications
    "EmailProvider",
    "NotificationProvider",
    "NotificationResult",
    "SlackProvider",
    "StdoutProvider",
    "build_engagement_message",
    "default_provider_from_env",
    "notify_engagement_complete",
    "should_notify",
]
