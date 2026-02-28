"""Tests for notification channels."""

import pytest
from kryon.notifications.channels import (
    EmailChannel, SlackChannel, TeamsChannel, PagerDutyChannel,
    WebhookChannel, get_channel, NotificationChannel,
)


def test_email_channel_type():
    ch = EmailChannel(config={})
    assert ch.channel_type == "email"


def test_slack_channel_type():
    ch = SlackChannel(config={})
    assert ch.channel_type == "slack"


def test_teams_channel_type():
    ch = TeamsChannel(config={})
    assert ch.channel_type == "teams"


def test_pagerduty_channel_type():
    ch = PagerDutyChannel(config={})
    assert ch.channel_type == "pagerduty"


def test_webhook_channel_type():
    ch = WebhookChannel(config={})
    assert ch.channel_type == "webhook"


@pytest.mark.asyncio
async def test_email_no_recipients():
    ch = EmailChannel(config={"smtp_host": "localhost"})
    result = await ch.send("Test", "Body")
    assert result is False


@pytest.mark.asyncio
async def test_slack_no_webhook():
    ch = SlackChannel(config={})
    result = await ch.send("Test", "Body")
    assert result is False


@pytest.mark.asyncio
async def test_teams_no_webhook():
    ch = TeamsChannel(config={})
    result = await ch.send("Test", "Body")
    assert result is False


@pytest.mark.asyncio
async def test_pagerduty_no_key():
    ch = PagerDutyChannel(config={})
    result = await ch.send("Test", "Body")
    assert result is False


@pytest.mark.asyncio
async def test_webhook_no_url():
    ch = WebhookChannel(config={})
    result = await ch.send("Test", "Body")
    assert result is False


def test_get_channel_valid():
    ch = get_channel("email", {"smtp_host": "localhost"})
    assert isinstance(ch, EmailChannel)


def test_get_channel_invalid():
    with pytest.raises(ValueError, match="Unknown channel type"):
        get_channel("sms", {})


def test_get_channel_all_types():
    for ct in ["email", "slack", "teams", "pagerduty", "webhook"]:
        ch = get_channel(ct, {})
        assert isinstance(ch, NotificationChannel)
        assert ch.channel_type == ct
