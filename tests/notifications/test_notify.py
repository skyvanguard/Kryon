"""F140 — Notifications tests."""

from __future__ import annotations

from dataclasses import dataclass

from kryon.notifications.notify import (
    EmailProvider,
    NotificationResult,
    SlackProvider,
    StdoutProvider,
    build_engagement_message,
    default_provider_from_env,
    notify_engagement_complete,
    should_notify,
)


@dataclass
class _F:
    severity: str = "MEDIUM"
    rule_id: str = "x"
    host: str = "h"
    message: str = ""


# ---------------------------------------------------------------------------
# should_notify trigger rules
# ---------------------------------------------------------------------------


def test_default_mode_notifies_on_not_met(monkeypatch):
    monkeypatch.delenv("KRYON_NOTIFY", raising=False)
    assert should_notify(verdict="not_met", findings=[]) is True


def test_default_mode_notifies_on_satisfied_with_critical(monkeypatch):
    monkeypatch.delenv("KRYON_NOTIFY", raising=False)
    assert should_notify(verdict="satisfied", findings=[_F(severity="CRITICAL")]) is True


def test_default_mode_does_not_notify_satisfied_with_only_low(monkeypatch):
    monkeypatch.delenv("KRYON_NOTIFY", raising=False)
    assert should_notify(verdict="satisfied", findings=[_F(severity="LOW")]) is False


def test_default_mode_notifies_on_partial_with_high(monkeypatch):
    monkeypatch.delenv("KRYON_NOTIFY", raising=False)
    assert should_notify(verdict="partial", findings=[_F(severity="HIGH")]) is True


def test_env_off_disables_all_notifications(monkeypatch):
    monkeypatch.setenv("KRYON_NOTIFY", "off")
    assert should_notify(verdict="not_met", findings=[_F(severity="CRITICAL")]) is False


def test_env_always_notifies_even_on_satisfied(monkeypatch):
    monkeypatch.setenv("KRYON_NOTIFY", "always")
    assert should_notify(verdict="satisfied", findings=[_F(severity="INFO")]) is True


# ---------------------------------------------------------------------------
# build_engagement_message
# ---------------------------------------------------------------------------


def test_build_message_has_subject_and_severity_counts():
    subject, body = build_engagement_message(
        engagement_id="eng-1",
        target="x.com",
        verdict="not_met",
        findings=[_F(severity="HIGH"), _F(severity="MEDIUM"), _F(severity="LOW")],
    )
    assert "eng-1" in subject
    assert "NOT_MET" in subject
    assert "total=3" in body
    assert "HIGH=1" in body


def test_build_message_lists_top_severe_findings():
    findings = [
        _F(severity="CRITICAL", rule_id="WEB-001", host="x", message="RCE on /upload"),
        _F(severity="HIGH", rule_id="WEB-002", host="x", message="SQLi on /login"),
    ]
    _, body = build_engagement_message(engagement_id="eng", target="x", verdict="not_met", findings=findings)
    assert "WEB-001" in body
    assert "WEB-002" in body
    assert "RCE" in body


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


def test_stdout_provider_always_succeeds(capsys):
    p = StdoutProvider()
    res = p.send(subject="s", body="b")
    assert res.ok is True
    assert res.dry_run is True
    captured = capsys.readouterr()
    assert "KRYON NOTIFY" in captured.out


def test_slack_provider_without_webhook_returns_dry_run():
    p = SlackProvider(webhook_url="")
    res = p.send(subject="s", body="b")
    assert res.ok is False
    assert res.dry_run is True
    assert "missing" in res.detail.lower()


def test_email_provider_without_config_returns_dry_run():
    p = EmailProvider()
    res = p.send(subject="s", body="b")
    assert res.ok is False
    assert res.dry_run is True


# ---------------------------------------------------------------------------
# default_provider_from_env
# ---------------------------------------------------------------------------


def test_default_is_stdout_without_env(monkeypatch):
    monkeypatch.delenv("KRYON_SLACK_WEBHOOK", raising=False)
    monkeypatch.delenv("KRYON_EMAIL_SMTP_HOST", raising=False)
    p = default_provider_from_env()
    assert isinstance(p, StdoutProvider)


def test_slack_selected_with_webhook(monkeypatch):
    monkeypatch.setenv("KRYON_SLACK_WEBHOOK", "https://hooks.slack.com/x")
    p = default_provider_from_env()
    assert isinstance(p, SlackProvider)


def test_email_selected_with_smtp_config(monkeypatch):
    monkeypatch.delenv("KRYON_SLACK_WEBHOOK", raising=False)
    monkeypatch.setenv("KRYON_EMAIL_SMTP_HOST", "smtp.x.com")
    monkeypatch.setenv("KRYON_EMAIL_FROM", "from@x.com")
    monkeypatch.setenv("KRYON_EMAIL_TO", "to@x.com")
    p = default_provider_from_env()
    assert isinstance(p, EmailProvider)


# ---------------------------------------------------------------------------
# notify_engagement_complete
# ---------------------------------------------------------------------------


def test_notify_suppressed_when_no_trigger(monkeypatch):
    monkeypatch.delenv("KRYON_NOTIFY", raising=False)
    res = notify_engagement_complete(
        engagement_id="x",
        target="x",
        verdict="satisfied",
        findings=[_F(severity="LOW")],
        provider=StdoutProvider(),
    )
    assert res is None


def test_notify_fires_on_not_met(monkeypatch, capsys):
    monkeypatch.delenv("KRYON_NOTIFY", raising=False)
    res = notify_engagement_complete(
        engagement_id="x",
        target="x",
        verdict="not_met",
        findings=[],
        provider=StdoutProvider(),
    )
    assert res is not None
    assert res.ok is True
    captured = capsys.readouterr()
    assert "NOT_MET" in captured.out
