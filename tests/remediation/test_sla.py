"""Tests for SLA calculations."""

from datetime import datetime, timedelta, timezone

import pytest

from kryon.remediation.sla import SLA_DEADLINES, calculate_sla_deadline


def test_calculate_sla_critical():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    deadline = calculate_sla_deadline("critical", now)
    expected = (now + timedelta(days=7)).isoformat()
    assert deadline == expected


def test_calculate_sla_high():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    deadline = calculate_sla_deadline("high", now)
    expected = (now + timedelta(days=30)).isoformat()
    assert deadline == expected


def test_calculate_sla_medium():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    deadline = calculate_sla_deadline("medium", now)
    expected = (now + timedelta(days=90)).isoformat()
    assert deadline == expected


def test_calculate_sla_low():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    deadline = calculate_sla_deadline("low", now)
    expected = (now + timedelta(days=180)).isoformat()
    assert deadline == expected


def test_sla_default():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    deadline = calculate_sla_deadline("unknown", now)
    expected = (now + timedelta(days=90)).isoformat()
    assert deadline == expected


def test_custom_from_date():
    custom = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    deadline = calculate_sla_deadline("critical", custom)
    expected = (custom + timedelta(days=7)).isoformat()
    assert deadline == expected


def test_sla_no_from_date():
    deadline = calculate_sla_deadline("high")
    assert "T" in deadline
    dt = datetime.fromisoformat(deadline)
    assert dt > datetime.now(timezone.utc)
