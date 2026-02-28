"""Tests for notification rule evaluation."""

import json
import pytest
from kryon.notifications.rules import evaluate_rules


def _channel(cid, ctype="slack", enabled=True):
    return {"id": cid, "channel_type": ctype, "config_json": "{}", "enabled": enabled}


def _rule(event_type, channel_ids, severity_filter="", client_filter="", enabled=True):
    return {
        "event_type": event_type,
        "severity_filter": severity_filter,
        "client_filter": client_filter,
        "channel_ids": json.dumps(channel_ids),
        "digest_mode": "immediate",
        "enabled": enabled,
    }


def test_matching_rule():
    rules = [_rule("new_critical_finding", ["ch1"])]
    channels = [_channel("ch1")]
    result = evaluate_rules(rules, channels, "new_critical_finding")
    assert len(result) == 1
    assert result[0]["id"] == "ch1"


def test_no_matching_event_type():
    rules = [_rule("scan_complete", ["ch1"])]
    channels = [_channel("ch1")]
    result = evaluate_rules(rules, channels, "new_critical_finding")
    assert len(result) == 0


def test_severity_filter():
    rules = [_rule("new_critical_finding", ["ch1"], severity_filter="critical,high")]
    channels = [_channel("ch1")]
    assert len(evaluate_rules(rules, channels, "new_critical_finding", severity="critical")) == 1
    assert len(evaluate_rules(rules, channels, "new_critical_finding", severity="low")) == 0


def test_client_filter():
    rules = [_rule("new_critical_finding", ["ch1"], client_filter="client-1,client-2")]
    channels = [_channel("ch1")]
    assert len(evaluate_rules(rules, channels, "new_critical_finding", client_id="client-1")) == 1
    assert len(evaluate_rules(rules, channels, "new_critical_finding", client_id="client-3")) == 0


def test_disabled_rule():
    rules = [_rule("new_critical_finding", ["ch1"], enabled=False)]
    channels = [_channel("ch1")]
    assert len(evaluate_rules(rules, channels, "new_critical_finding")) == 0


def test_disabled_channel():
    rules = [_rule("new_critical_finding", ["ch1"])]
    channels = [_channel("ch1", enabled=False)]
    assert len(evaluate_rules(rules, channels, "new_critical_finding")) == 0


def test_multiple_channels():
    rules = [_rule("scan_complete", ["ch1", "ch2"])]
    channels = [_channel("ch1"), _channel("ch2")]
    result = evaluate_rules(rules, channels, "scan_complete")
    assert len(result) == 2


def test_empty_rules():
    assert len(evaluate_rules([], [_channel("ch1")], "test")) == 0
