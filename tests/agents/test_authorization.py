"""Engagement authorization — window ("when") + tier ("what") on top of scope.

These extend the cage so the agent stays inside its written authorization on all
three axes even when running fully autonomously.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from kryon.agents.authorization import (
    EngagementAuthorization,
    _tool_tier,
    get_authorization,
    reset_authorization,
)


def _args(**kw) -> str:
    return json.dumps(kw)


# ---------------------------------------------------------------------------
# Time window
# ---------------------------------------------------------------------------


def test_before_window_blocks_everything():
    start = datetime.now(timezone.utc) + timedelta(hours=1)
    auth = EngagementAuthorization(None, start, None, None)
    ok, why = auth.authorize("web_fetch_smart", _args(url="http://x"))
    assert ok is False and "not started" in why


def test_after_window_blocks_everything():
    end = datetime.now(timezone.utc) - timedelta(hours=1)
    auth = EngagementAuthorization(None, None, end, None)
    ok, why = auth.authorize("web_fetch_smart", _args(url="http://x"))
    assert ok is False and "ended" in why


def test_inside_window_allows():
    now = datetime.now(timezone.utc)
    auth = EngagementAuthorization(None, now - timedelta(hours=1), now + timedelta(hours=1), None)
    assert auth.authorize("web_fetch_smart", _args(url="http://x"))[0] is True


# ---------------------------------------------------------------------------
# Action tier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool,expected",
    [
        ("web_fetch_smart", "passive"),
        ("nmap_scan", "active"),
        ("nuclei_scan", "active"),
        ("hydra_bruteforce", "exploit"),
        ("sqlmap_dump_database", "exploit"),
        ("dump_lsass", "post"),
        ("kerberoast", "post"),
        ("psexec_lateral_movement", "post"),
        ("some_unknown_tool", "active"),  # conservative default
    ],
)
def test_tool_tier_classification(tool, expected):
    from kryon.agents.authorization import _TIERS

    assert _tool_tier(tool) == _TIERS[expected]


def test_tier_ceiling_blocks_above():
    # active-tier engagement: scanning OK, exploitation/post refused.
    auth = EngagementAuthorization(None, None, None, max_tier=2)  # active
    assert auth.authorize("nmap_scan", _args(target="10.0.0.5"))[0] is True
    ok, why = auth.authorize("dump_lsass", _args(host="10.0.0.5"))
    assert ok is False and "post" in why and "active" in why
    assert auth.authorize("sqlmap_dump_database", _args(url="http://x"))[0] is False


def test_passive_tier_blocks_active():
    auth = EngagementAuthorization(None, None, None, max_tier=1)  # passive only
    assert auth.authorize("web_fetch_smart", _args(url="http://x"))[0] is True
    assert auth.authorize("nmap_scan", _args(target="10.0.0.5"))[0] is False


# ---------------------------------------------------------------------------
# env activation
# ---------------------------------------------------------------------------


def test_inactive_when_nothing_declared(monkeypatch):
    for v in ("KRYON_SCOPE", "KRYON_ENGAGEMENT_START", "KRYON_ENGAGEMENT_END", "KRYON_MAX_TIER"):
        monkeypatch.delenv(v, raising=False)
    reset_authorization()
    assert get_authorization() is None
    reset_authorization()


def test_active_with_only_tier(monkeypatch):
    monkeypatch.delenv("KRYON_SCOPE", raising=False)
    monkeypatch.setenv("KRYON_MAX_TIER", "passive")
    reset_authorization()
    auth = get_authorization()
    assert auth is not None
    assert auth.authorize("nmap_scan", _args(target="1.2.3.4"))[0] is False  # active > passive
    reset_authorization()


def test_active_combines_scope_and_tier(monkeypatch):
    monkeypatch.setenv("KRYON_SCOPE", "10.0.0.0/24")
    monkeypatch.setenv("KRYON_MAX_TIER", "active")
    reset_authorization()
    auth = get_authorization()
    # in-scope active tool: OK
    assert auth.authorize("nmap_scan", _args(target="10.0.0.5"))[0] is True
    # in-scope but post-tier: blocked by tier
    assert auth.authorize("dump_lsass", _args(host="10.0.0.5"))[0] is False
    # out-of-scope active tool: blocked by scope
    assert auth.authorize("nmap_scan", _args(target="8.8.8.8"))[0] is False
    reset_authorization()
