"""Canonical KRYON_RED_TEAM gate + investigate passive technical gate."""

from __future__ import annotations

from kryon.util.env import is_red_team


def test_is_red_team_canonical_parsing(monkeypatch):
    for val in ("1", "true", "TRUE", "yes", "on", " on "):
        monkeypatch.setenv("KRYON_RED_TEAM", val)
        assert is_red_team() is True, val
    for val in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("KRYON_RED_TEAM", val)
        assert is_red_team() is False, val
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    assert is_red_team() is False


def test_offensive_gate_delegates(monkeypatch):
    from kryon.tools._offensive_gate import is_red_team_enabled

    monkeypatch.setenv("KRYON_RED_TEAM", "on")  # 'on' must be honored everywhere
    assert is_red_team_enabled() is True
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    assert is_red_team_enabled() is False


class _Tool:
    def __init__(self, name):
        self.name = name


class _Agent:
    def __init__(self, names):
        self.tools = [_Tool(n) for n in names]


def test_passive_toolset_drops_active_keeps_passive():
    from kryon.cli.investigate import _enforce_passive_toolset

    agent = _Agent(["web_fetch_smart", "tool_search", "request_skill",
                    "nmap_scan", "nuclei_scan", "sqlmap_dump", "run_command", "hydra_bruteforce"])
    dropped = _enforce_passive_toolset(agent)
    kept = {t.name for t in agent.tools}
    assert dropped == 5  # nmap/nuclei/sqlmap/run_command/hydra
    assert kept == {"web_fetch_smart", "tool_search", "request_skill"}


def test_passive_toolset_empty_agent():
    from kryon.cli.investigate import _enforce_passive_toolset

    class _Empty:
        tools = []

    assert _enforce_passive_toolset(_Empty()) == 0
