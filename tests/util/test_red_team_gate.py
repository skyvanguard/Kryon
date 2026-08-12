"""Canonical KRYON_RED_TEAM gate + investigate passive technical gate."""

from __future__ import annotations

from kryon.util.env import anon_proxy, is_capable_model, is_demo_mode, is_red_team, is_verbose


def test_is_capable_model_default_off(monkeypatch):
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    assert is_capable_model() is False


def test_is_capable_model_toggles(monkeypatch):
    for val in ("1", "true", "yes", "on"):
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", val)
        assert is_capable_model() is True, val
    for val in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("KRYON_CAPABLE_MODEL", val)
        assert is_capable_model() is False, val


def test_force_tool_turns_capability_gated(monkeypatch):
    from kryon.util.env import force_tool_turns

    monkeypatch.delenv("KRYON_FORCE_TOOL_TURNS", raising=False)
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    assert force_tool_turns() == 8  # 4B-local won't call tools on its own
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    assert force_tool_turns() == 0  # capable model drives itself — no blind forcing
    monkeypatch.setenv("KRYON_FORCE_TOOL_TURNS", "5")
    assert force_tool_turns() == 5  # explicit override wins


def test_anon_proxy_unset_returns_none(monkeypatch):
    monkeypatch.delenv("KRYON_ANON_PROXY", raising=False)
    monkeypatch.delenv("KRYON_SOCKS_PROXY", raising=False)
    assert anon_proxy() is None


def test_anon_proxy_reads_canonical_and_alias(monkeypatch):
    monkeypatch.delenv("KRYON_SOCKS_PROXY", raising=False)
    monkeypatch.setenv("KRYON_ANON_PROXY", "socks5://127.0.0.1:9050")
    assert anon_proxy() == "socks5://127.0.0.1:9050"
    monkeypatch.delenv("KRYON_ANON_PROXY", raising=False)
    monkeypatch.setenv("KRYON_SOCKS_PROXY", "socks5://10.0.0.1:9050")
    assert anon_proxy() == "socks5://10.0.0.1:9050"


def test_anon_proxy_blank_is_none(monkeypatch):
    monkeypatch.setenv("KRYON_ANON_PROXY", "   ")
    monkeypatch.delenv("KRYON_SOCKS_PROXY", raising=False)
    assert anon_proxy() is None


def test_is_verbose_default_off_and_toggles(monkeypatch):
    # Clean/product-grade is the DEFAULT — verbose is opt-in.
    monkeypatch.delenv("KRYON_VERBOSE", raising=False)
    monkeypatch.delenv("KRYON_DEBUG", raising=False)
    assert is_verbose() is False
    monkeypatch.setenv("KRYON_VERBOSE", "true")
    assert is_verbose() is True
    monkeypatch.delenv("KRYON_VERBOSE", raising=False)
    # KRYON_DEBUG=2 also enables verbose.
    monkeypatch.setenv("KRYON_DEBUG", "2")
    assert is_verbose() is True
    monkeypatch.setenv("KRYON_DEBUG", "1")
    assert is_verbose() is False


def test_is_demo_mode_parsing(monkeypatch):
    for val in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("KRYON_DEMO_MODE", val)
        assert is_demo_mode() is True, val
    for val in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("KRYON_DEMO_MODE", val)
        assert is_demo_mode() is False, val
    monkeypatch.delenv("KRYON_DEMO_MODE", raising=False)
    assert is_demo_mode() is False


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

    agent = _Agent(
        [
            "web_fetch_smart",
            "tool_search",
            "request_skill",
            "nmap_scan",
            "nuclei_scan",
            "sqlmap_dump",
            "run_command",
            "hydra_bruteforce",
        ]
    )
    dropped = _enforce_passive_toolset(agent)
    kept = {t.name for t in agent.tools}
    assert dropped == 5  # nmap/nuclei/sqlmap/run_command/hydra
    assert kept == {"web_fetch_smart", "tool_search", "request_skill"}


def test_passive_toolset_empty_agent():
    from kryon.cli.investigate import _enforce_passive_toolset

    class _Empty:
        tools = []

    assert _enforce_passive_toolset(_Empty()) == 0
