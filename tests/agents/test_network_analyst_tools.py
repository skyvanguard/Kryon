"""Tests for network_analyst tool registration."""


def test_network_analyst_has_nmap():
    from kryon.agents.network_analyst import network_analyst

    tool_names = [getattr(t, "name", str(t)) for t in network_analyst.tools]
    assert "nmap" in tool_names, f"Missing nmap in: {tool_names}"


def test_network_analyst_has_run_command():
    from kryon.agents.network_analyst import network_analyst

    tool_names = [getattr(t, "name", str(t)) for t in network_analyst.tools]
    assert "run_command" in tool_names, f"Missing run_command in: {tool_names}"
