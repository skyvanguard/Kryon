"""T4-M3: the SSH/chisel tunneling functions must be @function_tool and appear in
the tool registry under KRYON_RED_TEAM, or the agent has a foothold but no transport
to pivot into an isolated segment."""

from __future__ import annotations

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"


def test_tunneling_functions_are_function_tools():
    from kryon.tools.pivoting import tunneling

    for name in (
        "ssh_local_port_forward",
        "ssh_remote_port_forward",
        "ssh_dynamic_port_forward",
        "setup_chisel_tunnel",
        "kill_tunnel",
    ):
        obj = getattr(tunneling, name)
        assert hasattr(obj, "name"), f"{name} is not a function_tool"
        assert hasattr(obj, "params_json_schema"), f"{name} missing schema"
        assert hasattr(obj, "_raw_fn"), f"{name} missing raw callable"


def test_tunneling_registered_under_red_team(monkeypatch):
    monkeypatch.setenv("KRYON_RED_TEAM", "true")
    import importlib

    import kryon.skills.tool_budget as tb

    importlib.reload(tb)
    registry = tb.build_tool_registry()
    # at least the dynamic SOCKS forward must be present
    assert "ssh_dynamic_port_forward" in registry


def test_tunneling_absent_without_red_team(monkeypatch):
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    import importlib

    import kryon.skills.tool_budget as tb

    importlib.reload(tb)
    registry = tb.build_tool_registry()
    assert "ssh_dynamic_port_forward" not in registry
