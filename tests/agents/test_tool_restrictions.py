"""Tests for role-based tool filtering."""

from __future__ import annotations

from unittest.mock import MagicMock

from kryon.agents.tool_restrictions import DEFAULT_TOOL_POLICIES, RoleBasedToolFilter, ToolPolicy


class TestRoleBasedToolFilter:
    """Test tool filtering by role."""

    def _make_tool(self, name: str):
        tool = MagicMock()
        tool.name = name
        return tool

    def test_admin_has_full_access(self):
        f = RoleBasedToolFilter(role="admin")
        assert f.is_tool_allowed("nmap_scan")
        assert f.is_tool_allowed("rm_rf")
        assert f.is_tool_allowed("any_tool")

    def test_analyst_allowed_tools(self):
        f = RoleBasedToolFilter(role="analyst")
        assert f.is_tool_allowed("nmap_scan")
        assert f.is_tool_allowed("web_search")
        assert f.is_tool_allowed("dns_query")

    def test_analyst_denied_destructive(self):
        f = RoleBasedToolFilter(role="analyst")
        assert not f.is_tool_allowed("rm_rf")
        assert not f.is_tool_allowed("dd_wipe")
        assert not f.is_tool_allowed("format_disk")

    def test_viewer_read_only(self):
        f = RoleBasedToolFilter(role="viewer")
        assert f.is_tool_allowed("web_search")
        assert f.is_tool_allowed("dns_query")
        assert not f.is_tool_allowed("nmap_scan")

    def test_filter_tools_list(self):
        f = RoleBasedToolFilter(role="analyst")
        tools = [self._make_tool("nmap_scan"), self._make_tool("rm_rf"), self._make_tool("web_search")]
        filtered = f.filter_tools(tools)
        names = [t.name for t in filtered]
        assert "nmap_scan" in names
        assert "web_search" in names
        assert "rm_rf" not in names

    def test_custom_policy(self):
        policy = ToolPolicy(role="custom", allowed_tools=["my_tool"], denied_tools=[])
        f = RoleBasedToolFilter(policy=policy)
        assert f.is_tool_allowed("my_tool")
        assert not f.is_tool_allowed("other_tool")

    def test_denied_takes_priority(self):
        policy = ToolPolicy(role="test", allowed_tools=["*"], denied_tools=["dangerous_*"])
        f = RoleBasedToolFilter(policy=policy)
        assert f.is_tool_allowed("safe_tool")
        assert not f.is_tool_allowed("dangerous_tool")

    def test_default_policies_exist(self):
        assert "admin" in DEFAULT_TOOL_POLICIES
        assert "analyst" in DEFAULT_TOOL_POLICIES
        assert "viewer" in DEFAULT_TOOL_POLICIES
