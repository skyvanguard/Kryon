"""F203.E — Tests for `tool_search` autonomous discovery tool."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.tools.knowledge.tool_search import (
    _format_tool_entry,
    _score_tool,
    _whole_word,
    tool_search,
)

_raw = tool_search._raw_fn


def _make_tool(name: str, description: str = "", params: dict | None = None) -> SimpleNamespace:
    """Fabricate a FunctionTool-shaped object for tests."""
    return SimpleNamespace(
        name=name,
        description=description,
        params_json_schema={"properties": params or {}},
    )


# ---------------------------------------------------------------------------
# _whole_word
# ---------------------------------------------------------------------------


class TestWholeWord:
    def test_matches_exact_word(self):
        assert _whole_word("nmap", "scan with nmap tool")

    def test_does_not_match_substring(self):
        assert not _whole_word("map", "nmap is a port scanner")

    def test_case_insensitive(self):
        assert _whole_word("Nmap", "scan with NMAP")

    def test_empty_needle(self):
        assert not _whole_word("", "anything")


# ---------------------------------------------------------------------------
# _score_tool
# ---------------------------------------------------------------------------


class TestScoreTool:
    def test_name_match_higher_than_description(self):
        name_match = _make_tool("nmap_scan", "Generic scanner tool")
        desc_match = _make_tool("portmap", "Run nmap against a host")
        # Both should score, but name match scores more (peso 3 vs 2)
        s_name = _score_tool(name_match, "nmap target", {"nmap", "target"})
        s_desc = _score_tool(desc_match, "nmap target", {"nmap", "target"})
        assert s_name > s_desc

    def test_no_match_returns_zero(self):
        t = _make_tool("totally_unrelated", "does nothing")
        s = _score_tool(t, "find sqli vulns", {"find", "sqli", "vulns"})
        assert s == 0

    def test_short_tokens_ignored(self):
        # tokens < 3 chars don't count (avoid noise like "a", "of")
        t = _make_tool("a_tool", "of x y")
        s = _score_tool(t, "a of x", {"a", "of", "x"})
        # All tokens < 3 chars, so score should be 0 (no whole-word match)
        # Substring match also requires query_lower in desc — "a of x" is
        # NOT in "of x y", so substring fails too.
        assert s == 0


# ---------------------------------------------------------------------------
# _format_tool_entry
# ---------------------------------------------------------------------------


class TestFormatToolEntry:
    def test_includes_name(self):
        t = _make_tool("web_fetch_smart", "Fetch HTTP")
        out = _format_tool_entry(t)
        assert "web_fetch_smart" in out

    def test_includes_description(self):
        t = _make_tool("foo", "Bar baz qux")
        out = _format_tool_entry(t)
        assert "Bar baz qux" in out

    def test_truncates_long_description(self):
        t = _make_tool("foo", "X" * 500)
        out = _format_tool_entry(t)
        assert "..." in out
        assert out.count("X") < 500

    def test_shows_param_names(self):
        t = _make_tool("foo", "bar", params={"url": {}, "timeout": {}})
        out = _format_tool_entry(t)
        assert "url" in out
        assert "timeout" in out


# ---------------------------------------------------------------------------
# tool_search — integration with mocked inventory
# ---------------------------------------------------------------------------


def _patch_inventory(tools: list) -> patch:
    return patch(
        "kryon.tools.knowledge.tool_search._gather_inventory",
        return_value=tools,
    )


class TestToolSearchHappyPath:
    def test_returns_top_matches(self):
        inventory = [
            _make_tool("nmap_scan", "Run nmap port scanner against host"),
            _make_tool("nuclei_scan", "Template-based vuln scanner"),
            _make_tool("unrelated_tool", "Does nothing useful"),
        ]
        with _patch_inventory(inventory):
            result = _raw(query="scan host for open ports nmap")
        assert "nmap_scan" in result
        # Top result is nmap (name + desc match)
        nmap_pos = result.find("nmap_scan")
        unrelated_pos = result.find("unrelated_tool")
        # unrelated should not appear at all (score=0)
        assert unrelated_pos == -1 or unrelated_pos > nmap_pos

    def test_returns_top_8_at_most(self):
        inventory = [_make_tool(f"scanner_{i}", "scan tool") for i in range(20)]
        with _patch_inventory(inventory):
            result = _raw(query="scan something")
        # All match (word "scan" in description), but we cap at 8
        assert result.count("scanner_") <= 8


class TestToolSearchNoMatch:
    def test_no_match_returns_defaults(self):
        inventory = [
            _make_tool("web_fetch_smart", "Fetch HTTP and parse"),
            _make_tool("duckduckgo_search", "Web search engine"),
            _make_tool("request_skill", "Get methodology"),
            _make_tool("specialized_tool", "Very narrow purpose"),
        ]
        with _patch_inventory(inventory):
            result = _raw(query="xyzqwerty nothing matches")
        # Should show defaults
        assert "Default tools" in result or "No specific match" in result
        # web_fetch_smart is in the default whitelist and present
        assert "web_fetch_smart" in result

    def test_empty_inventory_returns_error(self):
        with _patch_inventory([]):
            result = _raw(query="anything")
        assert "ERROR" in result
        assert "inventory empty" in result


class TestToolSearchErrors:
    def test_empty_query_returns_error(self):
        result = _raw(query="")
        assert "ERROR" in result
        assert "empty query" in result.lower()

    def test_whitespace_only_query_returns_error(self):
        result = _raw(query="   \n\t  ")
        assert "ERROR" in result


# ---------------------------------------------------------------------------
# Banca-safe contract — source-level inspection
# ---------------------------------------------------------------------------


class TestBancaSafe:
    """tool_search must not write disk, touch network, or exec subprocess."""

    SRC = Path(__file__).resolve().parents[3] / "src" / "kryon" / "tools" / "knowledge" / "tool_search.py"

    def test_no_filesystem_writes(self):
        text = self.SRC.read_text(encoding="utf-8")
        assert "write_text(" not in text
        assert "write_draft(" not in text

    def test_no_network_calls(self):
        text = self.SRC.read_text(encoding="utf-8")
        assert "urllib" not in text
        assert "requests." not in text
        assert "httpx" not in text

    def test_no_subprocess(self):
        text = self.SRC.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "os.system" not in text
