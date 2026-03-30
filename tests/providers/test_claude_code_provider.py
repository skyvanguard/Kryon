"""Tests for ClaudeCodeProvider — defaults, tool parsing, message formatting, metadata."""

import json
import os

import pytest

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.sdk.agents.models.claude_code_provider import (
    ClaudeCodeConfig,
    ClaudeCodeModel,
    ClaudeCodeProvider,
    _find_matching_brace,
)

# ---------------------------------------------------------------------------
# Defaults (GAP 1)
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_config_default_model(self):
        cfg = ClaudeCodeConfig()
        assert cfg.model == "default"

    def test_model_default(self):
        m = ClaudeCodeModel()
        assert m.model == "default"

    def test_provider_default(self):
        p = ClaudeCodeProvider()
        assert p.default_model == "default"

    def test_provider_get_model_default(self):
        p = ClaudeCodeProvider()
        m = p.get_model(None)
        assert isinstance(m, ClaudeCodeModel)
        assert m.model == "default"

    def test_provider_get_model_override(self):
        p = ClaudeCodeProvider(default_model="haiku")
        m = p.get_model("sonnet")
        assert m.model == "sonnet"


# ---------------------------------------------------------------------------
# Balanced brace helper
# ---------------------------------------------------------------------------


class TestFindMatchingBrace:
    def test_simple(self):
        assert _find_matching_brace('{"a": 1}', 0) == 7

    def test_nested(self):
        text = '{"a": {"b": {"c": 1}}}'
        assert _find_matching_brace(text, 0) == len(text) - 1

    def test_string_with_braces(self):
        text = '{"a": "val{ue}"}'
        assert _find_matching_brace(text, 0) == len(text) - 1

    def test_escaped_quotes(self):
        text = r'{"a": "she said \"hi\""}'
        assert _find_matching_brace(text, 0) == len(text) - 1

    def test_no_match(self):
        assert _find_matching_brace("{unclosed", 0) == -1


# ---------------------------------------------------------------------------
# Tool call parsing (GAP 2)
# ---------------------------------------------------------------------------


class TestParseToolCalls:
    def setup_method(self):
        self.model = ClaudeCodeModel()

    def test_simple_tool_call(self):
        text = 'I will scan now. {"tool_call": {"name": "run_nmap", "arguments": {"target": "10.0.0.1"}}}'
        cleaned, calls = self.model._parse_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "run_nmap"
        assert calls[0]["arguments"]["target"] == "10.0.0.1"
        assert "run_nmap" not in cleaned
        assert "scan now" in cleaned

    def test_nested_arguments(self):
        tc = {
            "tool_call": {
                "name": "api_fuzz",
                "arguments": {
                    "config": {"headers": {"Authorization": "Bearer xxx"}, "timeout": 30},
                    "target": "http://example.com",
                },
            }
        }
        text = f"Fuzzing now. {json.dumps(tc)} Done."
        cleaned, calls = self.model._parse_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "api_fuzz"
        assert calls[0]["arguments"]["config"]["headers"]["Authorization"] == "Bearer xxx"
        assert "Fuzzing now" in cleaned
        assert "Done" in cleaned

    def test_multiple_tool_calls(self):
        tc1 = json.dumps({"tool_call": {"name": "tool_a", "arguments": {"x": 1}}})
        tc2 = json.dumps({"tool_call": {"name": "tool_b", "arguments": {"y": 2}}})
        text = f"Step 1. {tc1} Step 2. {tc2} End."
        cleaned, calls = self.model._parse_tool_calls(text)
        assert len(calls) == 2
        assert {c["name"] for c in calls} == {"tool_a", "tool_b"}

    def test_malformed_json_ignored(self):
        text = 'Some text {"tool_call": {broken and more text'
        cleaned, calls = self.model._parse_tool_calls(text)
        assert len(calls) == 0
        assert "Some text" in cleaned

    def test_no_tool_calls(self):
        text = "Just a regular response without tools."
        cleaned, calls = self.model._parse_tool_calls(text)
        assert len(calls) == 0
        assert cleaned == text


# ---------------------------------------------------------------------------
# Message formatting (GAP 3)
# ---------------------------------------------------------------------------


class TestFormatMessages:
    def setup_method(self):
        self.model = ClaudeCodeModel()

    def test_string_input(self):
        result = self.model._format_messages_as_prompt(None, "hello", [])
        assert "<user>\nhello\n</user>" in result

    def test_system_instructions(self):
        result = self.model._format_messages_as_prompt("Be helpful.", "hi", [])
        assert "<system>\nBe helpful.\n</system>" in result

    def test_function_call_item(self):
        items = [
            {"role": "user", "content": "scan 10.0.0.1"},
            {
                "type": "function_call",
                "call_id": "call_abc",
                "name": "run_nmap",
                "arguments": '{"target": "10.0.0.1"}',
            },
        ]
        result = self.model._format_messages_as_prompt(None, items, [])
        assert 'tool "run_nmap"' in result
        assert "call_abc" in result

    def test_function_call_output_item(self):
        items = [
            {"type": "function_call_output", "call_id": "call_abc", "output": "PORT 22/tcp open ssh"},
        ]
        result = self.model._format_messages_as_prompt(None, items, [])
        assert '<tool_result call_id="call_abc">' in result
        assert "PORT 22/tcp open ssh" in result

    def test_output_truncation(self):
        long_output = "A" * 15_000
        items = [
            {"type": "function_call_output", "call_id": "call_x", "output": long_output},
        ]
        result = self.model._format_messages_as_prompt(None, items, [])
        assert "...[truncated]" in result
        # Should not contain the full 15K chars
        assert len(result) < 12_000

    def test_multipart_content(self):
        items = [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "part1"},
                    {"type": "input_text", "text": "part2"},
                ],
            }
        ]
        result = self.model._format_messages_as_prompt(None, items, [])
        assert "part1\npart2" in result


# ---------------------------------------------------------------------------
# Metadata extraction (GAP 4)
# ---------------------------------------------------------------------------


class TestMetadataExtraction:
    @pytest.mark.asyncio
    async def test_metadata_populates_response(self, monkeypatch):
        """CLI metadata (cost, duration, session_id) should populate ModelResponse."""
        import subprocess as sp

        payload = json.dumps(
            {
                "result": "scan complete",
                "cost_usd": 0.005,
                "duration_ms": 1500,
                "session_id": "sess_abc123",
            }
        )

        def fake_run(*args, **kwargs):
            return sp.CompletedProcess(args=args[0], returncode=0, stdout=payload, stderr="")

        monkeypatch.setattr(sp, "run", fake_run)

        model = ClaudeCodeModel()
        # Minimal model_settings mock
        from types import SimpleNamespace

        ms = SimpleNamespace(max_tokens=None)
        response = await model.get_response(
            system_instructions=None,
            input="test",
            model_settings=ms,
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=None,
        )
        assert response.referenceable_id == "sess_abc123"
        assert response.usage.requests == 1

    @pytest.mark.asyncio
    async def test_max_tokens_forwarded(self, monkeypatch):
        """model_settings.max_tokens should become --max-tokens CLI flag."""
        import subprocess as sp

        captured_cmd = []

        def fake_run(cmd, *args, **kwargs):
            captured_cmd.extend(cmd)
            return sp.CompletedProcess(args=cmd, returncode=0, stdout=json.dumps({"result": "ok"}), stderr="")

        monkeypatch.setattr(sp, "run", fake_run)

        from types import SimpleNamespace

        ms = SimpleNamespace(max_tokens=4096)
        model = ClaudeCodeModel()
        await model.get_response(None, "test", ms, [], None, [], None)
        assert "--max-tokens" in captured_cmd
        assert "4096" in captured_cmd


# ---------------------------------------------------------------------------
# Retry logic (GAP 6)
# ---------------------------------------------------------------------------


class TestRetryLogic:
    @pytest.mark.asyncio
    async def test_retry_on_transient_error(self, monkeypatch):
        """Transient errors should be retried up to 2 times."""
        import subprocess as sp

        call_count = 0

        def fake_run(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return sp.CompletedProcess(args=[], returncode=1, stdout="", stderr="Connection reset")
            return sp.CompletedProcess(args=[], returncode=0, stdout=json.dumps({"result": "ok"}), stderr="")

        monkeypatch.setattr(sp, "run", fake_run)
        # Speed up retries for test
        import kryon.sdk.agents.models.claude_code_provider as mod

        monkeypatch.setattr(mod, "_RETRY_DELAYS", [0.01, 0.01])

        from types import SimpleNamespace

        model = ClaudeCodeModel()
        resp = await model.get_response(None, "test", SimpleNamespace(max_tokens=None), [], None, [], None)
        assert call_count == 3
        assert len(resp.output) > 0

    @pytest.mark.asyncio
    async def test_no_retry_on_auth_error(self, monkeypatch):
        """Auth errors should NOT be retried."""
        import subprocess as sp

        call_count = 0

        def fake_run(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return sp.CompletedProcess(args=[], returncode=1, stdout="", stderr="Unauthorized: invalid API key")

        monkeypatch.setattr(sp, "run", fake_run)
        import kryon.sdk.agents.models.claude_code_provider as mod

        monkeypatch.setattr(mod, "_RETRY_DELAYS", [0.01, 0.01])

        from types import SimpleNamespace

        model = ClaudeCodeModel()
        with pytest.raises(RuntimeError, match="Unauthorized"):
            await model.get_response(None, "test", SimpleNamespace(max_tokens=None), [], None, [], None)
        assert call_count == 1
