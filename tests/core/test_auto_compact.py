"""Test automatic context compaction when limit is reached."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kryon.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel


class TestAutoCompact:
    """Test automatic context compaction functionality."""

    @pytest.mark.asyncio
    async def test_auto_compact_triggers_at_threshold(self):
        """Test that auto-compact triggers when context exceeds threshold."""
        # Set up environment
        os.environ["KRYON_AUTO_COMPACT"] = "true"
        os.environ["KRYON_AUTO_COMPACT_THRESHOLD"] = "0.8"  # 80% threshold
        os.environ["KRYON_CONTEXT_USAGE"] = "0.0"

        # Mock the internal auto_compact method directly
        model = MagicMock(spec=OpenAIChatCompletionsModel)
        model._get_model_max_tokens = MagicMock(return_value=1000)

        # Test the _auto_compact_if_needed method
        with patch("kryon.sdk.agents.models.openai_chatcompletions.count_tokens_with_tiktoken") as mock_count:
            mock_count.return_value = (850, 0)  # 85% of max

            with patch("kryon.repl.commands.memory.MEMORY_COMMAND_INSTANCE") as mock_memory:
                mock_memory._ai_summarize_history = AsyncMock(return_value="Summary")

                with patch("kryon.repl.commands.memory.COMPACTED_SUMMARIES", {}):
                    with patch("rich.console.Console"):
                        # Create actual model instance
                        from openai import AsyncOpenAI

                        client = AsyncMock(spec=AsyncOpenAI)

                        with patch("kryon.sdk.agents.models.openai_chatcompletions.get_session_recorder"):
                            model = OpenAIChatCompletionsModel(
                                model="gpt-4",
                                openai_client=client,
                                agent_name="Test Agent",
                                agent_id="TEST123",
                            )

                            # Mock the model's max tokens method
                            with patch.object(model, "_get_model_max_tokens", return_value=1000):
                                # Call the auto-compact method directly
                                input_text = "Test message"
                                (
                                    new_input,
                                    new_instructions,
                                    compacted,
                                ) = await model._auto_compact_if_needed(
                                    estimated_tokens=850, input=input_text, system_instructions=None
                                )

                                # Verify compaction occurred
                                assert compacted is True
                                assert "Previous conversation summary" in new_instructions
                                mock_memory._ai_summarize_history.assert_called_once_with("Test Agent")

    @pytest.mark.asyncio
    async def test_auto_compact_disabled(self):
        """Test that auto-compact doesn't trigger when disabled."""
        os.environ["KRYON_AUTO_COMPACT"] = "false"

        from openai import AsyncOpenAI

        client = AsyncMock(spec=AsyncOpenAI)

        with patch("kryon.sdk.agents.models.openai_chatcompletions.get_session_recorder"):
            model = OpenAIChatCompletionsModel(
                model="gpt-4", openai_client=client, agent_name="Test Agent", agent_id="TEST123"
            )

            # Call the auto-compact method directly
            new_input, new_instructions, compacted = await model._auto_compact_if_needed(
                estimated_tokens=900,  # High token count
                input="Test",
                system_instructions=None,
            )

            # Verify no compaction occurred
            assert compacted is False
            assert new_input == "Test"
            assert new_instructions is None

    @pytest.mark.asyncio
    async def test_auto_compact_below_threshold(self):
        """Test that auto-compact doesn't trigger below threshold."""
        os.environ["KRYON_AUTO_COMPACT"] = "true"
        os.environ["KRYON_AUTO_COMPACT_THRESHOLD"] = "0.8"

        from openai import AsyncOpenAI

        client = AsyncMock(spec=AsyncOpenAI)

        with patch("kryon.sdk.agents.models.openai_chatcompletions.get_session_recorder"):
            model = OpenAIChatCompletionsModel(
                model="gpt-4", openai_client=client, agent_name="Test Agent", agent_id="TEST123"
            )

            with patch.object(model, "_get_model_max_tokens", return_value=1000):
                # Call the auto-compact method directly
                new_input, new_instructions, compacted = await model._auto_compact_if_needed(
                    estimated_tokens=700,  # 70% - below threshold
                    input="Test",
                    system_instructions=None,
                )

                # Verify no compaction occurred
                assert compacted is False

    @pytest.mark.asyncio
    async def test_auto_compact_with_custom_threshold(self):
        """Test auto-compact with custom threshold value."""
        os.environ["KRYON_AUTO_COMPACT"] = "true"
        os.environ["KRYON_AUTO_COMPACT_THRESHOLD"] = "0.5"  # 50% threshold

        from openai import AsyncOpenAI

        client = AsyncMock(spec=AsyncOpenAI)

        with patch("kryon.sdk.agents.models.openai_chatcompletions.get_session_recorder"):
            model = OpenAIChatCompletionsModel(
                model="gpt-4", openai_client=client, agent_name="Test Agent", agent_id="TEST123"
            )

            with patch.object(model, "_get_model_max_tokens", return_value=1000):
                with patch("kryon.sdk.agents.models.openai_chatcompletions.count_tokens_with_tiktoken") as mock_count:
                    mock_count.return_value = (600, 0)  # 60% - exceeds 50% threshold

                    with patch("kryon.repl.commands.memory.MEMORY_COMMAND_INSTANCE") as mock_memory:
                        mock_memory._ai_summarize_history = AsyncMock(return_value="Summary")

                        with patch("kryon.repl.commands.memory.COMPACTED_SUMMARIES", {}):
                            with patch("rich.console.Console"):
                                # Call the auto-compact method
                                (
                                    new_input,
                                    new_instructions,
                                    compacted,
                                ) = await model._auto_compact_if_needed(
                                    estimated_tokens=600, input="Test", system_instructions=None
                                )

                                # Verify compaction occurred at 60% with 50% threshold
                                assert compacted is True
                                mock_memory._ai_summarize_history.assert_called_once()

    @pytest.mark.asyncio
    async def test_auto_compact_error_handling(self):
        """Test that errors during auto-compact are handled gracefully."""
        os.environ["KRYON_AUTO_COMPACT"] = "true"
        os.environ["KRYON_AUTO_COMPACT_THRESHOLD"] = "0.8"

        from openai import AsyncOpenAI

        client = AsyncMock(spec=AsyncOpenAI)

        with patch("kryon.sdk.agents.models.openai_chatcompletions.get_session_recorder"):
            model = OpenAIChatCompletionsModel(
                model="gpt-4", openai_client=client, agent_name="Test Agent", agent_id="TEST123"
            )

            with patch.object(model, "_get_model_max_tokens", return_value=1000):
                with patch("kryon.repl.commands.memory.MEMORY_COMMAND_INSTANCE") as mock_memory:
                    # Make the summarization fail
                    mock_memory._ai_summarize_history = AsyncMock(side_effect=Exception("Failed"))

                    with patch("rich.console.Console"):
                        # Call the auto-compact method
                        (
                            new_input,
                            new_instructions,
                            compacted,
                        ) = await model._auto_compact_if_needed(
                            estimated_tokens=850, input="Test", system_instructions=None
                        )

                        # Should return without compaction on error
                        assert compacted is False
                        assert new_input == "Test"
                        assert new_instructions is None

    def test_get_model_max_tokens_resolves_v4_flash_context(self, monkeypatch):
        """The active DeepSeek V4 Flash must resolve to its real 1M window, not
        the legacy 200k default — otherwise auto-compact fires at ~160k and
        throws away ~84% of the usable context."""
        from unittest.mock import AsyncMock

        from openai import AsyncOpenAI

        monkeypatch.delenv("KRYON_MODEL_MAX_TOKENS", raising=False)
        client = AsyncMock(spec=AsyncOpenAI)
        with patch("kryon.sdk.agents.models.openai_chatcompletions.get_session_recorder"):
            model = OpenAIChatCompletionsModel(
                model="deepseek-v4-flash", openai_client=client, agent_name="T", agent_id="X"
            )
        assert model._get_model_max_tokens("deepseek-v4-flash") == 1_000_000
        # Unknown neutral alias falls back to the safe default.
        assert model._get_model_max_tokens("kryon-local") == 200_000
        # Explicit override wins for the alias.
        monkeypatch.setenv("KRYON_MODEL_MAX_TOKENS", "1000000")
        assert model._get_model_max_tokens("kryon-local") == 1_000_000

    @pytest.mark.asyncio
    async def test_deterministic_compaction_skips_llm_summary(self, monkeypatch):
        """Layer-3a: when trimming old tool outputs deterministically drops the
        history back under the threshold, the slow/fragile LLM summary is skipped
        and the history is preserved (not destroyed)."""
        from openai import AsyncOpenAI

        monkeypatch.setenv("KRYON_AUTO_COMPACT", "true")
        monkeypatch.setenv("KRYON_AUTO_COMPACT_THRESHOLD", "0.8")
        monkeypatch.setenv("KRYON_MICRO_COMPACT", "true")

        def _big_history():
            h = [{"role": "system", "content": "s"}, {"role": "user", "content": "go"}]
            for i in range(6):
                h.append(
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {"id": f"c{i}", "type": "function", "function": {"name": "run_command", "arguments": "{}"}}
                        ],
                    }
                )
                h.append({"role": "tool", "tool_call_id": f"c{i}", "content": "X" * 4000})
            h.append({"role": "assistant", "content": "thinking"})
            return h

        client = AsyncMock(spec=AsyncOpenAI)
        with patch("kryon.sdk.agents.models.openai_chatcompletions.get_session_recorder"):
            model = OpenAIChatCompletionsModel(
                model="deepseek-v4-flash", openai_client=client, agent_name="T", agent_id="X"
            )
        model.message_history = _big_history()

        with patch.object(model, "_get_model_max_tokens", return_value=1000):
            # Post-trim re-count returns 700 (<= 800 threshold), so the LLM is skipped.
            with patch(
                "kryon.sdk.agents.models.openai_chatcompletions.count_tokens_with_tiktoken",
                return_value=(700, 0),
            ):
                with patch("kryon.repl.commands.memory.MEMORY_COMMAND_INSTANCE") as mock_memory:
                    mock_memory._ai_summarize_history = AsyncMock(return_value="Summary")
                    new_input, new_sys, compacted = await model._auto_compact_if_needed(
                        estimated_tokens=850, input="Test", system_instructions=None
                    )

        assert compacted is False  # deterministic path handled it
        assert new_input == "Test"  # input untouched (history preserved, not summarized)
        mock_memory._ai_summarize_history.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.allow_call_model_methods
    async def test_auto_compact_integration(self):
        """Integration test for auto-compact during get_response."""
        os.environ["KRYON_AUTO_COMPACT"] = "true"
        os.environ["KRYON_AUTO_COMPACT_THRESHOLD"] = "0.8"

        from openai import AsyncOpenAI
        from openai.types.chat import ChatCompletion, ChatCompletionMessage
        from openai.types.chat.chat_completion import Choice, CompletionUsage

        from kryon.sdk.agents.model_settings import ModelSettings
        from kryon.sdk.agents.models.interface import ModelTracing

        client = AsyncMock(spec=AsyncOpenAI)
        client.base_url = "https://api.openai.com"

        # Create mock response
        mock_response = ChatCompletion(
            id="test-id",
            object="chat.completion",
            created=1234567890,
            model="gpt-4",
            choices=[
                Choice(
                    index=0,
                    message=ChatCompletionMessage(role="assistant", content="Response after compaction"),
                    finish_reason="stop",
                )
            ],
            usage=CompletionUsage(
                prompt_tokens=200,  # After compaction
                completion_tokens=50,
                total_tokens=250,
            ),
        )

        with patch("kryon.sdk.agents.models.openai_chatcompletions.get_session_recorder"):
            model = OpenAIChatCompletionsModel(
                model="gpt-4", openai_client=client, agent_name="Test Agent", agent_id="TEST123"
            )

            # Mock dependencies
            with patch.object(model, "_get_model_max_tokens", return_value=1000):
                with patch("kryon.sdk.agents.models.openai_chatcompletions.count_tokens_with_tiktoken") as mock_count:
                    # First count exceeds threshold, triggers compaction
                    mock_count.side_effect = [
                        (850, 0),  # Initial high count
                        (850, 0),  # Pre-compaction
                        (200, 0),  # Post-compaction
                    ]

                    with patch("kryon.repl.commands.memory.MEMORY_COMMAND_INSTANCE") as mock_memory:
                        mock_memory._ai_summarize_history = AsyncMock(return_value="Previous summary")

                        with patch("kryon.repl.commands.memory.COMPACTED_SUMMARIES", {}):
                            with patch("rich.console.Console"):
                                # Mock all the timer and tracking functions
                                with patch("kryon.sdk.agents.models.openai_chatcompletions.stop_idle_timer"):
                                    with patch("kryon.sdk.agents.models.openai_chatcompletions.start_active_timer"):
                                        with patch("kryon.sdk.agents.models.openai_chatcompletions.stop_active_timer"):
                                            with patch(
                                                "kryon.sdk.agents.models.openai_chatcompletions.start_idle_timer"
                                            ):
                                                with patch(
                                                    "kryon.sdk.agents.models.openai_chatcompletions.COST_TRACKER"
                                                ):
                                                    with patch.object(
                                                        model,
                                                        "_fetch_response",
                                                        AsyncMock(return_value=mock_response),
                                                    ):
                                                        # Call get_response
                                                        result = await model.get_response(
                                                            system_instructions=None,
                                                            input="Test message",
                                                            model_settings=ModelSettings(),
                                                            tools=[],
                                                            output_schema=None,
                                                            handoffs=[],
                                                            tracing=ModelTracing.DISABLED,
                                                        )

                                                        # Verify compaction was triggered
                                                        mock_memory._ai_summarize_history.assert_called_once()

                                                        # Verify response was returned
                                                        assert result is not None


class TestTokenCountingToolCalls:
    """count_tokens_with_tiktoken must count tool_calls payload — assistant
    tool-call messages carry content=None, so counting only content made the
    auto-compact trigger fire late (HIGH)."""

    def test_tool_calls_payload_is_counted(self):
        from kryon.sdk.agents.models.openai_chatcompletions import count_tokens_with_tiktoken

        # An assistant message with content=None but a big tool_calls arguments blob.
        big_args = '{"command": "' + "nmap -p- -T4 " * 200 + '"}'
        msgs = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "run_command", "arguments": big_args}}
            ]},
        ]
        total, _ = count_tokens_with_tiktoken(msgs)
        # Without the fix this was ~1 (role only). Now it reflects the arguments blob.
        assert total > 100, f"tool_calls payload not counted (got {total})"

    def test_content_only_message_still_counted(self):
        from kryon.sdk.agents.models.openai_chatcompletions import count_tokens_with_tiktoken

        total, _ = count_tokens_with_tiktoken([{"role": "user", "content": "hello world"}])
        assert total > 0
