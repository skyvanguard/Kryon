"""Tests for LLM health ping in readiness check."""

from __future__ import annotations

import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kryon.server.routes.health import _llm_cache, _ping_llm


@pytest.fixture(autouse=True)
def _clear_llm_cache():
    """Reset LLM health cache between tests."""
    _llm_cache["check"] = None
    _llm_cache["ts"] = 0.0
    yield
    _llm_cache["check"] = None
    _llm_cache["ts"] = 0.0


@pytest.fixture
def mock_litellm():
    """Inject a mock litellm module into sys.modules."""
    mod = types.ModuleType("litellm")
    mod.acompletion = AsyncMock(return_value=MagicMock())  # type: ignore[attr-defined]
    with patch.dict(sys.modules, {"litellm": mod}):
        yield mod


@pytest.mark.asyncio
async def test_ping_llm_no_provider(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    check = await _ping_llm()
    assert check.status == "degraded"
    assert "No LLM provider" in (check.error or "")


@pytest.mark.asyncio
async def test_ping_llm_success(monkeypatch, mock_litellm):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://test-llm:8080/v1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    mock_litellm.acompletion = AsyncMock(return_value=MagicMock())
    check = await _ping_llm()

    assert check.status == "healthy"
    assert check.error is None


@pytest.mark.asyncio
async def test_ping_llm_failure(monkeypatch, mock_litellm):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.delenv("OLLAMA", raising=False)

    mock_litellm.acompletion = AsyncMock(side_effect=RuntimeError("timeout"))
    check = await _ping_llm()

    assert check.status == "degraded"
    assert "ping failed" in (check.error or "")


@pytest.mark.asyncio
async def test_ping_llm_cache(monkeypatch, mock_litellm):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://test-llm:8080/v1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    call_count = 0

    async def mock_completion(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return MagicMock()

    mock_litellm.acompletion = mock_completion
    check1 = await _ping_llm()
    check2 = await _ping_llm()  # Should use cache

    assert check1.status == "healthy"
    assert check2.status == "healthy"
    assert call_count == 1  # Only called once due to cache
