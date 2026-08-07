"""The trace exporter must not phone home to OpenAI when we're talking to a
local / OpenAI-compatible backend (llama.cpp / DeepSeek) — both to avoid the
401 noise on a placeholder key AND to avoid leaking telemetry to a third party.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from kryon.sdk.agents.tracing.processors import BackendSpanExporter


def _exporter(monkeypatch, *, base_url=None, key="sk-real-...") -> BackendSpanExporter:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    if base_url is not None:
        monkeypatch.setenv("OPENAI_BASE_URL", base_url)
    exp = BackendSpanExporter(api_key=key)
    return exp


def test_skips_export_for_local_endpoint(monkeypatch):
    exp = _exporter(monkeypatch, base_url="http://localhost:8081/v1", key="sk-noauth")
    exp._client = MagicMock()
    exp.export([MagicMock()])
    exp._client.post.assert_not_called()


def test_skips_export_for_deepseek_endpoint(monkeypatch):
    exp = _exporter(monkeypatch, base_url="https://api.deepseek.com/v1", key="sk-deepseek")
    exp._client = MagicMock()
    exp.export([MagicMock()])
    exp._client.post.assert_not_called()


def test_skips_for_placeholder_key_even_without_base_url(monkeypatch):
    exp = _exporter(monkeypatch, base_url=None, key="not-set")
    exp._client = MagicMock()
    exp.export([MagicMock()])
    exp._client.post.assert_not_called()


def test_target_is_openai_true_for_real_openai(monkeypatch):
    # Real OpenAI: no custom base_url + a real-looking key → would export.
    exp = _exporter(monkeypatch, base_url=None, key="sk-realkey123")
    assert exp._target_is_openai() is True


def test_target_is_openai_true_for_explicit_openai_base(monkeypatch):
    exp = _exporter(monkeypatch, base_url="https://api.openai.com/v1", key="sk-realkey123")
    assert exp._target_is_openai() is True
