"""Tests for webhook retry with exponential backoff."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from kryon.server.webhooks import _retry_post, send_webhook


@pytest.fixture
def _fast_sleep(monkeypatch):
    """Replace asyncio.sleep to avoid real delays in tests."""
    monkeypatch.setattr("kryon.server.webhooks.asyncio.sleep", AsyncMock())


def _make_mock_client(post_side_effect=None, post_return=None):
    mock_resp = AsyncMock()
    mock_resp.raise_for_status = MagicMock()

    mc = AsyncMock()
    if post_side_effect is not None:
        mc.post = AsyncMock(side_effect=post_side_effect)
    else:
        mc.post = AsyncMock(return_value=post_return or mock_resp)
    mc.__aenter__ = AsyncMock(return_value=mc)
    mc.__aexit__ = AsyncMock(return_value=False)
    return mc


@pytest.mark.asyncio
async def test_retry_post_success_first_attempt(_fast_sleep):
    mc = _make_mock_client()

    with patch("kryon.server.webhooks.httpx.AsyncClient", return_value=mc):
        result = await _retry_post("https://example.com/hook", {"key": "val"})

    assert result is True
    assert mc.post.call_count == 1


@pytest.mark.asyncio
async def test_retry_post_success_second_attempt(_fast_sleep):
    ok_resp = AsyncMock()
    ok_resp.raise_for_status = MagicMock()
    mc = _make_mock_client(post_side_effect=[httpx.ConnectError("fail"), ok_resp])

    with patch("kryon.server.webhooks.httpx.AsyncClient", return_value=mc):
        result = await _retry_post("https://example.com/hook", {"key": "val"})

    assert result is True
    assert mc.post.call_count == 2


@pytest.mark.asyncio
async def test_retry_post_all_attempts_fail(_fast_sleep):
    mc = _make_mock_client(post_side_effect=httpx.ConnectError("down"))

    with patch("kryon.server.webhooks.httpx.AsyncClient", return_value=mc):
        result = await _retry_post("https://example.com/hook", {}, max_attempts=3)

    assert result is False
    assert mc.post.call_count == 3


@pytest.mark.asyncio
async def test_retry_post_jitter_applied():
    """Verify sleep is called with a value between base and base*1.3."""
    sleep_values: list[float] = []

    async def capture_sleep(delay):
        sleep_values.append(delay)

    mc = _make_mock_client(post_side_effect=httpx.ConnectError("down"))

    with (
        patch("kryon.server.webhooks.httpx.AsyncClient", return_value=mc),
        patch("kryon.server.webhooks.asyncio.sleep", side_effect=capture_sleep),
    ):
        await _retry_post("https://example.com/hook", {}, max_attempts=3)

    assert len(sleep_values) == 2
    # First retry: base=1, jitter up to 0.3 → [1.0, 1.3]
    assert 1.0 <= sleep_values[0] <= 1.3
    # Second retry: base=4, jitter up to 1.2 → [4.0, 5.2]
    assert 4.0 <= sleep_values[1] <= 5.2


@pytest.mark.asyncio
async def test_send_webhook_uses_retry(_fast_sleep):
    with patch("kryon.server.webhooks._retry_post", new_callable=AsyncMock) as mock_retry:
        mock_retry.return_value = True
        result = await send_webhook("https://example.com", "scan.complete", {"id": "1"})

    assert result is True
    mock_retry.assert_called_once()
    payload = mock_retry.call_args[0][1]
    assert payload["event"] == "scan.complete"
    assert "timestamp" in payload


@pytest.mark.asyncio
async def test_email_channel_uses_thread():
    from kryon.notifications.channels import EmailChannel

    ch = EmailChannel(
        {
            "smtp_host": "localhost",
            "smtp_port": 587,
            "from_address": "test@test.com",
            "to_addresses": ["dest@test.com"],
            "use_tls": False,
        }
    )

    with patch("kryon.notifications.channels.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
        mock_thread.return_value = True
        result = await ch.send("Test Subject", "Test Body")

    assert result is True
    mock_thread.assert_called_once()
