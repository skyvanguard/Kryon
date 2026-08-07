"""Tests for webhook delivery."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kryon.server.webhooks import send_webhook


@pytest.mark.asyncio
async def test_send_webhook_success():
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()

    with (
        patch("kryon.tools.common._url_validation.validate_external_url", return_value=None),
        patch("httpx.AsyncClient") as mock_client,
    ):
        instance = AsyncMock()
        instance.post = AsyncMock(return_value=mock_response)
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = instance

        result = await send_webhook(
            "https://hooks.example.com/notify",
            "scan_completed",
            {"job_id": "123"},
        )
        assert result is True


@pytest.mark.asyncio
async def test_send_webhook_failure():
    with (
        patch("kryon.tools.common._url_validation.validate_external_url", return_value=None),
        patch("httpx.AsyncClient") as mock_client,
    ):
        instance = AsyncMock()
        instance.post = AsyncMock(side_effect=Exception("network error"))
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = instance

        result = await send_webhook(
            "https://hooks.example.com/notify",
            "scan_completed",
            {"job_id": "123"},
        )
        assert result is False
