"""Tests for CVE enrichment (mocked HTTP calls)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kryon.intelligence.cve_enrichment import CVEEnricher


@pytest.fixture
def enricher():
    return CVEEnricher()


@pytest.mark.asyncio
async def test_get_epss_success(enricher):
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": [{"cve": "CVE-2024-12345", "epss": "0.75", "percentile": "0.95"}]}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client:
        instance = AsyncMock()
        instance.get = AsyncMock(return_value=mock_response)
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = instance

        score, pct = await enricher.get_epss("CVE-2024-12345")
        assert score == 0.75
        assert pct == 0.95


@pytest.mark.asyncio
async def test_get_epss_failure(enricher):
    with patch("httpx.AsyncClient") as mock_client:
        instance = AsyncMock()
        instance.get = AsyncMock(side_effect=Exception("network error"))
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = instance

        score, pct = await enricher.get_epss("CVE-2024-99999")
        assert score is None
        assert pct is None


@pytest.mark.asyncio
async def test_check_cisa_kev_with_cached_data(enricher, tmp_path):
    kev_data = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-12345"},
            {"cveID": "CVE-2023-99999"},
        ]
    }
    # Pre-populate the KEV set directly
    enricher._kev_set = {v["cveID"] for v in kev_data["vulnerabilities"]}
    enricher._kev_data = kev_data["vulnerabilities"]

    assert await enricher.check_cisa_kev("CVE-2024-12345") is True
    assert await enricher.check_cisa_kev("CVE-2024-00000") is False


@pytest.mark.asyncio
async def test_enrich_batch(enricher):
    enricher._kev_set = {"CVE-2024-11111"}
    enricher._kev_data = [{"cveID": "CVE-2024-11111"}]

    with patch.object(enricher, "get_epss", return_value=(0.5, 0.8)):
        with patch.object(enricher, "check_exploit_db", return_value=[]):
            results = await enricher.enrich_batch(["CVE-2024-11111", "CVE-2024-22222"])

    assert len(results) == 2
    assert results[0].cve_id == "CVE-2024-11111"
    assert results[0].cisa_kev is True
    assert results[1].cisa_kev is False
