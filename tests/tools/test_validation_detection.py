"""Tests for validation.detection_validator — SIEM detection validation."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.validation.detection_validator import check_siem_alert, validate_detection


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# validate_detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_no_endpoint(monkeypatch):
    """No SIEM endpoint returns SKIPPED status."""
    result = await _invoke(
        validate_detection,
        {
            "technique_id": "T1046",
        },
    )
    assert "SKIPPED" in result
    assert "no SIEM endpoint" in result.lower() or "no SIEM endpoint" in result


@pytest.mark.asyncio
async def test_validate_elastic(monkeypatch):
    """Elastic SIEM validation builds correct curl command."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"hits": {"total": 0}}'

    monkeypatch.setattr("kryon.tools.validation.detection_validator.run_command", fake_run)

    result = await _invoke(
        validate_detection,
        {
            "technique_id": "T1046",
            "siem_type": "elastic",
            "siem_endpoint": "https://elastic.local:9200",
        },
    )
    assert "_search" in captured["cmd"]
    assert "T1046" in captured["cmd"]
    assert "elastic" in result.lower()


@pytest.mark.asyncio
async def test_validate_splunk(monkeypatch):
    """Splunk SIEM validation builds correct curl command."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"results": []}'

    monkeypatch.setattr("kryon.tools.validation.detection_validator.run_command", fake_run)

    result = await _invoke(
        validate_detection,
        {
            "technique_id": "T1110",
            "siem_type": "splunk",
            "siem_endpoint": "https://splunk.local:8089",
        },
    )
    assert "services/search" in captured["cmd"]
    assert "T1110" in captured["cmd"]


@pytest.mark.asyncio
async def test_validate_unknown_siem(monkeypatch):
    """Unknown SIEM type returns error."""
    result = await _invoke(
        validate_detection,
        {
            "technique_id": "T1046",
            "siem_type": "unknown_siem",
            "siem_endpoint": "https://siem.local",
        },
    )
    assert "Error" in result or "Unsupported" in result


@pytest.mark.asyncio
async def test_validate_with_time_window(monkeypatch):
    """Custom time window is forwarded."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return "{}"

    monkeypatch.setattr("kryon.tools.validation.detection_validator.run_command", fake_run)

    result = await _invoke(
        validate_detection,
        {
            "technique_id": "T1046",
            "siem_type": "elastic",
            "siem_endpoint": "https://elastic.local:9200",
            "time_window_minutes": 30,
        },
    )
    assert "30m" in result
    assert "now-30m" in captured["cmd"]


# ---------------------------------------------------------------------------
# check_siem_alert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_siem_elastic(monkeypatch):
    """Elastic SIEM check builds curl POST."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"hits": {"total": 5}}'

    monkeypatch.setattr("kryon.tools.validation.detection_validator.run_command", fake_run)

    result = await _invoke(
        check_siem_alert,
        {
            "query": '{"query": {"match_all": {}}}',
            "siem_type": "elastic",
            "siem_endpoint": "https://elastic.local:9200",
        },
    )
    assert "_search" in captured["cmd"]


@pytest.mark.asyncio
async def test_check_siem_splunk(monkeypatch):
    """Splunk SIEM check builds curl with SPL query."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return '{"results": []}'

    monkeypatch.setattr("kryon.tools.validation.detection_validator.run_command", fake_run)

    result = await _invoke(
        check_siem_alert,
        {
            "query": "search index=main sourcetype=syslog",
            "siem_type": "splunk",
            "siem_endpoint": "https://splunk.local:8089",
        },
    )
    assert "services/search" in captured["cmd"]


@pytest.mark.asyncio
async def test_check_siem_no_endpoint(monkeypatch):
    """No endpoint returns error."""
    result = await _invoke(
        check_siem_alert,
        {
            "query": "test query",
            "siem_type": "elastic",
        },
    )
    assert "Error" in result
    assert "endpoint" in result.lower()
