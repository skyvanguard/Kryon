"""Tests for validation.bas_scenarios — BAS scenario tools."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from unittest.mock import MagicMock, patch

import pytest

from kryon.sdk.agents import FunctionTool


def test_bas_endpoint_security_exists():
    from kryon.tools.validation.bas_scenarios import bas_endpoint_security

    assert isinstance(bas_endpoint_security, FunctionTool)


def test_bas_data_exfiltration_exists():
    from kryon.tools.validation.bas_scenarios import bas_data_exfiltration

    assert isinstance(bas_data_exfiltration, FunctionTool)


def test_bas_ad_reconnaissance_exists():
    from kryon.tools.validation.bas_scenarios import bas_ad_reconnaissance

    assert isinstance(bas_ad_reconnaissance, FunctionTool)


def test_mitre_attack_mapping_exists():
    from kryon.tools.validation.bas_scenarios import mitre_attack_mapping

    assert isinstance(mitre_attack_mapping, FunctionTool)


@pytest.mark.asyncio
async def test_bas_endpoint_security_returns_structured():
    from kryon.tools.validation.bas_scenarios import bas_endpoint_security

    ctx = MagicMock()
    ctx.context = None
    with patch("kryon.tools.validation.bas_scenarios._run_cmd") as mock_run:
        mock_run.return_value = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE detected"
        result = await bas_endpoint_security.on_invoke_tool(ctx, json.dumps({"target_host": "192.168.1.100"}))
        data = json.loads(result)
        assert "scenario" in data
        assert data["scenario"] == "endpoint_security"


@pytest.mark.asyncio
async def test_bas_data_exfiltration_returns_structured():
    from kryon.tools.validation.bas_scenarios import bas_data_exfiltration

    ctx = MagicMock()
    ctx.context = None
    with patch("kryon.tools.validation.bas_scenarios._run_cmd") as mock_run:
        mock_run.return_value = "DNS exfiltration test: blocked"
        result = await bas_data_exfiltration.on_invoke_tool(
            ctx, json.dumps({"target_host": "192.168.1.100", "protocol": "dns"})
        )
        data = json.loads(result)
        assert "scenario" in data
        assert data["scenario"] == "data_exfiltration"


@pytest.mark.asyncio
async def test_mitre_attack_mapping_returns_techniques():
    from kryon.tools.validation.bas_scenarios import mitre_attack_mapping

    ctx = MagicMock()
    ctx.context = None
    result = await mitre_attack_mapping.on_invoke_tool(ctx, json.dumps({"technique_ids": "T1059,T1078"}))
    data = json.loads(result)
    assert "techniques" in data
    assert len(data["techniques"]) >= 1
