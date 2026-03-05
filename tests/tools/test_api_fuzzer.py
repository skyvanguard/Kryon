"""Tests for API fuzzing tools (Task 2.1 - API Fuzzer Agent)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from kryon.sdk.agents import FunctionTool


def test_parse_openapi_spec_exists():
    from kryon.tools.api_attacks.api_fuzzer import parse_openapi_spec

    assert isinstance(parse_openapi_spec, FunctionTool)


def test_discover_api_endpoints_exists():
    from kryon.tools.api_attacks.api_fuzzer import discover_api_endpoints

    assert isinstance(discover_api_endpoints, FunctionTool)


def test_fuzz_api_endpoint_exists():
    from kryon.tools.api_attacks.api_fuzzer import fuzz_api_endpoint

    assert isinstance(fuzz_api_endpoint, FunctionTool)


def test_test_idor_exists():
    from kryon.tools.api_attacks.api_fuzzer import test_idor

    assert isinstance(test_idor, FunctionTool)


def test_test_rate_limiting_exists():
    from kryon.tools.api_attacks.api_fuzzer import test_rate_limiting

    assert isinstance(test_rate_limiting, FunctionTool)


def test_test_auth_mechanisms_exists():
    from kryon.tools.api_attacks.api_fuzzer import test_auth_mechanisms

    assert isinstance(test_auth_mechanisms, FunctionTool)


@pytest.mark.asyncio
async def test_parse_openapi_spec_parses_json():
    from kryon.tools.api_attacks.api_fuzzer import parse_openapi_spec

    ctx = MagicMock()
    ctx.context = None
    mock_spec = json.dumps(
        {
            "openapi": "3.0.0",
            "paths": {
                "/api/users": {
                    "get": {"summary": "List users"},
                    "post": {"summary": "Create user"},
                },
                "/api/users/{id}": {
                    "get": {"summary": "Get user"},
                    "delete": {"summary": "Delete user"},
                },
            },
        }
    )
    with patch("kryon.tools.api_attacks.api_fuzzer._run_cmd") as mock_run:
        mock_run.return_value = mock_spec
        result = await parse_openapi_spec.on_invoke_tool(ctx, json.dumps({"spec_url": "http://test.com/openapi.json"}))
        data = json.loads(result)
        assert "endpoints" in data
        assert len(data["endpoints"]) >= 2


@pytest.mark.asyncio
async def test_discover_api_endpoints_uses_ffuf():
    from kryon.tools.api_attacks.api_fuzzer import discover_api_endpoints

    ctx = MagicMock()
    ctx.context = None
    with patch("kryon.tools.api_attacks.api_fuzzer._run_cmd") as mock_run:
        mock_run.return_value = json.dumps({"results": [{"url": "http://test.com/api/v1/users", "status": 200}]})
        result = await discover_api_endpoints.on_invoke_tool(ctx, json.dumps({"target_url": "http://test.com"}))
        assert "api" in result.lower() or "endpoint" in result.lower() or "results" in result.lower()


@pytest.mark.asyncio
async def test_test_idor_checks_multiple_ids():
    from kryon.tools.api_attacks.api_fuzzer import test_idor

    ctx = MagicMock()
    ctx.context = None
    with patch("kryon.tools.api_attacks.api_fuzzer._run_cmd") as mock_run:
        mock_run.return_value = 'HTTP/1.1 200 OK\n{"id": 2, "name": "other_user"}'
        result = await test_idor.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "base_url": "http://test.com/api/users/",
                    "id_param": "1",
                    "valid_id": "1",
                }
            ),
        )
        data = json.loads(result)
        assert "idor" in data.get("test_type", "").lower() or "status" in data
