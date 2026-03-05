"""
Tests for Active Directory attack tools.
Task 5.1 - AD Infiltrator: BloodHound, Kerberoast, ASREPRoast, AD enum, DCSync, attack paths.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from kryon.sdk.agents import FunctionTool


def test_bloodhound_collect_exists():
    from kryon.tools.lateral_movement.ad_attacks import bloodhound_collect

    assert isinstance(bloodhound_collect, FunctionTool)


def test_kerberoast_exists():
    from kryon.tools.lateral_movement.ad_attacks import kerberoast

    assert isinstance(kerberoast, FunctionTool)


def test_asreproast_exists():
    from kryon.tools.lateral_movement.ad_attacks import asreproast

    assert isinstance(asreproast, FunctionTool)


def test_enumerate_ad_exists():
    from kryon.tools.lateral_movement.ad_attacks import enumerate_ad

    assert isinstance(enumerate_ad, FunctionTool)


def test_dcsync_attack_exists():
    from kryon.tools.lateral_movement.ad_attacks import dcsync_attack

    assert isinstance(dcsync_attack, FunctionTool)


def test_find_attack_path_exists():
    from kryon.tools.lateral_movement.ad_attacks import find_attack_path

    assert isinstance(find_attack_path, FunctionTool)


@pytest.mark.asyncio
async def test_kerberoast_runs_impacket():
    from kryon.tools.lateral_movement.ad_attacks import kerberoast

    ctx = MagicMock()
    ctx.context = None
    with patch("kryon.tools.lateral_movement.ad_attacks._run_cmd") as mock_run:
        mock_run.return_value = "$krb5tgs$23$*svc_sql$CORP.LOCAL$..."
        result = await kerberoast.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "domain_controller": "dc01.corp.local",
                    "domain": "corp.local",
                    "username": "user",
                    "password": "pass",
                }
            ),
        )
        data = json.loads(result)
        assert "tickets" in data or "results" in data or "output" in data
        assert mock_run.called


@pytest.mark.asyncio
async def test_enumerate_ad_runs_enumeration():
    from kryon.tools.lateral_movement.ad_attacks import enumerate_ad

    ctx = MagicMock()
    ctx.context = None
    with patch("kryon.tools.lateral_movement.ad_attacks._run_cmd") as mock_run:
        mock_run.return_value = (
            "Users: Administrator, Guest, krbtgt\nGroups: Domain Admins, Domain Users"
        )
        result = await enumerate_ad.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "domain_controller": "dc01.corp.local",
                    "domain": "corp.local",
                }
            ),
        )
        data = json.loads(result)
        assert (
            "enumeration" in data
            or "results" in data
            or "users" in data
            or "output" in data
        )


@pytest.mark.asyncio
async def test_find_attack_path_returns_path():
    from kryon.tools.lateral_movement.ad_attacks import find_attack_path

    ctx = MagicMock()
    ctx.context = None
    with patch("kryon.tools.lateral_movement.ad_attacks._run_cmd") as mock_run:
        mock_run.return_value = json.dumps(
            {
                "paths": [
                    {
                        "start": "user@corp.local",
                        "end": "Domain Admins",
                        "hops": 3,
                    }
                ]
            }
        )
        result = await find_attack_path.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "start_node": "user@corp.local",
                    "target_node": "Domain Admins",
                }
            ),
        )
        data = json.loads(result)
        assert "paths" in data or "attack_path" in data or "results" in data
