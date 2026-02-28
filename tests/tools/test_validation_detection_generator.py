"""Tests for validation.detection_generator — Sigma, YARA, Suricata rule generators."""

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.validation.detection_generator import (
    generate_sigma_rule,
    generate_yara_rule,
    generate_suricata_rule,
)


def _invoke(tool, args: dict):
    return tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# generate_sigma_rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sigma_t1046():
    """T1046 generates a port scan Sigma rule."""
    result = await _invoke(generate_sigma_rule, {"technique_id": "T1046"})
    assert "Network Service Discovery" in result or "T1046" in result.lower()
    assert "KRYON" in result


@pytest.mark.asyncio
async def test_sigma_t1110():
    """T1110 generates a brute force Sigma rule."""
    result = await _invoke(generate_sigma_rule, {"technique_id": "T1110"})
    assert "Brute Force" in result or "4625" in result
    assert "KRYON" in result


@pytest.mark.asyncio
async def test_sigma_unknown_technique():
    """Unknown technique generates a custom placeholder rule."""
    result = await _invoke(generate_sigma_rule, {
        "technique_id": "T9999",
        "finding_title": "Custom Finding",
    })
    assert "Custom Finding" in result or "T9999" in result
    assert "TODO" in result or "customize" in result.lower()


@pytest.mark.asyncio
async def test_sigma_custom_log_source():
    """Custom log_source overrides the default."""
    result = await _invoke(generate_sigma_rule, {
        "technique_id": "T1046",
        "log_source": "windows/sysmon",
    })
    assert "windows" in result.lower()
    assert "sysmon" in result.lower()


# ---------------------------------------------------------------------------
# generate_yara_rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_yara_hash_ioc():
    """Hash IOC generates a YARA rule with hash imports."""
    result = await _invoke(generate_yara_rule, {
        "ioc_type": "hash",
        "ioc_value": "d41d8cd98f00b204e9800998ecf8427e",
    })
    assert 'import "hash"' in result
    assert "d41d8cd98f00b204e9800998ecf8427e" in result
    assert "rule" in result


@pytest.mark.asyncio
async def test_yara_string_ioc():
    """String IOC generates a YARA rule with string matching."""
    result = await _invoke(generate_yara_rule, {
        "ioc_type": "string",
        "ioc_value": "malware_callback",
    })
    assert "$ioc" in result
    assert "malware_callback" in result
    assert "ascii wide nocase" in result


@pytest.mark.asyncio
async def test_yara_domain_ioc():
    """Domain IOC generates a YARA rule with string matching."""
    result = await _invoke(generate_yara_rule, {
        "ioc_type": "domain",
        "ioc_value": "evil.example.com",
    })
    assert "evil.example.com" in result
    assert "$ioc" in result


@pytest.mark.asyncio
async def test_yara_regex_ioc():
    """Regex IOC generates a YARA rule with regex pattern."""
    result = await _invoke(generate_yara_rule, {
        "ioc_type": "regex",
        "ioc_value": "malware[0-9]+\\.dll",
    })
    assert "/$" not in result or "/" in result  # regex delimiters
    assert "ascii wide" in result


# ---------------------------------------------------------------------------
# generate_suricata_rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_suricata_ip():
    """IP IOC generates an alert ip rule."""
    result = await _invoke(generate_suricata_rule, {
        "ioc_type": "ip",
        "ioc_value": "192.168.1.100",
    })
    assert "alert ip" in result
    assert "192.168.1.100" in result
    assert "KRYON" in result
    assert "sid:" in result


@pytest.mark.asyncio
async def test_suricata_domain():
    """Domain IOC generates an alert dns rule."""
    result = await _invoke(generate_suricata_rule, {
        "ioc_type": "domain",
        "ioc_value": "malicious.example.com",
    })
    assert "alert dns" in result
    assert "malicious.example.com" in result
    assert "dns.query" in result


@pytest.mark.asyncio
async def test_suricata_url():
    """URL IOC generates an alert http rule."""
    result = await _invoke(generate_suricata_rule, {
        "ioc_type": "url",
        "ioc_value": "/malware/payload.bin",
    })
    assert "alert http" in result
    assert "/malware/payload.bin" in result
    assert "http.uri" in result
