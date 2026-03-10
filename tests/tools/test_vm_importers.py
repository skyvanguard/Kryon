"""Tests for VM scanner import tools (Qualys, Tenable, Rapid7, nmap XML, nuclei JSONL)."""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from kryon.sdk.agents import FunctionTool


def test_import_qualys_exists():
    from kryon.tools.intelligence.vm_importers import import_qualys_findings

    assert isinstance(import_qualys_findings, FunctionTool)


def test_import_tenable_exists():
    from kryon.tools.intelligence.vm_importers import import_tenable_findings

    assert isinstance(import_tenable_findings, FunctionTool)


def test_import_rapid7_exists():
    from kryon.tools.intelligence.vm_importers import import_rapid7_findings

    assert isinstance(import_rapid7_findings, FunctionTool)


def test_import_nmap_xml_exists():
    from kryon.tools.intelligence.vm_importers import import_nmap_xml

    assert isinstance(import_nmap_xml, FunctionTool)


def test_import_nuclei_jsonl_exists():
    from kryon.tools.intelligence.vm_importers import import_nuclei_jsonl

    assert isinstance(import_nuclei_jsonl, FunctionTool)


@pytest.mark.asyncio
async def test_import_qualys_parses_response():
    from kryon.tools.intelligence.vm_importers import import_qualys_findings

    ctx = MagicMock()
    ctx.context = None
    mock_response = json.dumps(
        {
            "HOST_LIST_VM_DETECTION_OUTPUT": {
                "RESPONSE": {
                    "HOST_LIST": {
                        "HOST": [
                            {
                                "IP": "192.168.1.1",
                                "DETECTION_LIST": {
                                    "DETECTION": [
                                        {
                                            "QID": "38173",
                                            "SEVERITY": "4",
                                            "TITLE": "SSL Certificate Expired",
                                        }
                                    ]
                                },
                            }
                        ]
                    }
                }
            }
        }
    )
    with (
        patch("kryon.tools.intelligence.vm_importers._http_request") as mock_req,
        patch("kryon.tools.intelligence.vm_importers.validate_external_url", return_value=None),
    ):
        mock_req.return_value = mock_response
        result = await import_qualys_findings.on_invoke_tool(
            ctx,
            json.dumps({"api_url": "https://qualys.example.com", "api_key": "test123"}),
        )
        data = json.loads(result)
        assert "findings" in data
        assert data["source"] == "qualys"


@pytest.mark.asyncio
async def test_import_tenable_parses_response():
    from kryon.tools.intelligence.vm_importers import import_tenable_findings

    ctx = MagicMock()
    ctx.context = None
    mock_response = json.dumps(
        {
            "vulnerabilities": [
                {
                    "plugin_id": 12345,
                    "plugin_name": "Apache HTTP Server RCE",
                    "severity": 4,
                    "host_id": 1,
                    "hostname": "192.168.1.10",
                }
            ]
        }
    )
    with (
        patch("kryon.tools.intelligence.vm_importers._http_request") as mock_req,
        patch("kryon.tools.intelligence.vm_importers.validate_external_url", return_value=None),
    ):
        mock_req.return_value = mock_response
        result = await import_tenable_findings.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "api_url": "https://cloud.tenable.com",
                    "access_key": "ak123",
                    "secret_key": "sk456",
                    "scan_id": "100",
                }
            ),
        )
        data = json.loads(result)
        assert "findings" in data
        assert data["source"] == "tenable"


@pytest.mark.asyncio
async def test_import_rapid7_parses_response():
    from kryon.tools.intelligence.vm_importers import import_rapid7_findings

    ctx = MagicMock()
    ctx.context = None
    mock_response = json.dumps(
        {
            "resources": [
                {
                    "id": "vuln-001",
                    "title": "OpenSSH Vulnerability",
                    "severity": "Critical",
                    "instances": 3,
                }
            ]
        }
    )
    with (
        patch("kryon.tools.intelligence.vm_importers._http_request") as mock_req,
        patch("kryon.tools.intelligence.vm_importers.validate_external_url", return_value=None),
    ):
        mock_req.return_value = mock_response
        result = await import_rapid7_findings.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "api_url": "https://insightvm.example.com",
                    "api_key": "r7key",
                    "site_id": "5",
                }
            ),
        )
        data = json.loads(result)
        assert "findings" in data
        assert data["source"] == "rapid7"


@pytest.mark.asyncio
async def test_import_nmap_xml_parses_file():
    from kryon.tools.intelligence.vm_importers import import_nmap_xml

    ctx = MagicMock()
    ctx.context = None
    mock_xml = """<?xml version="1.0"?>
    <nmaprun><host><address addr="192.168.1.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports>
    </host></nmaprun>"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(mock_xml)
        tmp_path = f.name
    try:
        result = await import_nmap_xml.on_invoke_tool(ctx, json.dumps({"xml_file": tmp_path}))
        data = json.loads(result)
        assert "findings" in data
        assert data["source"] == "nmap"
        assert len(data["findings"]) >= 1
    finally:
        os.unlink(tmp_path)


@pytest.mark.asyncio
async def test_import_nuclei_jsonl_parses_file():
    from kryon.tools.intelligence.vm_importers import import_nuclei_jsonl

    ctx = MagicMock()
    ctx.context = None
    lines = [
        json.dumps(
            {
                "info": {"name": "XSS Detection", "severity": "high"},
                "host": "http://test.com",
                "matched-at": "http://test.com/search",
            }
        ),
        json.dumps(
            {
                "info": {"name": "SQLi Detection", "severity": "critical"},
                "host": "http://test.com",
                "matched-at": "http://test.com/login",
            }
        ),
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(lines))
        tmp_path = f.name
    try:
        result = await import_nuclei_jsonl.on_invoke_tool(ctx, json.dumps({"jsonl_file": tmp_path}))
        data = json.loads(result)
        assert "findings" in data
        assert len(data["findings"]) == 2
        assert data["source"] == "nuclei"
    finally:
        os.unlink(tmp_path)
