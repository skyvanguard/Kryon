"""Tests for the Wazuh file-drop forwarder."""

from __future__ import annotations

import json

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem.wazuh import WazuhFileForwarder


def _cfg(path: str, **extra):
    return {"name": "test-wazuh", "endpoint": path, "config_json": extra}


def _event(**kwargs):
    defaults = {
        "event_type": "finding",
        "severity": "high",
        "title": "SQLi",
        "metadata": {"cwe": "CWE-89", "host": "10.0.0.5", "delta": "new"},
    }
    defaults.update(kwargs)
    return SIEMEvent(**defaults)


async def test_send_event_appends_json_line(tmp_path):
    path = str(tmp_path / "findings.json")
    fwd = WazuhFileForwarder(_cfg(path))
    assert await fwd.send_event(_event()) is True
    lines = (tmp_path / "findings.json").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    # metadata flattened to top level for Wazuh decoders
    assert rec["cwe"] == "CWE-89"
    assert rec["host"] == "10.0.0.5"
    assert rec["delta"] == "new"
    assert rec["severity"] == "high"


async def test_send_batch_appends_all(tmp_path):
    path = str(tmp_path / "out" / "findings.json")  # nested dir auto-created
    fwd = WazuhFileForwarder(_cfg(path))
    n = await fwd.send_batch([_event(title=f"f{i}") for i in range(3)])
    assert n == 3
    lines = (tmp_path / "out" / "findings.json").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3


async def test_write_failure_returns_false_not_raises(tmp_path):
    # endpoint points at a directory → open() for append fails
    fwd = WazuhFileForwarder(_cfg(str(tmp_path)))
    assert await fwd.send_event(_event()) is False


def test_should_forward_min_severity(tmp_path):
    fwd = WazuhFileForwarder(_cfg(str(tmp_path / "f.json"), min_severity="high"))
    assert fwd.should_forward(_event(severity="critical")) is True
    assert fwd.should_forward(_event(severity="low")) is False
