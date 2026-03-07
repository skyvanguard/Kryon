"""Tests for CLIFindingsCollector."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from kryon.cli.findings_collector import CLIFindingsCollector
from kryon.intelligence.models import Finding, Severity


class TestExtractFromMessageHistory:
    """Test finding extraction from agent message histories."""

    def test_empty_messages_returns_empty(self):
        collector = CLIFindingsCollector()
        assert collector.extract_from_message_history([]) == []

    def test_no_findings_in_irrelevant_messages(self):
        collector = CLIFindingsCollector()
        messages = [
            {"role": "assistant", "content": "Hello, how can I help?"},
            {"role": "user", "content": "Scan this network"},
        ]
        assert collector.extract_from_message_history(messages) == []

    def test_extracts_cve_from_tool_output(self):
        collector = CLIFindingsCollector()
        messages = [
            {
                "role": "tool",
                "content": "Found critical vulnerability CVE-2021-44228 on target 10.0.0.1 port 8080",
            },
        ]
        findings = collector.extract_from_message_history(messages)
        assert len(findings) == 1
        assert "CVE-2021-44228" in findings[0].title

    def test_extracts_json_finding_from_content(self):
        collector = CLIFindingsCollector()
        finding_json = json.dumps({
            "title": "SQL Injection vulnerability",
            "description": "Possible SQLi in login form",
            "severity": "high",
            "affected_asset": "10.0.0.1:443",
            "cvss_score": 8.5,
        })
        messages = [
            {"role": "tool", "content": f"Found vulnerability: {finding_json}"},
        ]
        findings = collector.extract_from_message_history(messages)
        assert len(findings) == 1
        assert findings[0].title == "SQL Injection vulnerability"
        assert findings[0].severity == Severity.HIGH

    def test_deduplication_by_id(self):
        collector = CLIFindingsCollector()
        messages = [
            {"role": "tool", "content": "Found vulnerability CVE-2021-44228 critical issue"},
        ]
        first = collector.extract_from_message_history(messages)
        # Same messages again
        second = collector.extract_from_message_history(messages)
        assert len(first) == 1
        assert len(second) == 0  # Already seen

    def test_non_string_content_is_skipped(self):
        collector = CLIFindingsCollector()
        messages = [
            {"role": "tool", "content": 12345},
            {"role": "tool", "content": None},
            {"role": "tool", "content": ["list"]},
        ]
        assert collector.extract_from_message_history(messages) == []

    def test_keyword_vuln_triggers_parsing(self):
        collector = CLIFindingsCollector()
        messages = [
            {"role": "tool", "content": "Vulnerability scan complete: CVE-2023-12345 medium severity"},
        ]
        findings = collector.extract_from_message_history(messages)
        assert len(findings) == 1


class TestSaveFindings:
    """Test finding persistence."""

    def test_save_findings_calls_store(self):
        mock_store = MagicMock()
        collector = CLIFindingsCollector(store=mock_store)

        findings = [
            Finding(
                title="Test Finding",
                description="A test",
                severity=Severity.HIGH,
                affected_asset="10.0.0.1",
            ),
        ]
        count = collector.save_findings(findings)
        assert count == 1
        mock_store.save_finding.assert_called_once()
        record = mock_store.save_finding.call_args[0][0]
        assert record.scan_id == collector.scan_id
        assert record.client_id == "cli-session"
        assert record.status == "open"

    def test_save_empty_list(self):
        mock_store = MagicMock()
        collector = CLIFindingsCollector(store=mock_store)
        assert collector.save_findings([]) == 0
        mock_store.save_finding.assert_not_called()


class TestScanId:
    """Scan ID properties."""

    def test_scan_id_is_12_chars(self):
        collector = CLIFindingsCollector()
        assert len(collector.scan_id) == 12

    def test_scan_id_is_stable(self):
        collector = CLIFindingsCollector()
        assert collector.scan_id == collector.scan_id
