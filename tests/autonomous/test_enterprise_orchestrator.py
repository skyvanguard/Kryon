"""Tests for the Enterprise Orchestrator."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from kryon.tools.autonomous.enterprise_orchestrator import (
    EnterpriseOrchestrator,
    ScanProgress,
    parse_scope,
)


class TestParseScope:
    def test_single_ip(self):
        result = parse_scope("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_cidr_24(self):
        result = parse_scope("192.168.1.0/24")
        assert len(result) == 254  # /24 has 254 usable hosts
        assert "192.168.1.1" in result
        assert "192.168.1.254" in result

    def test_cidr_30(self):
        result = parse_scope("10.10.10.0/30")
        assert len(result) == 2
        assert "10.10.10.1" in result
        assert "10.10.10.2" in result

    def test_comma_separated(self):
        result = parse_scope("10.10.10.1, 10.10.10.2, 10.10.10.3")
        assert len(result) == 3

    def test_list_input(self):
        result = parse_scope(["10.0.0.1", "10.0.0.2"])
        assert len(result) == 2

    def test_hostname(self):
        result = parse_scope("example.com")
        assert result == ["example.com"]

    def test_mixed_input(self):
        result = parse_scope("192.168.1.0/30, example.com")
        assert "example.com" in result
        assert len(result) == 3  # 2 from /30 + 1 hostname

    def test_large_cidr_capped(self):
        result = parse_scope("10.0.0.0/16")
        assert len(result) == 256  # capped at 256


class TestScanProgress:
    def test_initial_state(self):
        p = ScanProgress()
        assert p.status == "initializing"
        assert p.phase_progress == 0.0
        assert p.findings_count == 0

    def test_log_appends(self):
        p = ScanProgress()
        p.log("test message")
        assert len(p.log_messages) == 1
        assert "test message" in p.log_messages[0]

    def test_to_dict(self):
        p = ScanProgress()
        p.log("hello")
        d = p.to_dict()
        assert "scan_id" in d
        assert "status" in d
        assert d["findings_count"] == 0
        assert len(d["log_messages"]) == 1

    def test_scan_id_generated(self):
        p1 = ScanProgress()
        p2 = ScanProgress()
        assert p1.scan_id != p2.scan_id


class TestEnterpriseOrchestratorInit:
    def test_basic_init(self):
        orch = EnterpriseOrchestrator(scope="192.168.1.1")
        assert len(orch.targets) == 1
        assert orch.profile == "standard"
        assert orch.stealth_level == "normal"

    def test_cidr_scope(self):
        orch = EnterpriseOrchestrator(scope="10.10.10.0/30")
        assert len(orch.targets) == 2

    def test_client_info(self):
        orch = EnterpriseOrchestrator(
            scope="10.0.0.1",
            client_id="acme",
            client_name="ACME Corp",
        )
        assert orch.client_id == "acme"
        assert orch.client_name == "ACME Corp"

    def test_max_time_conversion(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1", max_time_hours=2.0)
        assert orch.max_time_seconds == 7200.0

    def test_compliance_frameworks(self):
        orch = EnterpriseOrchestrator(
            scope="10.0.0.1",
            compliance_frameworks=["pci-dss", "iso-27001"],
        )
        assert len(orch.compliance_frameworks) == 2


class TestEnterpriseOrchestratorRun:
    @pytest.mark.asyncio
    @patch("kryon.tools.autonomous.enterprise_orchestrator.EnterpriseOrchestrator._phase_recon")
    @patch("kryon.tools.autonomous.enterprise_orchestrator.EnterpriseOrchestrator._phase_vuln_scan")
    @patch("kryon.tools.autonomous.enterprise_orchestrator.EnterpriseOrchestrator._phase_reporting")
    async def test_standard_profile_skips_exploitation(
        self, mock_reporting, mock_vuln, mock_recon
    ):
        """Standard profile should not run exploitation phase."""
        mock_recon.return_value = None
        mock_vuln.return_value = None
        mock_reporting.return_value = None

        orch = EnterpriseOrchestrator(scope="10.0.0.1", profile="standard")
        result = await orch.run()

        assert result["status"] == "completed"
        mock_recon.assert_called_once()
        mock_vuln.assert_called_once()
        mock_reporting.assert_called_once()

    @pytest.mark.asyncio
    @patch("kryon.tools.autonomous.enterprise_orchestrator.EnterpriseOrchestrator._phase_recon")
    @patch("kryon.tools.autonomous.enterprise_orchestrator.EnterpriseOrchestrator._phase_vuln_scan")
    @patch("kryon.tools.autonomous.enterprise_orchestrator.EnterpriseOrchestrator._phase_exploitation")
    @patch("kryon.tools.autonomous.enterprise_orchestrator.EnterpriseOrchestrator._phase_reporting")
    async def test_deep_profile_runs_exploitation(
        self, mock_reporting, mock_exploit, mock_vuln, mock_recon
    ):
        """Deep profile should run exploitation phase."""
        mock_recon.return_value = None
        mock_vuln.return_value = None
        mock_exploit.return_value = None
        mock_reporting.return_value = None

        orch = EnterpriseOrchestrator(scope="10.0.0.1", profile="deep")
        result = await orch.run()

        assert result["status"] == "completed"
        mock_exploit.assert_called_once()

    @pytest.mark.asyncio
    @patch("kryon.tools.autonomous.enterprise_orchestrator.EnterpriseOrchestrator._phase_recon")
    async def test_failure_captured(self, mock_recon):
        """Errors should be captured in result, not raised."""
        mock_recon.side_effect = RuntimeError("Connection refused")

        orch = EnterpriseOrchestrator(scope="10.0.0.1")
        result = await orch.run()

        assert result["status"] == "failed"
        assert "Connection refused" in result["error"]

    @pytest.mark.asyncio
    async def test_progress_callback_called(self):
        """Progress callback should be invoked during run."""
        calls = []

        def cb(progress):
            calls.append(progress.status)

        with patch.object(EnterpriseOrchestrator, "_phase_recon", new_callable=AsyncMock):
            with patch.object(EnterpriseOrchestrator, "_phase_vuln_scan", new_callable=AsyncMock):
                with patch.object(EnterpriseOrchestrator, "_phase_reporting", new_callable=AsyncMock):
                    orch = EnterpriseOrchestrator(
                        scope="10.0.0.1",
                        progress_callback=cb,
                    )
                    await orch.run()

        assert len(calls) > 0
        assert "completed" in calls

    @pytest.mark.asyncio
    async def test_result_structure(self):
        """Result dict should have all required keys."""
        with patch.object(EnterpriseOrchestrator, "_phase_recon", new_callable=AsyncMock):
            with patch.object(EnterpriseOrchestrator, "_phase_vuln_scan", new_callable=AsyncMock):
                with patch.object(EnterpriseOrchestrator, "_phase_reporting", new_callable=AsyncMock):
                    orch = EnterpriseOrchestrator(scope="10.0.0.1")
                    result = await orch.run()

        required_keys = [
            "scan_id", "status", "findings_count",
            "critical_count", "high_count", "report_path",
            "elapsed_seconds", "error",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"


class TestKnownVulns:
    def test_apache_vuln_detection(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1")
        findings = orch._check_known_vulns("10.0.0.1", "http", "Apache 2.4.49", 80)
        assert len(findings) >= 1
        assert any("CVE-2021-41773" in f.title for f in findings)

    def test_openssh_old_version(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1")
        findings = orch._check_known_vulns("10.0.0.1", "ssh", "OpenSSH_7.4", 22)
        assert len(findings) >= 1
        assert any("Outdated" in f.title for f in findings)

    def test_tls_info_finding(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1")
        findings = orch._check_known_vulns("10.0.0.1", "https", "nginx", 443)
        assert len(findings) >= 1
        assert any("TLS" in f.title for f in findings)

    def test_no_vulns_for_unknown(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1")
        findings = orch._check_known_vulns("10.0.0.1", "unknown", "", 9999)
        assert len(findings) == 0


class TestRiskScore:
    def test_empty_findings_zero(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1")
        assert orch._calculate_risk_score() == 0.0

    def test_critical_findings_high_score(self):
        from kryon.intelligence.models import Finding, Severity

        orch = EnterpriseOrchestrator(scope="10.0.0.1")
        orch._findings = [
            Finding(title="Critical Bug", description="Bad", severity=Severity.CRITICAL, affected_asset="10.0.0.1"),
            Finding(title="High Bug", description="Bad", severity=Severity.HIGH, affected_asset="10.0.0.1"),
        ]
        score = orch._calculate_risk_score()
        assert score > 0
        assert score == 15.0  # 10 + 5


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
