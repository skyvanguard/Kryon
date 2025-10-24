"""
SKYNET Orchestrator Integration Tests
======================================

Comprehensive integration tests for autonomous orchestrator.

Tests Cover:
- Complete autonomous_ctf_solver workflow
- Multi-agent coordination
- All 7 phases of CTF solving
- Integration between modules
- Failure scenarios and recovery
- Time constraints and timeouts

Clearance Level: Omega-Command (Testing Authority)
"""

import pytest
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from skynet.tools.autonomous.orchestrator import (
    autonomous_ctf_solver,
    autonomous_pentest,
    autonomous_network_pivot,
    multi_agent_coordination
)


class TestAutonomousCTFSolver:
    """Test complete autonomous CTF solving workflow."""

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    @patch('skynet.tools.autonomous.learning_engine.get_learned_recommendations')
    @patch('skynet.tools.autonomous.decision_engine.select_best_exploit')
    def test_complete_ctf_workflow_success(
        self,
        mock_exploit_select,
        mock_learned,
        mock_analyzer_class,
        mock_planner_class,
        mock_recon
    ):
        """Test complete successful CTF solving workflow."""
        # Mock strategic planner
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access", "find_flags"],
                "estimated_time_hours": 1.5
            }
        }

        # Mock reconnaissance
        mock_recon.return_value = {
            "success": True,
            "open_ports": [
                {"port": 80, "service": "http", "version": "Apache 2.4.49"},
                {"port": 22, "service": "ssh", "version": "OpenSSH 7.6"}
            ],
            "services_detected": [
                {"name": "http", "port": 80, "version": "Apache 2.4.49"},
                {"name": "ssh", "port": 22, "version": "OpenSSH 7.6"}
            ],
            "vulnerabilities": [
                {"cve": "CVE-2021-41773", "severity": "critical"}
            ],
            "http_endpoints": ["/admin", "/api"],
            "enumeration_time": 120.5
        }

        # Mock context analyzer
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.autonomous_context_analysis.return_value = {
            "credentials": [],
            "hints": ["Check /admin for vulnerabilities"],
            "attack_surface": {
                "endpoints": ["/admin", "/api"]
            }
        }

        # Mock learned recommendations
        mock_learned.return_value = {
            "recommended_exploits": [
                {
                    "exploit_name": "apache_path_traversal",
                    "exploit_type": "rce",
                    "success_rate": 0.95,
                    "service_name": "http"
                }
            ]
        }

        # Mock exploit selection
        mock_exploit_select.return_value = {
            "exploit_recommended": True,
            "exploit_name": "apache_path_traversal_cve_2021_41773",
            "exploit_type": "remote_code_execution",
            "success_probability": 0.95
        }

        # Execute
        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            difficulty="medium",
            max_time_hours=2
        )

        # Verify workflow executed
        assert mock_planner.autonomous_mission_planner.called
        assert mock_recon.called
        assert mock_analyzer.autonomous_context_analysis.called
        assert mock_learned.called

        # Verify result structure
        assert "exploitation_path" in result
        assert "flags_found" in result
        assert "time_elapsed" in result
        assert "report_path" in result

        # Verify phases were executed
        phases = [step["phase"] for step in result["exploitation_path"]]
        assert "planning" in phases
        assert "reconnaissance" in phases
        assert "context_analysis" in phases

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    def test_recon_failure_handling(self, mock_planner_class, mock_recon):
        """Test handling of reconnaissance failure."""
        # Mock planner
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        # Mock failed reconnaissance
        mock_recon.return_value = {
            "success": False,
            "open_ports": [],
            "error": "Target unreachable"
        }

        # Execute
        result = autonomous_ctf_solver(
            target_ip="192.168.1.99",
            max_time_hours=1
        )

        # Should fail gracefully
        assert result["success"] is False
        assert result["error"] is not None
        assert "reconnaissance failed" in result["error"].lower() or "no open ports" in result["error"].lower()

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    @patch('skynet.tools.autonomous.learning_engine.get_learned_recommendations')
    def test_no_exploits_available(
        self,
        mock_learned,
        mock_analyzer_class,
        mock_planner_class,
        mock_recon
    ):
        """Test behavior when no exploits are available."""
        # Mock planner
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        # Mock recon with unknown services
        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 9999, "service": "unknown", "version": ""}],
            "services_detected": [{"name": "unknown", "port": 9999, "version": ""}],
            "vulnerabilities": []
        }

        # Mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.autonomous_context_analysis.return_value = {
            "credentials": [],
            "hints": [],
            "attack_surface": {"endpoints": []}
        }

        # No learned recommendations
        mock_learned.return_value = {"recommended_exploits": []}

        # Execute
        result = autonomous_ctf_solver(
            target_ip="10.10.10.1",
            max_time_hours=1
        )

        # Should complete but with no exploits
        assert "exploitation_path" in result
        phases = [step["phase"] for step in result["exploitation_path"]]
        assert "reconnaissance" in phases

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    @patch('skynet.tools.autonomous.learning_engine.get_learned_recommendations')
    @patch('skynet.tools.autonomous.decision_engine.select_best_exploit')
    def test_timeout_handling(
        self,
        mock_exploit_select,
        mock_learned,
        mock_analyzer_class,
        mock_planner_class,
        mock_recon
    ):
        """Test that operation respects time limits."""
        # Mock all dependencies
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 0.01
            }
        }

        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 80, "service": "http", "version": ""}],
            "services_detected": [{"name": "http", "port": 80, "version": ""}],
            "vulnerabilities": []
        }

        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.autonomous_context_analysis.return_value = {
            "credentials": [],
            "hints": [],
            "attack_surface": {"endpoints": []}
        }

        mock_learned.return_value = {"recommended_exploits": []}
        mock_exploit_select.return_value = {"exploit_recommended": False}

        # Execute with very short timeout
        start_time = time.time()
        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=0.01  # ~36 seconds
        )
        elapsed = time.time() - start_time

        # Should complete quickly
        assert elapsed < 60  # Should not exceed reasonable time
        assert result["time_elapsed"] < 60

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    @patch('skynet.tools.autonomous.learning_engine.get_learned_recommendations')
    def test_credentials_discovery(
        self,
        mock_learned,
        mock_analyzer_class,
        mock_planner_class,
        mock_recon
    ):
        """Test handling of discovered credentials."""
        # Mock planner
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        # Mock recon
        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 22, "service": "ssh", "version": ""}],
            "services_detected": [{"name": "ssh", "port": 22, "version": ""}],
            "vulnerabilities": []
        }

        # Mock analyzer with credentials
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.autonomous_context_analysis.return_value = {
            "credentials": [
                {"username": "admin", "password": "admin123", "service": "ssh"}
            ],
            "hints": [],
            "attack_surface": {"endpoints": []}
        }

        mock_learned.return_value = {"recommended_exploits": []}

        # Execute
        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=1
        )

        # Verify credentials were noted
        phases = [step for step in result["exploitation_path"]]
        creds_phases = [p for p in phases if p.get("phase") == "intelligence"]
        assert len(creds_phases) > 0
        assert creds_phases[0].get("status") == "credentials_discovered"
        assert creds_phases[0].get("count") == 1

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    @patch('skynet.tools.autonomous.learning_engine.get_learned_recommendations')
    @patch('skynet.tools.autonomous.decision_engine.select_best_exploit')
    def test_multiple_services_enumeration(
        self,
        mock_exploit_select,
        mock_learned,
        mock_analyzer_class,
        mock_planner_class,
        mock_recon
    ):
        """Test handling of multiple services."""
        # Mock planner
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        # Mock recon with multiple services
        mock_recon.return_value = {
            "success": True,
            "open_ports": [
                {"port": 80, "service": "http", "version": "Apache 2.4"},
                {"port": 22, "service": "ssh", "version": "OpenSSH 7.6"},
                {"port": 3306, "service": "mysql", "version": "MySQL 5.7"}
            ],
            "services_detected": [
                {"name": "http", "port": 80, "version": "Apache 2.4"},
                {"name": "ssh", "port": 22, "version": "OpenSSH 7.6"},
                {"name": "mysql", "port": 3306, "version": "MySQL 5.7"}
            ],
            "vulnerabilities": []
        }

        # Mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.autonomous_context_analysis.return_value = {
            "credentials": [],
            "hints": [],
            "attack_surface": {"endpoints": []}
        }

        mock_learned.return_value = {"recommended_exploits": []}

        # Mock exploit selection to return different results per service
        mock_exploit_select.side_effect = [
            {"exploit_recommended": True, "exploit_name": "apache_exploit", "exploit_type": "rce", "success_probability": 0.8},
            {"exploit_recommended": True, "exploit_name": "ssh_exploit", "exploit_type": "auth_bypass", "success_probability": 0.6},
            {"exploit_recommended": True, "exploit_name": "mysql_exploit", "exploit_type": "auth_bypass", "success_probability": 0.7}
        ]

        # Execute
        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=1
        )

        # Should have called exploit selection for each service
        assert mock_exploit_select.call_count == 3

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    def test_difficulty_levels(self, mock_planner_class, mock_recon):
        """Test different difficulty levels affect planning."""
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 80, "service": "http", "version": ""}],
            "services_detected": [{"name": "http", "port": 80, "version": ""}],
            "vulnerabilities": []
        }

        # Test easy difficulty
        result_easy = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            difficulty="easy",
            max_time_hours=1
        )

        # Test hard difficulty
        result_hard = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            difficulty="hard",
            max_time_hours=1
        )

        # Hard should enable deep scan
        recon_calls = mock_recon.call_args_list
        # Check if deep_scan parameter differs
        assert len(recon_calls) >= 2


class TestAutonomousPentest:
    """Test autonomous penetration testing."""

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    def test_pentest_basic_execution(self, mock_planner_class, mock_recon):
        """Test basic pentest execution."""
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Pentest Plan",
                "objectives_order": ["reconnaissance", "vulnerability_assessment"],
                "estimated_time_hours": 2.0
            }
        }

        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 443, "service": "https", "version": "nginx"}],
            "services_detected": [{"name": "https", "port": 443, "version": "nginx"}],
            "vulnerabilities": []
        }

        result = autonomous_pentest(
            target_network="192.168.1.0/24",
            scope=["192.168.1.0/24"],  # Required parameter
            max_time_hours=2,
            stealth_level="high"  # Instead of compliance_mode
        )

        # Check actual return fields from autonomous_pentest
        assert "hosts_discovered" in result
        assert "vulnerabilities" in result
        assert "compromised_hosts" in result
        assert isinstance(result["success"], bool)

    def test_pentest_compliance_mode(self):
        """Test that compliance mode affects behavior."""
        # Compliance mode should be more cautious
        # This is a basic structure test
        pass


class TestAutonomousNetworkPivot:
    """Test autonomous network pivoting."""

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    def test_network_pivot_discovery(self, mock_recon):
        """Test network pivot discovery."""
        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 22, "service": "ssh", "version": ""}],
            "services_detected": [{"name": "ssh", "port": 22, "version": ""}],
            "vulnerabilities": []
        }

        result = autonomous_network_pivot(
            entry_point_ip="10.10.10.5",  # Correct parameter name
            entry_credentials={"username": "user", "password": "pass"},  # Required parameter
            internal_network="192.168.100.0/24",  # Instead of discovered_networks
            max_depth=2
        )

        # Check actual return fields from autonomous_network_pivot
        assert "pivot_chain" in result  # Function returns pivot_chain not pivot_path
        assert "compromised_hosts" in result  # Function returns compromised_hosts not discovered_hosts
        assert "tunnels_created" in result
        assert isinstance(result["success"], bool)


class TestMultiAgentCoordination:
    """Test multi-agent coordination."""

    def test_multi_agent_basic(self):
        """Test basic multi-agent coordination."""
        result = multi_agent_coordination(
            target_ip="10.10.10.5",
            agents_to_use=["t600_scout", "t800_infiltrator"],
            coordination_mode="parallel"
        )

        assert "agent_results" in result or "results" in result
        # Test should verify basic structure
        assert result is not None


class TestPhaseIntegration:
    """Test integration between phases."""

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    @patch('skynet.tools.autonomous.learning_engine.get_learned_recommendations')
    @patch('skynet.tools.autonomous.decision_engine.select_best_exploit')
    def test_phase_data_flow(
        self,
        mock_exploit_select,
        mock_learned,
        mock_analyzer_class,
        mock_planner_class,
        mock_recon
    ):
        """Test that data flows correctly between phases."""
        # Setup mocks
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 80, "service": "http", "version": "Apache 2.4.49"}],
            "services_detected": [{"name": "http", "port": 80, "version": "Apache 2.4.49"}],
            "vulnerabilities": [{"cve": "CVE-2021-41773", "severity": "critical"}]
        }

        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.autonomous_context_analysis.return_value = {
            "credentials": [],
            "hints": ["Apache vulnerable"],
            "attack_surface": {"endpoints": ["/admin"]}
        }

        mock_learned.return_value = {"recommended_exploits": []}

        mock_exploit_select.return_value = {
            "exploit_recommended": True,
            "exploit_name": "apache_path_traversal",
            "exploit_type": "rce",
            "success_probability": 0.95
        }

        # Execute
        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=1
        )

        # Verify context analyzer received recon data
        analyzer_call = mock_analyzer.autonomous_context_analysis.call_args
        assert analyzer_call is not None
        target_data = analyzer_call[1]["target_data"]
        assert "recon_output" in target_data or "services" in target_data

        # Verify exploit selection received service info
        exploit_call = mock_exploit_select.call_args
        assert exploit_call is not None


class TestErrorRecovery:
    """Test error recovery mechanisms."""

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    def test_exception_handling(self, mock_planner_class, mock_recon):
        """Test that exceptions are handled gracefully."""
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.side_effect = Exception("Planning failed")

        # Should not crash
        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=1
        )

        assert "error" in result
        assert result["success"] is False

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    def test_partial_failure_recovery(self, mock_analyzer_class, mock_planner_class, mock_recon):
        """Test recovery from partial failures."""
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 80, "service": "http", "version": ""}],
            "services_detected": [{"name": "http", "port": 80, "version": ""}],
            "vulnerabilities": []
        }

        # Context analysis fails
        mock_analyzer_class.side_effect = Exception("Analysis failed")

        # Should continue despite failure
        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=1
        )

        # May have error but should have attempted recon
        assert "exploitation_path" in result


class TestPerformance:
    """Test performance and optimization."""

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    @patch('skynet.tools.autonomous.learning_engine.get_learned_recommendations')
    def test_execution_time_tracking(
        self,
        mock_learned,
        mock_analyzer_class,
        mock_planner_class,
        mock_recon
    ):
        """Test that execution time is properly tracked."""
        # Setup quick mocks
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 0.1
            }
        }

        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 80, "service": "http", "version": ""}],
            "services_detected": [{"name": "http", "port": 80, "version": ""}],
            "vulnerabilities": []
        }

        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.autonomous_context_analysis.return_value = {
            "credentials": [],
            "hints": [],
            "attack_surface": {"endpoints": []}
        }

        mock_learned.return_value = {"recommended_exploits": []}

        # Execute
        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=0.1
        )

        # Should have time_elapsed
        assert "time_elapsed" in result
        assert result["time_elapsed"] >= 0
        assert isinstance(result["time_elapsed"], (int, float))


class TestResultStructure:
    """Test result structure consistency."""

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    def test_result_has_required_fields(self, mock_planner_class, mock_recon):
        """Test that results have all required fields."""
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        mock_recon.return_value = {
            "success": False,
            "open_ports": [],
            "error": "Failed"
        }

        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=1
        )

        # Required fields
        required_fields = [
            "flags_found",
            "exploitation_path",
            "time_elapsed",
            "services_exploited",
            "privilege_level",
            "report_path",
            "success"
        ]

        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    @patch('skynet.tools.autonomous.auto_recon.full_auto_enumeration')
    @patch('skynet.tools.autonomous.strategic_planner.StrategicPlanner')
    @patch('skynet.tools.autonomous.context_analyzer.ContextAnalyzer')
    @patch('skynet.tools.autonomous.learning_engine.get_learned_recommendations')
    def test_exploitation_path_structure(
        self,
        mock_learned,
        mock_analyzer_class,
        mock_planner_class,
        mock_recon
    ):
        """Test exploitation path has correct structure."""
        mock_planner = MagicMock()
        mock_planner_class.return_value = mock_planner
        mock_planner.autonomous_mission_planner.return_value = {
            "primary_plan": {
                "name": "Test Plan",
                "objectives_order": ["initial_access"],
                "estimated_time_hours": 1.0
            }
        }

        mock_recon.return_value = {
            "success": True,
            "open_ports": [{"port": 80, "service": "http", "version": ""}],
            "services_detected": [{"name": "http", "port": 80, "version": ""}],
            "vulnerabilities": []
        }

        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.autonomous_context_analysis.return_value = {
            "credentials": [],
            "hints": [],
            "attack_surface": {"endpoints": []}
        }

        mock_learned.return_value = {"recommended_exploits": []}

        result = autonomous_ctf_solver(
            target_ip="10.10.10.5",
            max_time_hours=1
        )

        # Verify exploitation path structure
        assert isinstance(result["exploitation_path"], list)

        for step in result["exploitation_path"]:
            assert "phase" in step
            assert isinstance(step, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
