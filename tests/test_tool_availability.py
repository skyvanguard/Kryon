"""
Tool Availability and Validation Tests

Tests that verify all KRYON tools are properly configured,
dependencies are available, and tools can be imported successfully.
"""

import importlib
import os

import pytest

# Set placeholder API key for tests
os.environ.setdefault("OPENAI_API_KEY", "sk-placeholder-for-testing")


class TestToolImports:
    """Test that all tool modules can be imported"""

    # List of core tool modules that should be importable
    TOOL_MODULES = [
        # CTF Tools
        "kryon.tools.ctf.ctf_automation",
        "kryon.tools.ctf.tryhackme_helpers",
        # Privilege Escalation
        "kryon.tools.privilege_escalation.linux_privesc",
        "kryon.tools.privilege_escalation.windows_privesc",
        # OSINT
        "kryon.tools.osint.theharvester",
        "kryon.tools.osint.shodan_cli",
        "kryon.tools.osint.yara_scan",
        "kryon.tools.osint.threat_intel",
        # DFIR
        "kryon.tools.dfir.disk_forensics",
        "kryon.tools.dfir.network_forensics",
        "kryon.tools.dfir.log_analysis",
        "kryon.tools.dfir.volatility_forensics",
        # Wireless
        "kryon.tools.wireless.aircrack",
        "kryon.tools.wireless.kismet",
        # Mobile
        "kryon.tools.mobile.mobsf",
        "kryon.tools.mobile.apkid",
        "kryon.tools.mobile.androguard",
        # Cloud
        "kryon.tools.cloud.prowler",
        "kryon.tools.cloud.scoutsuite",
        "kryon.tools.cloud.cloudmapper",
        "kryon.tools.cloud.s3scanner",
        # Container
        "kryon.tools.container.docker_bench",
        "kryon.tools.container.kube_bench",
        "kryon.tools.container.kube_hunter",
        # Web
        "kryon.tools.web.nuclei",
        # Reconnaissance
        "kryon.tools.reconnaissance.nmap",
        "kryon.tools.reconnaissance.run_command",
        "kryon.tools.reconnaissance.exec_code",
        # Exploitation
        "kryon.tools.exploitation.exploit_builder",
        "kryon.tools.exploitation.metasploit_wrapper",
        "kryon.tools.exploitation.exploit_db",
        # Command and Control
        "kryon.tools.command_and_control.sshpass",
        # Data Exfiltration
        "kryon.tools.data_exfiltration.covert_channels",
        "kryon.tools.data_exfiltration.file_prep",
        "kryon.tools.data_exfiltration.cloud_upload",
        # Lateral Movement
        "kryon.tools.lateral_movement.pth_attacks",
        "kryon.tools.lateral_movement.remote_execution",
        "kryon.tools.lateral_movement.pivoting",
        # Common
        "kryon.tools.common",
    ]

    @pytest.mark.parametrize("module_name", TOOL_MODULES)
    def test_tool_module_imports(self, module_name: str):
        """Test that each tool module can be imported"""
        try:
            module = importlib.import_module(module_name)
            assert module is not None
        except ImportError as e:
            pytest.fail(f"Failed to import {module_name}: {str(e)}")


class TestAgentImports:
    """Test that all agent modules can be imported"""

    AGENT_MODULES = [
        "kryon.agents.pentest_agent",
        "kryon.agents.recon_scout",
        "kryon.agents.vuln_hunter",
        "kryon.agents.central_core",
        "kryon.agents.ctf_master",
        "kryon.agents.guardrails",
        "kryon.agents.forensic_analyzer",
        "kryon.agents.reverse_engineer",
        "kryon.agents.retester",
        "kryon.agents.mobile_infiltrator",
        "kryon.agents.wireless_infiltrator",
    ]

    @pytest.mark.parametrize("module_name", AGENT_MODULES)
    def test_agent_module_imports(self, module_name: str):
        """Test that each agent module can be imported"""
        try:
            module = importlib.import_module(module_name)
            assert module is not None
        except ImportError as e:
            pytest.fail(f"Failed to import {module_name}: {str(e)}")


class TestCoreImports:
    """Test core KRYON package imports"""

    def test_kryon_package(self):
        """Test core KRYON package"""
        import kryon

        assert kryon is not None

    def test_kryon_sdk(self):
        """Test KRYON SDK"""
        import kryon.sdk

        assert kryon.sdk is not None

    def test_kryon_sdk_agents(self):
        """Test KRYON SDK agents"""
        from kryon.sdk.agents import Agent, function_tool

        assert Agent is not None
        assert function_tool is not None

    def test_kryon_cache(self):
        """Test KRYON cache module"""
        from kryon.cache import cache_scan_result

        assert cache_scan_result is not None

    def test_kryon_util(self):
        """Test KRYON utilities"""
        from kryon.util import load_prompt_template

        assert load_prompt_template is not None


class TestPatternImports:
    """Test swarm pattern imports"""

    def test_bb_triage_pattern(self):
        """Test bb_triage swarm pattern"""
        from kryon.agents.patterns.bb_triage import bb_triage_swarm_pattern

        assert bb_triage_swarm_pattern is not None

    def test_redteam_pattern(self):
        """Test red team swarm pattern"""
        from kryon.agents.patterns.red_team import redteam_swarm_pattern

        assert redteam_swarm_pattern is not None


class TestAgentDiscovery:
    """Test agent discovery functionality"""

    def test_get_available_agents(self):
        """Test that get_available_agents returns agents"""
        from kryon.agents import get_available_agents

        agents = get_available_agents()
        assert len(agents) > 0
        assert isinstance(agents, dict)

    def test_minimum_agent_count(self):
        """Test that we have a minimum number of agents"""
        from kryon.agents import get_available_agents

        agents = get_available_agents()
        # After deduplication: 18 core agents + 3 patterns = ~21
        assert len(agents) >= 18, f"Expected at least 18 agents, got {len(agents)}"
