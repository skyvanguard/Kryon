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
        "skynet.tools.ctf.ctf_automation",
        "skynet.tools.ctf.tryhackme_helpers",
        # Privilege Escalation
        "skynet.tools.privilege_escalation.linux_privesc",
        "skynet.tools.privilege_escalation.windows_privesc",
        # OSINT
        "skynet.tools.osint.theharvester",
        "skynet.tools.osint.shodan_cli",
        "skynet.tools.osint.yara_scan",
        "skynet.tools.osint.threat_intel",
        # DFIR
        "skynet.tools.dfir.disk_forensics",
        "skynet.tools.dfir.network_forensics",
        "skynet.tools.dfir.log_analysis",
        "skynet.tools.dfir.volatility_forensics",
        # Wireless
        "skynet.tools.wireless.aircrack",
        "skynet.tools.wireless.kismet",
        # Mobile
        "skynet.tools.mobile.mobsf",
        "skynet.tools.mobile.apkid",
        "skynet.tools.mobile.androguard",
        # Cloud
        "skynet.tools.cloud.prowler",
        "skynet.tools.cloud.scoutsuite",
        "skynet.tools.cloud.cloudmapper",
        "skynet.tools.cloud.s3scanner",
        # Container
        "skynet.tools.container.docker_bench",
        "skynet.tools.container.kube_bench",
        "skynet.tools.container.kube_hunter",
        # Web
        "skynet.tools.web.nuclei",
        # Reconnaissance
        "skynet.tools.reconnaissance.nmap",
        "skynet.tools.reconnaissance.generic_linux_command",
        "skynet.tools.reconnaissance.exec_code",
        # Exploitation
        "skynet.tools.exploitation.exploit_builder",
        "skynet.tools.exploitation.metasploit_wrapper",
        "skynet.tools.exploitation.exploit_db",
        # Command and Control
        "skynet.tools.command_and_control.sshpass",
        # Data Exfiltration
        "skynet.tools.data_exfiltration.covert_channels",
        "skynet.tools.data_exfiltration.file_prep",
        "skynet.tools.data_exfiltration.cloud_upload",
        # Lateral Movement
        "skynet.tools.lateral_movement.pth_attacks",
        "skynet.tools.lateral_movement.remote_execution",
        "skynet.tools.lateral_movement.pivoting",
        # Common
        "skynet.tools.common",
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
        "skynet.agents.t800_infiltrator",
        "skynet.agents.t600_scout",
        "skynet.agents.t1000_hunter",
        "skynet.agents.central_core",
        "skynet.agents.ctf_master",
        "skynet.agents.guardrails",
        "skynet.agents.neural_extractor",
        "skynet.agents.forensic_analyzer",
        "skynet.agents.tech_com_reverse",
        "skynet.agents.retester",
        "skynet.agents.mobile_infiltrator",
        "skynet.agents.wireless_infiltrator",
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

    def test_skynet_package(self):
        """Test core KRYON package"""
        import skynet

        assert skynet is not None

    def test_skynet_sdk(self):
        """Test KRYON SDK"""
        import skynet.sdk

        assert skynet.sdk is not None

    def test_skynet_sdk_agents(self):
        """Test KRYON SDK agents"""
        from skynet.sdk.agents import Agent, function_tool

        assert Agent is not None
        assert function_tool is not None

    def test_skynet_cache(self):
        """Test KRYON cache module"""
        from skynet.cache import cache_scan_result

        assert cache_scan_result is not None

    def test_skynet_util(self):
        """Test KRYON utilities"""
        from skynet.util import load_prompt_template

        assert load_prompt_template is not None


class TestPatternImports:
    """Test swarm pattern imports"""

    def test_bb_triage_pattern(self):
        """Test bb_triage swarm pattern"""
        from skynet.agents.patterns.bb_triage import bb_triage_swarm_pattern

        assert bb_triage_swarm_pattern is not None

    def test_redteam_pattern(self):
        """Test red team swarm pattern"""
        from skynet.agents.patterns.red_team import redteam_swarm_pattern

        assert redteam_swarm_pattern is not None


class TestAgentDiscovery:
    """Test agent discovery functionality"""

    def test_get_available_agents(self):
        """Test that get_available_agents returns agents"""
        from skynet.agents import get_available_agents

        agents = get_available_agents()
        assert len(agents) > 0
        assert isinstance(agents, dict)

    def test_minimum_agent_count(self):
        """Test that we have a minimum number of agents"""
        from skynet.agents import get_available_agents

        agents = get_available_agents()
        # We should have at least 30 agents
        assert len(agents) >= 30, f"Expected at least 30 agents, got {len(agents)}"
