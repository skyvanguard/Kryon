#!/usr/bin/env python3
"""
KRYON Framework - Import and Compatibility Test Suite
======================================================

Tests all critical imports for the KRYON framework.
"""

import os

# Set placeholder API key for tests
os.environ.setdefault("OPENAI_API_KEY", "sk-placeholder-for-testing")


class TestCoreImports:
    """Test core KRYON package imports."""

    def test_skynet_package(self):
        """Test core KRYON package import."""
        import kryon

        assert skynet is not None

    def test_skynet_sdk(self):
        """Test KRYON SDK import."""
        import kryon.sdk

        assert kryon.sdk is not None

    def test_skynet_sdk_agents(self):
        """Test KRYON SDK agents module import."""
        import kryon.sdk.agents

        assert kryon.sdk.agents is not None

    def test_skynet_tools(self):
        """Test KRYON tools module import."""
        import kryon.tools

        assert kryon.tools is not None

    def test_skynet_cache(self):
        """Test KRYON cache module import."""
        from kryon.cache import cache_scan_result

        assert cache_scan_result is not None


class TestAgentImports:
    """Test agent module imports."""

    def test_agents_module(self):
        """Test agents module and get_available_agents."""
        from kryon.agents import get_available_agents

        agents = get_available_agents()
        assert len(agents) > 0

    def test_t800_infiltrator(self):
        """Test T-800 Infiltrator agent import."""
        from kryon.agents.t800_infiltrator import t800_infiltrator

        assert t800_infiltrator is not None

    def test_central_core(self):
        """Test Central Core agent import."""
        from kryon.agents.central_core import central_core

        assert central_core is not None

    def test_ctf_master(self):
        """Test CTF Master agent import."""
        from kryon.agents.ctf_master import ctf_master

        assert ctf_master is not None

    def test_guardrails(self):
        """Test guardrails module import."""
        from kryon.agents.guardrails import get_security_guardrails

        assert get_security_guardrails is not None

    def test_t600_scout(self):
        """Test T-600 Scout agent import."""
        from kryon.agents.t600_scout import t600_scout

        assert t600_scout is not None

    def test_t1000_hunter(self):
        """Test T-1000 Hunter agent import."""
        from kryon.agents.t1000_hunter import bug_bounter_agent

        assert bug_bounter_agent is not None

    def test_neural_extractor(self):
        """Test Neural Extractor agent import."""
        from kryon.agents.neural_extractor import neural_extractor

        assert neural_extractor is not None

    def test_forensic_analyzer(self):
        """Test Forensic Analyzer agent import."""
        from kryon.agents.forensic_analyzer import forensic_analyzer

        assert forensic_analyzer is not None

    def test_tech_com_reverse(self):
        """Test Tech-Com Reverse agent import."""
        from kryon.agents.tech_com_reverse import tech_com_reverse

        assert tech_com_reverse is not None


class TestToolImports:
    """Test tool module imports."""

    def test_common_tools(self):
        """Test common tools import."""
        from kryon.tools.common import run_command

        assert run_command is not None

    def test_generic_linux_command(self):
        """Test generic_linux_command import from common."""
        from kryon.tools.common import generic_linux_command

        assert generic_linux_command is not None

    def test_exploitation_tools(self):
        """Test exploitation tools import."""
        import kryon.tools.exploitation

        assert kryon.tools.exploitation is not None

    def test_exploit_builder(self):
        """Test exploit builder import."""
        from kryon.tools.exploitation.exploit_builder import generate_shellcode

        assert generate_shellcode is not None

    def test_privilege_escalation(self):
        """Test privilege escalation tools import."""
        import kryon.tools.privilege_escalation

        assert kryon.tools.privilege_escalation is not None

    def test_linux_privesc(self):
        """Test Linux privesc tools import."""
        from kryon.tools.privilege_escalation.linux_privesc import run_linpeas

        assert run_linpeas is not None

    def test_lateral_movement(self):
        """Test lateral movement tools import."""
        import kryon.tools.lateral_movement

        assert kryon.tools.lateral_movement is not None

    def test_data_exfiltration(self):
        """Test data exfiltration tools import."""
        import kryon.tools.data_exfiltration

        assert kryon.tools.data_exfiltration is not None

    def test_wireless_tools(self):
        """Test wireless tools import."""
        from kryon.tools.wireless.kismet import kismet_scan

        assert kismet_scan is not None

    def test_osint_tools(self):
        """Test OSINT tools import."""
        from kryon.tools.osint.yara_scan import yara_scan_file

        assert yara_scan_file is not None

    def test_dfir_tools(self):
        """Test DFIR tools import."""
        from kryon.tools.dfir.log_analysis import chainsaw_hunt

        assert chainsaw_hunt is not None

    def test_mobile_tools(self):
        """Test mobile tools import."""
        from kryon.tools.mobile.mobsf import mobsf_static_analysis

        assert mobsf_static_analysis is not None


class TestPatternImports:
    """Test swarm pattern imports."""

    def test_bb_triage_pattern(self):
        """Test bb_triage swarm pattern import."""
        from kryon.agents.patterns.bb_triage import bb_triage_swarm_pattern

        assert bb_triage_swarm_pattern is not None

    def test_redteam_pattern(self):
        """Test red team swarm pattern import."""
        from kryon.agents.patterns.red_team import redteam_swarm_pattern

        assert redteam_swarm_pattern is not None


class TestUtilityImports:
    """Test utility module imports."""

    def test_skynet_util(self):
        """Test KRYON utilities import."""
        from kryon.util import load_prompt_template

        assert load_prompt_template is not None

    def test_sdk_function_tool(self):
        """Test SDK function_tool decorator import."""
        from kryon.sdk.agents import function_tool

        assert function_tool is not None

    def test_sdk_agent(self):
        """Test SDK Agent class import."""
        from kryon.sdk.agents import Agent

        assert Agent is not None
