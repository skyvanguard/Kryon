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

    def test_kryon_package(self):
        """Test core KRYON package import."""
        import kryon

        assert kryon is not None

    def test_kryon_sdk(self):
        """Test KRYON SDK import."""
        import kryon.sdk

        assert kryon.sdk is not None

    def test_kryon_sdk_agents(self):
        """Test KRYON SDK agents module import."""
        import kryon.sdk.agents

        assert kryon.sdk.agents is not None

    def test_kryon_tools(self):
        """Test KRYON tools module import."""
        import kryon.tools

        assert kryon.tools is not None

    def test_kryon_cache(self):
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

    def test_get_agent_by_name_returns_unified(self):
        """v2.x: the 33 legacy per-name agents were removed; get_agent_by_name
        returns the unified Kryon agent for ANY key (see agents/__init__.py).
        Replaces the old per-agent import tests (pentest_agent, recon_scout,
        ctf_master, vuln_hunter, … modules no longer exist)."""
        from kryon.agents import get_agent_by_name

        for key in ("pentest_agent", "recon_scout", "ctf_master", "vuln_hunter", "anything_xyz"):
            assert get_agent_by_name(key) is not None

    def test_guardrails(self):
        """Test guardrails module import."""
        from kryon.agents.guardrails import get_security_guardrails

        assert get_security_guardrails is not None


class TestToolImports:
    """Test tool module imports."""

    def test_common_tools(self):
        """Test common tools import."""
        from kryon.tools.common import run_command

        assert run_command is not None

    def test_run_command(self):
        """Test run_command import from common."""
        from kryon.tools.common import run_command

        assert run_command is not None

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


# NOTE: TestPatternImports (bb_triage / red_team swarm patterns) was removed —
# those pattern modules still import the legacy per-name agents deleted in the
# v2.x unified-only migration (e.g. kryon.agents.retester), so they raise
# ModuleNotFoundError. The pattern source files under agents/patterns/ are dead
# code pending a separate refactor; the import tests can never pass post-removal.


class TestUtilityImports:
    """Test utility module imports."""

    def test_kryon_util(self):
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
