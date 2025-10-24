"""
Tool Availability and Validation Tests

Tests that verify all SKYNET tools are properly configured,
dependencies are available, and tools can be imported successfully.
"""

import pytest
import importlib
import subprocess
from pathlib import Path
from typing import List, Dict


class TestToolImports:
    """Test that all tool modules can be imported"""

    # List of all tool modules that should be importable
    TOOL_MODULES = [
        # CTF Tools (Phase 14)
        "skynet.tools.ctf.ctf_automation",
        "skynet.tools.ctf.tryhackme_helpers",

        # Privilege Escalation
        "skynet.tools.privilege_escalation.linux_privesc",
        "skynet.tools.privilege_escalation.windows_privesc",

        # OSINT (Phase 12)
        "skynet.tools.osint.theharvester",
        "skynet.tools.osint.shodan_api",
        "skynet.tools.osint.virustotal",
        "skynet.tools.osint.censys_api",

        # DFIR (Phase 13)
        "skynet.tools.dfir.memory_forensics",
        "skynet.tools.dfir.disk_forensics",
        "skynet.tools.dfir.network_forensics",
        "skynet.tools.dfir.log_analysis",

        # Wireless (Phase 11)
        "skynet.tools.wireless.aircrack",
        "skynet.tools.wireless.kismet",
        "skynet.tools.wireless.reaver",
        "skynet.tools.wireless.wifite",

        # Mobile (Phase 11)
        "skynet.tools.mobile.jadx",
        "skynet.tools.mobile.apktool",
        "skynet.tools.mobile.mobsf",
        "skynet.tools.mobile.frida_tools",

        # Cloud (Phase 10)
        "skynet.tools.cloud.prowler",
        "skynet.tools.cloud.scoutsuite",
        "skynet.tools.cloud.cloudmapper",
        "skynet.tools.cloud.s3scanner",

        # Container (Phase 10)
        "skynet.tools.container.docker_bench",
        "skynet.tools.container.trivy",
        "skynet.tools.container.kube_bench",
        "skynet.tools.container.kube_hunter",

        # Web
        "skynet.tools.web.nuclei",
        "skynet.tools.web.ffuf",
        "skynet.tools.web.wpscan",
        "skynet.tools.web.sqlmap",

        # Reconnaissance
        "skynet.tools.reconnaissance.nmap",
        "skynet.tools.reconnaissance.masscan",
        "skynet.tools.reconnaissance.generic_linux_command",
        "skynet.tools.reconnaissance.exec_code",

        # Network
        "skynet.tools.network.wireshark",

        # Exploitation
        "skynet.tools.exploitation.metasploit",
        "skynet.tools.exploitation.searchsploit",

        # Command and Control
        "skynet.tools.command_and_control.sshpass",

        # API Attacks
        "skynet.tools.api_attacks.graphql_fuzzer",
        "skynet.tools.api_attacks.rest_fuzzer",

        # Data Exfiltration
        "skynet.tools.data_exfiltration.dns_tunnel",

        # Lateral Movement
        "skynet.tools.lateral_movement.psexec",

        # Intelligence
        "skynet.tools.intelligence.cve_search",
    ]

    @pytest.mark.parametrize("module_name", TOOL_MODULES)
    def test_tool_module_imports(self, module_name):
        """Test that each tool module can be imported"""
        try:
            module = importlib.import_module(module_name)
            assert module is not None
        except ImportError as e:
            pytest.fail(f"Failed to import {module_name}: {e}")

    def test_all_tools_have_functions(self):
        """Test that all importable tools have callable functions"""
        for module_name in self.TOOL_MODULES:
            try:
                module = importlib.import_module(module_name)

                # Get all callable functions (exclude private and classes)
                functions = [
                    name for name in dir(module)
                    if callable(getattr(module, name))
                    and not name.startswith('_')
                    and not name[0].isupper()  # Exclude classes
                ]

                # Each tool module should have at least one function
                assert len(functions) > 0, f"{module_name} has no callable functions"

            except ImportError:
                # Already tested in parametrized test
                pass


class TestAgentImports:
    """Test that all agent modules can be imported"""

    AGENT_MODULES = [
        # T-Series Offensive Units
        "skynet.agents.t800_infiltrator",
        "skynet.agents.t1000_hunter",
        "skynet.agents.t600_scout",

        # Command Units
        "skynet.agents.central_core",
        "skynet.agents.strategic_core",

        # Hunter-Killer Series
        "skynet.agents.hk_aerial",
        "skynet.agents.neural_extractor",
        "skynet.agents.forensic_analyzer",

        # Guardian Series
        "skynet.agents.guardian_protocol",

        # Specialized Units
        "skynet.agents.mobile_infiltrator",
        "skynet.agents.wireless_infiltrator",
        "skynet.agents.rf_analyzer",
        "skynet.agents.chrome_infiltrator",
        "skynet.agents.ctf_master",

        # Support Units
        "skynet.agents.mission_analyst",
        "skynet.agents.reporter",
        "skynet.agents.retester",
        "skynet.agents.mail",
        "skynet.agents.tech_com_reverse",
        "skynet.agents.signal_repeater",
        "skynet.agents.target_validator",

        # Framework Agents
        "skynet.agents.codeagent",
        "skynet.agents.guardrails",
        "skynet.agents.memory",
    ]

    @pytest.mark.parametrize("agent_module", AGENT_MODULES)
    def test_agent_module_imports(self, agent_module):
        """Test that each agent module can be imported"""
        try:
            module = importlib.import_module(agent_module)
            assert module is not None
        except ImportError as e:
            pytest.fail(f"Failed to import {agent_module}: {e}")

    def test_all_agents_have_transfer_functions(self):
        """Test that agents have transfer functions where expected"""
        agents_with_transfer = [
            "skynet.agents.t800_infiltrator",
            "skynet.agents.t1000_hunter",
            "skynet.agents.guardian_protocol",
            "skynet.agents.ctf_master",
            "skynet.agents.forensic_analyzer",
        ]

        for agent_module in agents_with_transfer:
            try:
                module = importlib.import_module(agent_module)

                # Look for transfer_to_* function
                transfer_functions = [
                    name for name in dir(module)
                    if name.startswith('transfer_to_')
                ]

                assert len(transfer_functions) > 0, \
                    f"{agent_module} missing transfer function"

            except ImportError:
                pass  # Already tested in parametrized test


class TestExternalDependencies:
    """Test availability of external tool dependencies"""

    # Critical tools that should be available for core functionality
    CRITICAL_TOOLS = [
        "python3",
        "pip",
        "git",
    ]

    # Optional tools (nice to have but not required)
    OPTIONAL_TOOLS = [
        "nmap",
        "gobuster",
        "searchsploit",
        "msfconsole",
        "john",
        "hashcat",
        "volatility",
        "autopsy",
        "wireshark",
        "aircrack-ng",
        "jadx",
        "apktool",
    ]

    @pytest.mark.parametrize("tool", CRITICAL_TOOLS)
    def test_critical_tools_available(self, tool):
        """Test that critical tools are available in PATH"""
        result = subprocess.run(
            ["which", tool] if Path("/bin/which").exists() else ["where", tool],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, \
            f"Critical tool '{tool}' not found in PATH"

    @pytest.mark.parametrize("tool", OPTIONAL_TOOLS)
    def test_optional_tools_available(self, tool):
        """Test optional tools (will warn if missing, not fail)"""
        result = subprocess.run(
            ["which", tool] if Path("/bin/which").exists() else ["where", tool],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            pytest.skip(f"Optional tool '{tool}' not available (not required)")


class TestToolFunctionSignatures:
    """Test that tool functions have proper signatures and documentation"""

    def test_ctf_automation_signatures(self):
        """Test CTF automation functions have proper signatures"""
        from skynet.tools.ctf import ctf_automation

        # Check auto_enumerate_target
        assert hasattr(ctf_automation, 'auto_enumerate_target')
        func = ctf_automation.auto_enumerate_target
        assert func.__doc__ is not None, "auto_enumerate_target missing docstring"

        # Check search_exploits
        assert hasattr(ctf_automation, 'search_exploits')
        func = ctf_automation.search_exploits
        assert func.__doc__ is not None, "search_exploits missing docstring"

        # Check auto_privilege_escalation
        assert hasattr(ctf_automation, 'auto_privilege_escalation')
        func = ctf_automation.auto_privilege_escalation
        assert func.__doc__ is not None, "auto_privilege_escalation missing docstring"

    def test_linux_privesc_enhancements(self):
        """Test enhanced Linux privilege escalation functions"""
        from skynet.tools.privilege_escalation import linux_privesc

        # Phase 14 enhancements
        required_functions = [
            'run_linpeas',
            'run_linenum',
            'gtfobins_lookup',
            'check_sudo_exploits',
            'find_suid_exploitable',
        ]

        for func_name in required_functions:
            assert hasattr(linux_privesc, func_name), \
                f"Missing function: {func_name}"

            func = getattr(linux_privesc, func_name)
            assert func.__doc__ is not None, \
                f"{func_name} missing docstring"

    def test_thm_helpers_signatures(self):
        """Test TryHackMe helper functions"""
        from skynet.tools.ctf import tryhackme_helpers

        required_functions = [
            'check_thm_vpn',
            'get_target_ip',
            'submit_thm_answer',
            'parse_thm_questions',
            'generate_thm_notes',
        ]

        for func_name in required_functions:
            assert hasattr(tryhackme_helpers, func_name), \
                f"Missing function: {func_name}"


class TestPromptFiles:
    """Test that all agent prompt files exist and are valid"""

    def test_all_prompts_exist(self):
        """Test that all expected prompt files exist"""
        prompts_dir = Path("src/skynet/prompts")

        expected_prompts = [
            "system_t800_infiltrator.md",
            "system_t1000_hunter.md",
            "system_t600_scout.md",
            "system_central_core.md",
            "system_hk_aerial.md",
            "system_forensic_analyzer.md",
            "system_guardian_protocol.md",
            "system_ctf_master.md",
            "system_mobile_infiltrator.md",
            "system_wireless_infiltrator.md",
            "system_rf_analyzer.md",
            "system_mission_analyst.md",
        ]

        for prompt_file in expected_prompts:
            prompt_path = prompts_dir / prompt_file
            assert prompt_path.exists(), f"Missing prompt file: {prompt_file}"

            # Check file has content
            content = prompt_path.read_text()
            assert len(content) > 100, f"Prompt file too small: {prompt_file}"

    def test_prompts_have_skynet_theming(self):
        """Test that prompts have SKYNET Terminator theming"""
        prompts_dir = Path("src/skynet/prompts")

        themed_prompts = [
            "system_t800_infiltrator.md",
            "system_ctf_master.md",
            "system_guardian_protocol.md",
        ]

        for prompt_file in themed_prompts:
            prompt_path = prompts_dir / prompt_file
            if prompt_path.exists():
                content = prompt_path.read_text()

                # Should have clearance level mentioned
                assert "Clearance:" in content or "CLEARANCE:" in content, \
                    f"{prompt_file} missing clearance level"


class TestClearanceSystem:
    """Test SKYNET clearance level system"""

    def test_clearance_documentation_exists(self):
        """Test that clearance documentation exists"""
        clearance_doc = Path("docs/CLEARANCE_LEVELS.md")
        assert clearance_doc.exists(), "CLEARANCE_LEVELS.md not found"

        content = clearance_doc.read_text()

        # Should document all tiers
        assert "OMEGA" in content
        assert "ALPHA" in content
        assert "BETA" in content
        assert "BRAVO" in content

    def test_agents_have_clearance_levels(self):
        """Test that agents document their clearance levels"""
        agents_with_clearance = [
            ("skynet.agents.t800_infiltrator", "ALPHA-RED"),
            ("skynet.agents.ctf_master", "ALPHA-CRIMSON"),
            ("skynet.agents.guardian_protocol", "ALPHA-BLUE"),
            ("skynet.agents.central_core", "OMEGA-COMMAND"),
        ]

        for agent_module, expected_clearance in agents_with_clearance:
            try:
                module = importlib.import_module(agent_module)

                # Check module docstring has clearance
                if module.__doc__:
                    assert "Clearance:" in module.__doc__, \
                        f"{agent_module} missing clearance in docstring"

            except ImportError:
                pass


class TestDocumentation:
    """Test that documentation is complete and up-to-date"""

    def test_session_reports_exist(self):
        """Test that all phase completion reports exist"""
        sessions_dir = Path("docs/sessions")

        expected_reports = [
            "PHASE_10_COMPLETION_REPORT.md",
            "PHASE_11_COMPLETION_REPORT.md",
            "PHASE_12_COMPLETION_REPORT.md",
            "PHASE_13_COMPLETION_REPORT.md",
            "SESSION_TRYHACKME_CTF_OPTIMIZATION.md",  # Phase 14
            "PROJECT_GAP_ANALYSIS.md",
        ]

        for report in expected_reports:
            report_path = sessions_dir / report
            assert report_path.exists(), f"Missing report: {report}"

    def test_readme_is_updated(self):
        """Test that README.md exists and has content"""
        readme = Path("README.md")
        assert readme.exists(), "README.md not found"

        content = readme.read_text()
        assert len(content) > 1000, "README.md seems incomplete"
        assert "SKYNET" in content, "README.md missing SKYNET branding"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
