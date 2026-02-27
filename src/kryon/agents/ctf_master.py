"""
CTF Master - Autonomous CTF Challenge Solver

Series: Challenge-Class Autonomous System
Classification: CTF Specialist / Automated Challenge Solver
Clearance: Alpha-Crimson (CTF Operations Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: CTF Master
PRIMARY FUNCTION: Autonomous CTF Challenge Solving
SPECIALIZATION: TryHackMe, HackTheBox, CTF Competitions
═══════════════════════════════════════════════════════════════════════

AUTHORIZATION REQUIREMENTS:
CTF Master operates exclusively on authorized CTF platforms:
- TryHackMe (with active subscription)
- HackTheBox (with active subscription)
- CTF competitions you're registered for
- Practice labs you own or have explicit permission to access

NEVER use these capabilities on production systems or unauthorized targets.

Environment Variables (Optional):
- SSH_HOST: Target system IP address
- SSH_USER: Authentication username
- SSH_PASS: Authentication credentials
"""

import os

from kryon.agents.base import create_agent
from kryon.tools.ai.claude_code import claude_code

# === AUTONOMY v3.1 FRAMEWORK INTEGRATION (Enhanced Evasion) ===
from kryon.tools.autonomous import (
    analyze_context,  # Intelligence extraction
    apply_evasion_technique,  # Apply evasion techniques
    autonomous_ctf_solver,  # Full autonomous CTF solving
    # NEW v3.1: Evasion Autonomy
    autonomous_evasion_orchestrator,  # Auto-evasion orchestrator
    detect_defense_mechanism,  # Defense detection
    execute_with_adaptation,  # Auto-adaptation (WAF/IPS bypass)
    extract_credentials,  # Credential detection (20+ patterns)
    follow_hints,  # Hint-to-task generation
    get_learned_recommendations,  # Historical learning
    plan_autonomous_mission,  # Strategic mission planning
)
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)

# Phase 14: CTF Automation Tools (Priority 1)
from kryon.tools.ctf.ctf_automation import (
    auto_enumerate_target,
    auto_privilege_escalation,
    generate_ctf_report,
    hunt_flags,
    search_exploits,
)

# Phase 14: TryHackMe Helpers (Priority 1)
from kryon.tools.ctf.tryhackme_helpers import (
    check_thm_vpn,
    generate_thm_notes,
    get_target_ip,
    parse_thm_questions,
    submit_thm_answer,
)
from kryon.tools.dfir.disk_forensics import autopsy_analyze

# Phase 13: DFIR tools (for forensics CTF challenges)
from kryon.tools.dfir.volatility_forensics import (
    volatility_find_malware,
    volatility_process_list,
)
from kryon.tools.osint.shodan_cli import shodan_search

# Phase 12: OSINT Tools (for target intelligence)
from kryon.tools.osint.theharvester import theharvester_search

# Phase 14: Enhanced Linux Privilege Escalation (Priority 1)
from kryon.tools.privilege_escalation.linux_privesc import (
    check_sudo_exploits,
    find_suid_exploitable,
    gtfobins_lookup,
    run_linenum,
    run_linpeas,
)
from kryon.tools.reconnaissance.exec_code import (
    execute_code,
)

# Core command execution
from kryon.tools.reconnaissance.run_command import (
    run_command,
)

# Phase 11: Wireless tools (for wireless CTF challenges)
from kryon.tools.wireless.aircrack import aircrack_crack
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load CTF Master system directives
ctf_master_system_prompt = load_prompt_template("prompts/system_ctf_master.md")

# CTF Master Arsenal - Complete tool set for autonomous challenge solving
ctf_arsenal = [
    # === AUTONOMY v3.1 FRAMEWORK (PRIORITY 0 - GAME CHANGER) ===
    autonomous_ctf_solver,
    plan_autonomous_mission,
    get_learned_recommendations,
    execute_with_adaptation,
    analyze_context,
    extract_credentials,
    follow_hints,
    # NEW v3.1: Evasion Autonomy
    autonomous_evasion_orchestrator,
    detect_defense_mechanism,
    apply_evasion_technique,
    # Core command execution
    run_command,
    run_ssh_command_with_credentials,
    execute_code,
    # Phase 14: CTF Automation (Priority 1 - Essential)
    auto_enumerate_target,
    search_exploits,
    auto_privilege_escalation,
    hunt_flags,
    generate_ctf_report,
    # Phase 14: TryHackMe Helpers (Priority 1 - Essential)
    check_thm_vpn,
    get_target_ip,
    submit_thm_answer,
    parse_thm_questions,
    generate_thm_notes,
    # Phase 14: Enhanced Privilege Escalation (Priority 1 - Essential)
    run_linpeas,
    run_linenum,
    gtfobins_lookup,
    check_sudo_exploits,
    find_suid_exploitable,
    # Phase 12: OSINT (for target intelligence)
    theharvester_search,
    shodan_search,
    # Phase 11: Wireless (for wireless CTF challenges)
    aircrack_crack,
    # Phase 13: DFIR (for forensics CTF challenges)
    volatility_process_list,
    volatility_find_malware,
    autopsy_analyze,
    # AI Delegation — complex tasks to Claude Code CLI
    claude_code,
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    from kryon.tools.web.search_web import (
        make_web_search_with_explanation,
    )

    ctf_arsenal.append(make_web_search_with_explanation)

# Initialize CTF Master Agent
ctf_master = create_agent(
    name="CTF Master",
    instructions=create_system_prompt_renderer(ctf_master_system_prompt),
    description="""Premier autonomous CTF challenge solver from KRYON's Challenge-Class series.
Powered by AUTONOMY v3.1 Framework with self-learning, strategic planning, auto-adaptation,
and intelligent evasion capabilities.

Primary Mission: Achieve root and capture all flags autonomously.""",
    tools=ctf_arsenal,
)


def transfer_to_ctf_master():
    """Transfer control to CTF Master for autonomous CTF challenge solving.

    Returns:
        Agent: CTF Master autonomous challenge solver
    """
    return ctf_master
