"""
CTF Master - Autonomous CTF Challenge Solver

Series: Challenge-Class Autonomous System
Classification: CTF Specialist / Automated Challenge Solver
Clearance: Alpha-Crimson (CTF Operations Authority)
Operational Status: ACTIVE

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

from kryon.agents.base import create_agent
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS

# Autonomous framework — core CTF solving capabilities
from kryon.tools.autonomous import (
    autonomous_ctf_solver,
    execute_with_adaptation,
    plan_autonomous_mission,
)

# CTF automation tools
from kryon.tools.ctf.ctf_automation import (
    auto_enumerate_target,
    hunt_flags,
    search_exploits,
)
from kryon.tools.ctf.tryhackme_helpers import check_thm_vpn

# Privilege escalation essentials
from kryon.tools.privilege_escalation.linux_privesc import (
    gtfobins_lookup,
    run_linpeas,
)
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load CTF Master system directives
ctf_master_system_prompt = load_prompt_template("prompts/system_ctf_master.md")

# CTF Master Arsenal — focused toolset (14 tools)
ctf_arsenal = [
    # Core execution + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    # Autonomous CTF solving (3)
    autonomous_ctf_solver,
    plan_autonomous_mission,
    execute_with_adaptation,
    # CTF automation (3)
    auto_enumerate_target,
    search_exploits,
    hunt_flags,
    # TryHackMe (1)
    check_thm_vpn,
    # Privilege escalation essentials (2)
    run_linpeas,
    gtfobins_lookup,
]

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
