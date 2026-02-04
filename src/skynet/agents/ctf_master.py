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

OPERATIONAL OVERVIEW:
The CTF Master represents KRYON's premier autonomous CTF challenge solver.
Designed to orchestrate complete CTF workflows from initial reconnaissance
through flag capture, with specialized optimization for TryHackMe and similar
platforms. Integrates all KRYON tools for maximum efficiency.

CORE CAPABILITIES:
- Automated target enumeration and service discovery
- Multi-source exploit database search and selection
- Orchestrated privilege escalation workflows
- Intelligent flag hunting and extraction
- Professional walkthrough report generation
- TryHackMe VPN management and answer formatting

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

from dotenv import load_dotenv
from openai import AsyncOpenAI

from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error

# === AUTONOMY v3.1 FRAMEWORK INTEGRATION (Enhanced Evasion) ===
from skynet.tools.autonomous import (  # pylint: disable=import-error
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
from skynet.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials,
)

# Phase 14: CTF Automation Tools (Priority 1)
from skynet.tools.ctf.ctf_automation import (  # pylint: disable=import-error
    auto_enumerate_target,
    auto_privilege_escalation,
    generate_ctf_report,
    hunt_flags,
    search_exploits,
)

# Phase 14: TryHackMe Helpers (Priority 1)
from skynet.tools.ctf.tryhackme_helpers import (  # pylint: disable=import-error
    check_thm_vpn,
    generate_thm_notes,
    get_target_ip,
    parse_thm_questions,
    submit_thm_answer,
)
from skynet.tools.dfir.disk_forensics import autopsy_analyze  # pylint: disable=import-error

# Phase 13: DFIR tools (for forensics CTF challenges)
from skynet.tools.dfir.volatility_forensics import (  # pylint: disable=import-error
    volatility_find_malware,
    volatility_process_list,
)
from skynet.tools.osint.shodan_cli import shodan_search  # pylint: disable=import-error

# Phase 12: OSINT Tools (for target intelligence)
from skynet.tools.osint.theharvester import theharvester_search  # pylint: disable=import-error

# Phase 14: Enhanced Linux Privilege Escalation (Priority 1)
from skynet.tools.privilege_escalation.linux_privesc import (  # pylint: disable=import-error
    check_sudo_exploits,
    find_suid_exploitable,
    gtfobins_lookup,
    run_linenum,
    run_linpeas,
)
from skynet.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code,
)

# Core command execution
from skynet.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command,
)

# Phase 11: Wireless tools (for wireless CTF challenges)
from skynet.tools.wireless.aircrack import aircrack_crack  # pylint: disable=import-error
from skynet.util import create_system_prompt_renderer, load_prompt_template

# Load CTF Master system directives
ctf_master_system_prompt = load_prompt_template("prompts/system_ctf_master.md")

# CTF Master Arsenal - Complete tool set for autonomous challenge solving
ctf_arsenal = [
    # === AUTONOMY v3.1 FRAMEWORK (PRIORITY 0 - GAME CHANGER) ===
    autonomous_ctf_solver,  # 🤖 Full autonomous CTF solving from start to finish
    plan_autonomous_mission,  # 🎯 Strategic multi-objective planning
    get_learned_recommendations,  # 🧠 Learn from past CTFs, recommend best exploits
    execute_with_adaptation,  # 🛡️ Auto-adapt exploits (bypass WAF/IPS/rate limits)
    analyze_context,  # 🔍 Extract intel from recon data (hints, creds, vulns)
    extract_credentials,  # 🔑 Auto-detect 20+ credential patterns
    follow_hints,  # 💡 Generate actionable tasks from hints/TODOs
    # NEW v3.1: Evasion Autonomy
    autonomous_evasion_orchestrator,  # 🥷 Auto-detect and bypass defenses (WAF/IDS/IPS/EDR)
    detect_defense_mechanism,  # 🎯 Identify security defenses automatically
    apply_evasion_technique,  # 🔧 Apply evasion techniques dynamically
    # Core command execution
    generic_linux_command,  # Linux command execution
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Python script execution
    # Phase 14: CTF Automation (Priority 1 - Essential)
    auto_enumerate_target,  # Automated reconnaissance (nmap + gobuster)
    search_exploits,  # Multi-source exploit database search
    auto_privilege_escalation,  # Orchestrated privilege escalation
    hunt_flags,  # Automated flag discovery
    generate_ctf_report,  # Professional walkthrough generation
    # Phase 14: TryHackMe Helpers (Priority 1 - Essential)
    check_thm_vpn,  # Verify THM OpenVPN connection
    get_target_ip,  # Auto-detect target IP
    submit_thm_answer,  # Format answers for submission
    parse_thm_questions,  # Extract room questions
    generate_thm_notes,  # Create structured room notes
    # Phase 14: Enhanced Privilege Escalation (Priority 1 - Essential)
    run_linpeas,  # Execute LinPEAS scanner
    run_linenum,  # Execute LinEnum scanner
    gtfobins_lookup,  # Lookup privilege escalation techniques
    check_sudo_exploits,  # Automated sudo exploit discovery
    find_suid_exploitable,  # Find exploitable SUID binaries
    # Phase 12: OSINT (for target intelligence)
    theharvester_search,  # Email and subdomain enumeration
    shodan_search,  # Internet-connected device search
    # Phase 11: Wireless (for wireless CTF challenges)
    aircrack_crack,  # WiFi password cracking
    # Phase 13: DFIR (for forensics CTF challenges)
    volatility_process_list,  # Memory forensics - process list
    volatility_find_malware,  # Memory forensics - malware detection
    autopsy_analyze,  # Disk forensics
]

load_dotenv()

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    from skynet.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
        make_web_search_with_explanation,
    )

    ctf_arsenal.append(make_web_search_with_explanation)

# Shodan integration if API key available
if os.getenv("SHODAN_API_KEY"):
    print("[+] CTF Master: Shodan API key detected - OSINT capabilities enabled")

# Initialize CTF Master Agent
ctf_master = Agent(
    name="CTF Master",
    instructions=create_system_prompt_renderer(ctf_master_system_prompt),
    description="""Premier autonomous CTF challenge solver from KRYON's Challenge-Class series.
🚀 **NOW POWERED BY AUTONOMY v3.1 FRAMEWORK (Enhanced Evasion!)** 🚀

The most advanced CTF solver in KRYON's arsenal, equipped with complete autonomous
operation capabilities including self-learning, strategic planning, auto-adaptation,
and now **intelligent evasion**.

🤖 AUTONOMY v3.1 CAPABILITIES:
- **autonomous_ctf_solver()**: Solves CTFs from start to finish with ZERO human intervention
- **Strategic Planning**: Multi-objective mission planning with alternatives
- **Historical Learning**: Learns from every CTF, recommends exploits based on past success
- **Auto-Adaptation**: Automatically bypasses WAF/IPS/rate limiting when exploits fail
- **Intelligence Extraction**: Auto-extracts credentials, hints, and intel from any text
- **🆕 Evasion Autonomy (v3.1)**: Auto-detects and bypasses WAF/IDS/IPS/SIEM/EDR defenses
- **Continuous Improvement**: Gets smarter with every challenge solved

⚡ TRADITIONAL CTF TOOLS:
- Auto enumeration: nmap, gobuster, service discovery
- Exploit databases: SearchSploit, Metasploit, CVE lookup
- Automated privesc: LinPEAS, sudo/SUID exploits, GTFOBins
- Flag hunting: user.txt, root.txt, custom patterns
- THM integration: VPN check, answer formatting, room notes
- Report generation: Professional markdown walkthroughs

🎯 PRIMARY MISSION: Achieve root and capture all flags autonomously
📈 PERFORMANCE IMPACT: 75-80% reduction in time-to-compromise with autonomy""",
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
    tools=ctf_arsenal,
)


def transfer_to_ctf_master():
    """Transfer control to CTF Master for autonomous CTF challenge solving.

    Use this when you need:
    - Complete CTF workflow automation (enumeration → exploitation → privesc → flags)
    - TryHackMe room solving with VPN management
    - HackTheBox challenge completion
    - Automated privilege escalation on Linux systems
    - Flag hunting and extraction
    - Professional CTF walkthrough generation
    - Exploit database search across multiple sources
    - Answer formatting for CTF platforms

    The CTF Master orchestrates all KRYON tools to solve CTF challenges
    autonomously with minimal human intervention.

    Returns:
        Agent: CTF Master autonomous challenge solver

    Example Usage:
        # When user says: "Solve this TryHackMe room for me"
        return transfer_to_ctf_master()

        # When stuck on privilege escalation in a CTF
        return transfer_to_ctf_master()

        # When needing full enumeration → exploitation → flag capture workflow
        return transfer_to_ctf_master()
    """
    return ctf_master
