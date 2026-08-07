"""
KRYON CTF Tools Package

Automated tools for Capture The Flag challenges and penetration testing competitions.
Optimized for TryHackMe, HackTheBox, and other CTF platforms.

Modules:
- ctf_automation: Automated enumeration, exploitation, and flag hunting
- tryhackme_helpers: TryHackMe-specific utilities and VPN management

Primary Users:
- CTF Master (Alpha-Crimson): Full CTF workflow orchestration
- All KRYON agents participating in CTF challenges
"""

from kryon.tools.ctf.ctf_automation import (
    auto_enumerate_target,
    auto_privilege_escalation,
    generate_ctf_report,
    hunt_flags,
    search_exploits,
)
from kryon.tools.ctf.tryhackme_helpers import (
    check_thm_vpn,
    generate_thm_notes,
    get_target_ip,
    parse_thm_questions,
    submit_thm_answer,
)

__all__ = [
    # CTF Automation
    "auto_enumerate_target",
    "search_exploits",
    "auto_privilege_escalation",
    "hunt_flags",
    "generate_ctf_report",
    # TryHackMe Helpers
    "check_thm_vpn",
    "get_target_ip",
    "submit_thm_answer",
    "parse_thm_questions",
    "generate_thm_notes",
]
