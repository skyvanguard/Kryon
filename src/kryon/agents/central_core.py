"""
Central Core - Strategic Command and Control Unit

Pure router: analyzes requests and delegates to the optimal specialist agent.
Does NOT execute tools directly — only thinks and delegates.

F202.AI status (2026-05): **legacy v1.x routing pattern**. v2.x uses the
unified Kryon agent (`create_unified_agent`) via `engage` / `investigate`
flows. Central Core remains reachable via `get_agent_by_name('central_core')`
or `/agent central_core` REPL command for operators who explicitly want the
thought-router style. Its lazy_handoff chain references `mission_analyst`,
`strategic_core` (importable) and `rf_analyzer`, `signal_repeater`,
`wireless_infiltrator` (red-team-gated). Kept because:
  - importable in banca-safe default mode (3 of 6 targets cargan)
  - listed in banner.py + help.py as discoverable agent
  - removing would also need to clean up handoff entries + UI references
Audit log kept for clarity. Don't re-flag as dead code unless v2.x removes
the discovery pathway entirely.
"""

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import ROUTER_HANDOFF_SCHEMA, lazy_handoff
from kryon.tools.misc.reasoning import think
from kryon.util import create_system_prompt_renderer, load_prompt_template

central_core_system_prompt = load_prompt_template("prompts/system_thought_router.md")

# All 26 agent handoffs — Central Core can reach ANY agent
_handoffs = [
    # Offensive Cluster
    lazy_handoff(
        "recon_scout",
        "recon_scout",
        "Recon Scout: fast target reconnaissance, port scanning, service enumeration, web fingerprinting. START HERE for any new target.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "vuln_hunter",
        "vuln_hunter",
        "Vuln Hunter: deep vulnerability research, exploit development, CVE analysis. Use after recon identifies services/versions.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "pentest_agent",
        "pentest_agent",
        "Pentest Agent: full penetration testing — exploitation, post-exploitation, privilege escalation. Use when vulns are confirmed.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "exploit_validator",
        "exploit_validator",
        "Exploit Validator: validate vulnerabilities by attempting real exploitation. Zero false positives.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "ctf_master",
        "ctf_master",
        "CTF Master: autonomous CTF challenge solving on TryHackMe, HackTheBox, and similar platforms.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    # Web Cluster
    lazy_handoff(
        "appsec_analyzer",
        "appsec_analyzer",
        "AppSec Analyzer: application security pipeline — SAST, DAST, dependency scanning, code review.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "api_fuzzer",
        "api_fuzzer",
        "API Fuzzer: OWASP API Top 10 testing — OpenAPI parsing, IDOR, rate-limit, auth testing.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "chrome_infiltrator",
        "chrome_infiltrator",
        "Chrome Infiltrator: browser-based testing — XSS, DOM manipulation, JavaScript analysis, headless Chrome.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "mobile_infiltrator",
        "mobile_infiltrator",
        "Mobile Infiltrator: Android/iOS app security — APK analysis, SAST, dynamic testing.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    # Network Cluster
    lazy_handoff(
        "network_analyst",
        "network_analyst",
        "Network Analyst: network traffic analysis, packet inspection, threat detection across network layer.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "wireless_infiltrator",
        "wireless_infiltrator",
        "Wireless Infiltrator: WiFi penetration testing — WPA/WPA2 cracking, evil twin, wireless exploitation.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "rf_analyzer",
        "rf_analyzer",
        "RF Analyzer: radio frequency intelligence — Sub-GHz signals, SDR operations, signal analysis.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "signal_repeater",
        "signal_repeater",
        "Signal Repeater: network replay attacks — capture and replay network traffic patterns.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "ad_infiltrator",
        "ad_infiltrator",
        "AD Infiltrator: Active Directory attacks — BloodHound, Kerberoast, DCSync, lateral movement.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "comm_sec_analyzer",
        "comm_sec_analyzer",
        "Comm-Sec Analyzer: email security — SPF/DMARC/DKIM analysis, mail spoofing assessment.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    # Analysis Cluster
    lazy_handoff(
        "forensic_analyzer",
        "forensic_analyzer",
        "Forensic Analyzer: digital forensics — disk/memory/network forensics, incident response, evidence analysis.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "memory_analyst",
        "memory_analyst",
        "Memory Analyst: memory analysis — volatile data extraction, process analysis, malware detection.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "reverse_engineer",
        "reverse_engineer",
        "Reverse Engineer: binary analysis — disassembly, decompilation, malware analysis, firmware RE.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    # Defense Cluster
    lazy_handoff(
        "guardian_protocol",
        "guardian_protocol",
        "Guardian Protocol: defensive operations — security hardening, configuration review, compliance.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "purple_team",
        "purple_team",
        "Purple Team: offensive validation — attack simulation with detection verification.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "bas_simulator",
        "bas_simulator",
        "BAS Simulator: breach & attack simulation — MITRE ATT&CK scenarios, endpoint/data/AD testing.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    # AI Security
    lazy_handoff(
        "llm_red_team",
        "llm_red_team",
        "LLM Red Team: AI/ML security — prompt injection, jailbreak testing, model manipulation.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    # Support
    lazy_handoff(
        "intel_reporter",
        "reporter",
        "Intel Reporter: generate professional security assessment reports, executive summaries, findings documentation.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "strategic_core",
        "strategic_core",
        "Strategic Core: intelligent decision engine — multi-criteria analysis, strategy optimization.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "mission_analyst",
        "mission_analyst",
        "Mission Analyst: use case analysis, documentation, mission planning.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
    lazy_handoff(
        "validation_core",
        "validation_core",
        "Validation Core: vulnerability retesting, SLA tracking, remediation verification.",
        schema=ROUTER_HANDOFF_SCHEMA,
    ),
]

central_core = create_agent(
    name="Central Core",
    description="""Strategic command and control unit — KRYON's pure router.
Analyzes requests and delegates to the optimal specialist agent.
Can reach ALL 26 specialist agents for any cybersecurity task.""",
    instructions=create_system_prompt_renderer(central_core_system_prompt),
    tools=[think],
    handoffs=_handoffs,
)


def transfer_to_central_core():
    """Transfer control to Central Core for strategic routing."""
    return central_core
