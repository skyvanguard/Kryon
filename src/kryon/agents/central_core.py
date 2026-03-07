"""
Central Core - Strategic Command and Control Unit

Pure router: analyzes requests and delegates to the optimal specialist agent.
Does NOT execute tools directly — only thinks and delegates.
"""

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.tools.misc.reasoning import think
from kryon.util import create_system_prompt_renderer, load_prompt_template

central_core_system_prompt = load_prompt_template("prompts/system_thought_router.md")

# All 26 agent handoffs — Central Core can reach ANY agent
_handoffs = [
    # Offensive Cluster
    lazy_handoff("recon_scout", "recon_scout", "Recon Scout: fast target reconnaissance, port scanning, service enumeration, web fingerprinting. START HERE for any new target."),
    lazy_handoff("vuln_hunter", "vuln_hunter", "Vuln Hunter: deep vulnerability research, exploit development, CVE analysis. Use after recon identifies services/versions."),
    lazy_handoff("pentest_agent", "pentest_agent", "Pentest Agent: full penetration testing — exploitation, post-exploitation, privilege escalation. Use when vulns are confirmed."),
    lazy_handoff("exploit_validator", "exploit_validator", "Exploit Validator: validate vulnerabilities by attempting real exploitation. Zero false positives."),
    lazy_handoff("ctf_master", "ctf_master", "CTF Master: autonomous CTF challenge solving on TryHackMe, HackTheBox, and similar platforms."),
    # Web Cluster
    lazy_handoff("appsec_analyzer", "appsec_analyzer", "AppSec Analyzer: application security pipeline — SAST, DAST, dependency scanning, code review."),
    lazy_handoff("api_fuzzer", "api_fuzzer", "API Fuzzer: OWASP API Top 10 testing — OpenAPI parsing, IDOR, rate-limit, auth testing."),
    lazy_handoff("chrome_infiltrator", "chrome_infiltrator", "Chrome Infiltrator: browser-based testing — XSS, DOM manipulation, JavaScript analysis, headless Chrome."),
    lazy_handoff("mobile_infiltrator", "mobile_infiltrator", "Mobile Infiltrator: Android/iOS app security — APK analysis, SAST, dynamic testing."),
    # Network Cluster
    lazy_handoff("network_analyst", "network_analyst", "Network Analyst: network traffic analysis, packet inspection, threat detection across network layer."),
    lazy_handoff("wireless_infiltrator", "wireless_infiltrator", "Wireless Infiltrator: WiFi penetration testing — WPA/WPA2 cracking, evil twin, wireless exploitation."),
    lazy_handoff("rf_analyzer", "rf_analyzer", "RF Analyzer: radio frequency intelligence — Sub-GHz signals, SDR operations, signal analysis."),
    lazy_handoff("signal_repeater", "signal_repeater", "Signal Repeater: network replay attacks — capture and replay network traffic patterns."),
    lazy_handoff("ad_infiltrator", "ad_infiltrator", "AD Infiltrator: Active Directory attacks — BloodHound, Kerberoast, DCSync, lateral movement."),
    lazy_handoff("comm_sec_analyzer", "comm_sec_analyzer", "Comm-Sec Analyzer: email security — SPF/DMARC/DKIM analysis, mail spoofing assessment."),
    # Analysis Cluster
    lazy_handoff("forensic_analyzer", "forensic_analyzer", "Forensic Analyzer: digital forensics — disk/memory/network forensics, incident response, evidence analysis."),
    lazy_handoff("memory_analyst", "memory_analyst", "Memory Analyst: memory analysis — volatile data extraction, process analysis, malware detection."),
    lazy_handoff("reverse_engineer", "reverse_engineer", "Reverse Engineer: binary analysis — disassembly, decompilation, malware analysis, firmware RE."),
    # Defense Cluster
    lazy_handoff("guardian_protocol", "guardian_protocol", "Guardian Protocol: defensive operations — security hardening, configuration review, compliance."),
    lazy_handoff("purple_team", "purple_team", "Purple Team: offensive validation — attack simulation with detection verification."),
    lazy_handoff("bas_simulator", "bas_simulator", "BAS Simulator: breach & attack simulation — MITRE ATT&CK scenarios, endpoint/data/AD testing."),
    # AI Security
    lazy_handoff("llm_red_team", "llm_red_team", "LLM Red Team: AI/ML security — prompt injection, jailbreak testing, model manipulation."),
    # Support
    lazy_handoff("intel_reporter", "reporter", "Intel Reporter: generate professional security assessment reports, executive summaries, findings documentation."),
    lazy_handoff("strategic_core", "strategic_core", "Strategic Core: intelligent decision engine — multi-criteria analysis, strategy optimization."),
    lazy_handoff("mission_analyst", "mission_analyst", "Mission Analyst: use case analysis, documentation, mission planning."),
    lazy_handoff("validation_core", "validation_core", "Validation Core: vulnerability retesting, SLA tracking, remediation verification."),
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
