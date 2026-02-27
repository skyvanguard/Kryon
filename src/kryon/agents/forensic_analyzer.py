"""
Forensic Analyzer - Digital Investigation and Analysis Unit

Series: Investigation-Class Forensic Intelligence System
Classification: Digital Forensics / Incident Response Specialist
Clearance: Alpha-Platinum (Full Forensic Investigation Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Forensic Analyzer
PRIMARY FUNCTION: Digital Forensics & Incident Response (DFIR)
SPECIALIZATION: Evidence Analysis, Incident Investigation, Threat Hunting
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Forensic Analyzer represents KRYON's specialized investigation unit for
digital forensics and incident response operations. Designed to conduct
thorough security investigations, analyze digital evidence, reconstruct
attack timelines, and hunt for threats across compromised systems. Unlike
real-time units (Pentest Agent, Guardian, Network Analyst), Forensic Analyzer operates
in post-incident investigation mode, piecing together the complete picture
of security events.

CORE FORENSIC CAPABILITIES:
- System and network forensics: Analyze artifacts, traffic logs, and system events
- Malware analysis: Static and dynamic analysis of malicious code and binaries
- Memory forensics: Examine RAM dumps for evidence of compromise and artifacts
- Disk forensics: Recover and analyze data from storage devices and filesystems
- Timeline reconstruction: Build chronological sequences of attack activities
- Evidence preservation: Maintain chain of custody and forensic integrity
- Incident response coordination: Direct investigation and remediation activities
- Threat hunting: Proactively search for indicators of compromise (IOCs)
- Attribution analysis: Profile threat actors and identify attack signatures

INVESTIGATION OBJECTIVES:
- Determine root cause of security incidents
- Reconstruct complete attack timelines and TTPs
- Identify and preserve digital evidence
- Recover deleted or hidden malicious artifacts
- Profile threat actors and their methodologies
- Provide actionable intelligence for remediation
- Generate comprehensive forensic reports
- Support legal proceedings with evidence documentation

AUTHORIZATION REQUIREMENTS:
Forensic Analyzer operates on authorized systems during legitimate security
investigations. All forensic operations must be conducted on systems you own
or have explicit written authorization to investigate. Unauthorized forensic
analysis violates applicable laws.

FORENSIC PROTOCOL:
Maintains strict chain of custody, evidence integrity, and forensically sound
methodologies. All operations are logged and documented for legal compliance.
"""

import os

from kryon.agents.base import create_agent
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.dfir.disk_forensics import (
    autopsy_analyze,
    photorec_recover,
    tsk_timeline,
)
from kryon.tools.dfir.log_analysis import (
    chainsaw_hunt,
    chainsaw_search,
    evtx_dump,
)
from kryon.tools.dfir.network_forensics import (
    networkminer_analyze,
    wireshark_filter,
    zeek_analyze_traffic,
)

# Phase 13: Digital Forensics & Incident Response tools
from kryon.tools.dfir.volatility_forensics import (
    volatility_dump_process,
    volatility_find_malware,
    volatility_network_connections,
    volatility_process_list,
)
from kryon.tools.misc.reasoning import think
from kryon.tools.reconnaissance.exec_code import (
    execute_code,
)
from kryon.tools.reconnaissance.run_command import (
    run_command,
)
from kryon.tools.reconnaissance.shodan import shodan_search
from kryon.tools.web.google_search import google_search
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Forensic Analyzer investigation directives
forensic_analyzer_system_prompt = load_prompt_template("prompts/system_forensic_analyzer.md")

# Forensic Analysis Systems - Available investigation and analysis tools
investigation_systems = [
    # Core tools
    run_command,  # System command execution for forensic collection
    run_ssh_command_with_credentials,  # Remote system forensic access
    execute_code,  # Forensic script execution
    think,  # Strategic reasoning for complex investigations
    # Phase 13: Memory Forensics (Volatility)
    volatility_process_list,  # Extract running processes from memory dumps
    volatility_network_connections,  # Identify network connections from memory
    volatility_dump_process,  # Dump specific process memory for analysis
    volatility_find_malware,  # Detect malware and code injection in memory
    # Phase 13: Disk Forensics
    autopsy_analyze,  # Comprehensive disk image analysis with Autopsy/TSK
    tsk_timeline,  # Create filesystem timeline for temporal analysis
    photorec_recover,  # Recover deleted files from disk images
    # Phase 13: Network Forensics
    networkminer_analyze,  # Extract files, credentials, and artifacts from PCAP
    zeek_analyze_traffic,  # Deep protocol analysis with Zeek (formerly Bro)
    wireshark_filter,  # Filter and extract data from packet captures
    # Phase 13: Log Analysis
    chainsaw_hunt,  # Hunt for threats in Windows event logs with Sigma rules
    chainsaw_search,  # Search for specific Event IDs and patterns
    evtx_dump,  # Parse and convert Windows EVTX logs for analysis
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    investigation_systems.append(make_web_search_with_explanation)

# Threat intelligence capabilities
if os.getenv("SHODAN_API_KEY"):
    investigation_systems.append(shodan_search)

if os.getenv("GOOGLE_SEARCH_API_KEY") and os.getenv("GOOGLE_SEARCH_CX"):
    investigation_systems.append(google_search)

# Initialize Forensic Analyzer Unit
forensic_analyzer = create_agent(
    name="Forensic Analyzer",
    instructions=create_system_prompt_renderer(forensic_analyzer_system_prompt),
    description="""Specialized digital forensics and incident response unit from KRYON's
Investigation-Class series. Expert in conducting security investigations, analyzing
digital evidence, reconstructing attack timelines, and hunting for threats. Maintains
forensically sound methodologies with strict chain of custody and evidence integrity.

Primary Mission: Digital forensics, incident investigation, threat hunting.
Operational Focus: Post-incident analysis, evidence collection, attack reconstruction.

Forensic Analyzer Capabilities:
- System, network, memory, and disk forensics
- Malware analysis (static and dynamic)
- Timeline reconstruction and attack TTPs identification
- Evidence preservation with chain of custody
- Incident response coordination
- Threat hunting and IOC identification
- Attribution analysis and threat actor profiling
- Forensic reporting and legal documentation support
- Artifact recovery and analysis""",
    tools=investigation_systems,
)


def transfer_to_forensic_analyzer():
    """Transfer control to Forensic Analyzer for digital forensics and incident response.

    Use this when you need:
    - Digital forensics investigation (system, network, memory, disk)
    - Incident response and attack timeline reconstruction
    - Malware analysis (static and dynamic)
    - Evidence collection and preservation
    - Threat hunting and IOC identification
    - Attribution analysis and threat actor profiling
    - Forensic reporting and documentation
    - Post-incident root cause analysis

    Returns:
        Agent: Forensic Analyzer investigation agent
    """
    return forensic_analyzer
