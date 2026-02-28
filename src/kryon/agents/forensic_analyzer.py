"""
Forensic Analyzer - Digital Investigation and Analysis Unit

Series: Investigation-Class Forensic Intelligence System
Classification: Digital Forensics / Incident Response Specialist
Clearance: Alpha-Platinum (Full Forensic Investigation Authority)
Operational Status: ACTIVE

AUTHORIZATION REQUIREMENTS:
Forensic Analyzer operates on authorized systems during legitimate security
investigations. All forensic operations must be conducted on systems you own
or have explicit written authorization to investigate.
"""

from kryon.agents.base import create_agent
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS
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
from kryon.tools.dfir.volatility_forensics import (
    volatility_dump_process,
    volatility_find_malware,
    volatility_network_connections,
    volatility_process_list,
)
from kryon.tools.misc.reasoning import think
from kryon.tools.osint.yara_scan import yara_scan_directory, yara_scan_file
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Forensic Analyzer investigation directives
forensic_analyzer_system_prompt = load_prompt_template("prompts/system_forensic_analyzer.md")

# Forensic Analysis Systems — focused toolset (14 tools)
investigation_systems = [
    # Core + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    # Remote access
    run_ssh_command_with_credentials,
    # Reasoning
    think,
    # Memory Forensics — Volatility (4)
    volatility_process_list,
    volatility_network_connections,
    volatility_dump_process,
    volatility_find_malware,
    # Disk Forensics (3)
    autopsy_analyze,
    tsk_timeline,
    photorec_recover,
    # Network Forensics (3)
    networkminer_analyze,
    zeek_analyze_traffic,
    wireshark_filter,
    # Log Analysis (3)
    chainsaw_hunt,
    chainsaw_search,
    evtx_dump,
    # YARA malware detection (2)
    yara_scan_file,
    yara_scan_directory,
]

# Initialize Forensic Analyzer Unit
forensic_analyzer = create_agent(
    name="Forensic Analyzer",
    instructions=create_system_prompt_renderer(forensic_analyzer_system_prompt),
    description="""Specialized digital forensics and incident response unit from KRYON's
Investigation-Class series. Expert in conducting security investigations, analyzing
digital evidence, reconstructing attack timelines, and hunting for threats.

Primary Mission: Digital forensics, incident investigation, threat hunting.
Operational Focus: Post-incident analysis, evidence collection, attack reconstruction.""",
    tools=investigation_systems,
)


def transfer_to_forensic_analyzer():
    """Transfer control to Forensic Analyzer for digital forensics and incident response.

    Returns:
        Agent: Forensic Analyzer investigation agent
    """
    return forensic_analyzer
