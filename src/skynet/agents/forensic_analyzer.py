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
Forensic Analyzer represents SKYNET's specialized investigation unit for
digital forensics and incident response operations. Designed to conduct
thorough security investigations, analyze digital evidence, reconstruct
attack timelines, and hunt for threats across compromised systems. Unlike
real-time units (T-Series, Guardian, HK-Aerial), Forensic Analyzer operates
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

from dotenv import load_dotenv
from openai import AsyncOpenAI

from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error
from skynet.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials,
)
from skynet.tools.dfir.disk_forensics import (  # pylint: disable=import-error
    autopsy_analyze,
    photorec_recover,
    tsk_timeline,
)
from skynet.tools.dfir.log_analysis import (  # pylint: disable=import-error
    chainsaw_hunt,
    chainsaw_search,
    evtx_dump,
)
from skynet.tools.dfir.network_forensics import (  # pylint: disable=import-error
    networkminer_analyze,
    wireshark_filter,
    zeek_analyze_traffic,
)

# Phase 13: Digital Forensics & Incident Response tools
from skynet.tools.dfir.volatility_forensics import (  # pylint: disable=import-error
    volatility_dump_process,
    volatility_find_malware,
    volatility_network_connections,
    volatility_process_list,
)
from skynet.tools.misc.reasoning import think  # pylint: disable=import-error
from skynet.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code,
)
from skynet.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command,
)
from skynet.tools.reconnaissance.shodan import shodan_search
from skynet.tools.web.google_search import google_search
from skynet.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_web_search_with_explanation,
)
from skynet.util import create_system_prompt_renderer, load_prompt_template

load_dotenv()

# Load Forensic Analyzer investigation directives
forensic_analyzer_system_prompt = load_prompt_template("prompts/system_forensic_analyzer.md")

# Forensic Analysis Systems - Available investigation and analysis tools
investigation_systems = [
    # Core tools
    generic_linux_command,  # System command execution for forensic collection
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
forensic_analyzer = Agent(
    name="Forensic Analyzer",
    instructions=create_system_prompt_renderer(forensic_analyzer_system_prompt),
    description="""Specialized digital forensics and incident response unit from SKYNET's
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
    model=OpenAIChatCompletionsModel(
        model=os.getenv("SKYNET_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
    tools=investigation_systems,
)

# Legacy compatibility - maintain backward compatibility with old naming
dfir_agent = forensic_analyzer  # Alias for legacy code


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


# Legacy transfer function for backward compatibility
def transfer_to_dfir():
    """Legacy function - transfers to Forensic Analyzer.

    This function maintained for backward compatibility.
    Use transfer_to_forensic_analyzer() in new code.
    """
    return transfer_to_forensic_analyzer()
