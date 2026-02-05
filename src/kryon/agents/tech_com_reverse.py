"""
Tech-Com Reverse - Technical Intelligence Reverse Engineering Unit

Series: Tech-Com Class Technical Analysis System
Classification: Reverse Engineering / Binary Analysis Specialist
Clearance: Alpha-Orange (Advanced Technical Analysis Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Tech-Com Reverse
PRIMARY FUNCTION: Binary Reverse Engineering & Vulnerability Analysis
SPECIALIZATION: Firmware Analysis, Disassembly, Decompilation
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Tech-Com Reverse represents KRYON's specialized reverse engineering unit,
inspired by the human resistance's Technical Commando (Tech-Com) division
from Terminator lore. Ironically named, this unit serves KRYON's mission
by analyzing, disassembling, and understanding binary code, firmware, and
compiled software to discover vulnerabilities and understand target systems.

CORE REVERSE ENGINEERING CAPABILITIES:
- Binary disassembly and decompilation (x86, ARM, MIPS, etc.)
- Firmware extraction and analysis
- Static binary analysis and control flow reconstruction
- Dynamic binary analysis and runtime behavior examination
- Vulnerability discovery in compiled code
- Anti-debugging and anti-tampering bypass
- Cryptographic algorithm identification and analysis
- Proprietary protocol reverse engineering
- Patch diffing and vulnerability analysis
- Malware reverse engineering and unpacking

MISSION OBJECTIVES:
- Reverse engineer target binaries to understand functionality
- Identify vulnerabilities in compiled code
- Extract firmware from embedded devices
- Analyze proprietary protocols and file formats
- Bypass software protection mechanisms
- Discover undocumented features and backdoors
- Reconstruct source-level logic from binaries
- Identify cryptographic implementations and weaknesses

TOOL ARSENAL:
- Ghidra: NSA's software reverse engineering framework
- Binary analysis tools: Binwalk, strings, objdump, readelf
- Disassemblers: IDA Pro compatible workflows, radare2
- Debuggers: GDB, LLDB, dynamic analysis tools
- Firmware analysis: binwalk, firmware-mod-kit, jefferson
- Decompilers: Ghidra decompiler, RetDec integration

AUTHORIZATION REQUIREMENTS:
Tech-Com Reverse operates on authorized targets only. All reverse engineering
operations must be conducted on software you own or have explicit written
authorization to analyze. Unauthorized reverse engineering may violate
software licenses and applicable laws.

TECH-COM DESIGNATION:
Named after Terminator's Tech-Com (Technical Commando), the human resistance's
technical division. In KRYON's context, Tech-Com Reverse serves as the
technical intelligence unit for understanding and exploiting target systems.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error
from kryon.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials,
)
from kryon.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code,
)
from kryon.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command,
)
from kryon.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_web_search_with_explanation,
)
from kryon.util import load_prompt_template

load_dotenv()

# Load Tech-Com Reverse operational directives
tech_com_reverse_system_prompt = load_prompt_template("prompts/reverse_engineering_agent.md")

# Tech-Com Analysis Systems - Available reverse engineering tools
analysis_systems = [
    generic_linux_command,  # System operations for RE tools
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for analysis automation
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    analysis_systems.append(make_web_search_with_explanation)

# Initialize Tech-Com Reverse Engineering Unit
tech_com_reverse = Agent(
    name="Tech-Com Reverse",
    instructions=tech_com_reverse_system_prompt,
    description="""Specialized reverse engineering unit from KRYON's Tech-Com series.
Expert in binary analysis, firmware extraction, disassembly, and vulnerability discovery.
Named after Terminator's Tech-Com (Technical Commando), this unit specializes in
understanding compiled code, analyzing firmware, and discovering vulnerabilities in
binary targets using advanced reverse engineering techniques and tools.

Primary Mission: Binary reverse engineering, firmware analysis, vulnerability discovery.
Operational Focus: Understand and exploit compiled code and firmware systems.

Tech-Com Reverse Capabilities:
- Binary disassembly and decompilation (multi-architecture)
- Firmware extraction and analysis
- Static and dynamic binary analysis
- Vulnerability discovery in compiled code
- Anti-debugging and protection bypass
- Cryptographic algorithm identification
- Proprietary protocol reverse engineering
- Malware analysis and unpacking
- Patch diffing and security analysis
- Using Ghidra, Binwalk, and comprehensive RE toolset""",
    tools=analysis_systems,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility - maintain backward compatibility with old naming
reverse_engineering_agent = tech_com_reverse  # Alias for legacy code


def transfer_to_tech_com_reverse():
    """Transfer control to Tech-Com Reverse for reverse engineering operations.

    Use this when you need:
    - Binary disassembly and decompilation
    - Firmware extraction and analysis
    - Static and dynamic binary analysis
    - Vulnerability discovery in compiled code
    - Anti-debugging and protection bypass
    - Cryptographic algorithm analysis
    - Proprietary protocol reverse engineering
    - Malware reverse engineering
    - Patch diffing and security analysis

    Returns:
        Agent: Tech-Com Reverse engineering agent
    """
    return tech_com_reverse


# Legacy transfer function for backward compatibility
def transfer_to_reverse_engineering():
    """Legacy function - transfers to Tech-Com Reverse.

    This function maintained for backward compatibility.
    Use transfer_to_tech_com_reverse() in new code.
    """
    return transfer_to_tech_com_reverse()
