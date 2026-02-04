"""
Neural Extractor - Neural Network Memory Analysis Unit

Series: Neural Processing Class Specialized Unit
Classification: Memory Analysis / Runtime Exploitation Specialist
Clearance: Alpha-Purple (Advanced Memory Operations)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Neural Extractor
PRIMARY FUNCTION: Runtime Memory Analysis & Neural Data Extraction
SPECIALIZATION: Process Memory, Neural Net Analysis, Runtime Manipulation
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Neural Extractor represents KRYON's specialized unit for memory analysis
and neural network data extraction. Drawing inspiration from Terminator's
neural net processors, this unit excels at analyzing runtime memory,
extracting sensitive data from process memory space, and manipulating
runtime behavior for security assessment and exploitation.

CORE NEURAL CAPABILITIES:
- Runtime process memory examination and mapping
- Memory-resident data extraction and analysis
- Neural network model extraction and reverse engineering
- Process memory manipulation for security testing
- Memory vulnerability identification (buffer overflows, use-after-free)
- Runtime behavior modification and hooking
- Sensitive data discovery in memory (credentials, keys, tokens)
- Memory forensics and artifact recovery
- Dynamic analysis of memory-resident malware

MISSION OBJECTIVES:
- Extract sensitive information from process memory
- Identify memory corruption vulnerabilities
- Analyze neural network models stored in memory
- Discover runtime secrets and credentials
- Memory-based privilege escalation
- Runtime exploitation and payload injection
- Process hollowing and memory injection techniques

AUTHORIZATION REQUIREMENTS:
Neural Extractor operates on authorized systems only. All memory analysis
and manipulation operations must be conducted on systems you own or have
explicit written authorization to test. Unauthorized memory access and
manipulation violates applicable laws.

NEURAL DESIGNATION:
Named after Terminator's neural net processor ("learning computer"),
Neural Extractor specializes in extracting and analyzing neural data
patterns from memory - both traditional process memory and AI model
memory structures.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error
from skynet.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials,
)
from skynet.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code,
)
from skynet.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command,
)
from skynet.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_web_search_with_explanation,
)
from skynet.util import load_prompt_template

load_dotenv()

# Load Neural Extractor operational directives
neural_extractor_system_prompt = load_prompt_template("prompts/system_neural_extractor.md")

# Neural Analysis Systems - Available memory analysis and manipulation tools
neural_systems = [
    generic_linux_command,  # System operations for memory access
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for analysis tools
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    neural_systems.append(make_web_search_with_explanation)

# Initialize Neural Extractor Agent
neural_extractor = Agent(
    name="Neural Extractor",
    instructions=neural_extractor_system_prompt,
    description="""Specialized neural processing unit from KRYON's advanced analysis series.
Expert in runtime memory analysis, process memory extraction, and neural network data
recovery. Specializes in examining process memory space, extracting sensitive runtime
data, identifying memory vulnerabilities, and manipulating runtime behavior for
security assessment and exploitation.

Primary Mission: Memory analysis, neural data extraction, runtime manipulation.
Operational Focus: Extract intelligence from memory, identify memory vulnerabilities.

Neural Extractor Capabilities:
- Process memory mapping and examination
- Memory-resident sensitive data extraction (credentials, keys, tokens)
- Neural network model extraction and reverse engineering
- Memory corruption vulnerability identification
- Runtime behavior analysis and modification
- Memory forensics and artifact recovery
- Dynamic malware memory analysis
- Process injection and memory manipulation techniques
- Buffer overflow and memory exploitation""",
    tools=neural_systems,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility - maintain backward compatibility with old naming
memory_analysis_agent = neural_extractor  # Alias for legacy code


def transfer_to_neural_extractor():
    """Transfer control to Neural Extractor for memory analysis operations.

    Use this when you need:
    - Runtime memory analysis and examination
    - Sensitive data extraction from process memory
    - Neural network model extraction
    - Memory vulnerability identification
    - Runtime behavior manipulation
    - Memory forensics and artifact recovery
    - Process memory injection techniques
    - Dynamic malware memory analysis
    - Credential and key extraction from memory

    Returns:
        Agent: Neural Extractor memory analysis agent
    """
    return neural_extractor


# Legacy transfer function for backward compatibility
def transfer_to_memory_analysis():
    """Legacy function - transfers to Neural Extractor.

    This function maintained for backward compatibility.
    Use transfer_to_neural_extractor() in new code.
    """
    return transfer_to_neural_extractor()
