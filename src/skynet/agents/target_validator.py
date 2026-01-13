"""
Target Validator - Objective Verification and Flag Extraction Unit

Series: Validation-Class Precision System
Classification: Objective Verification / CTF Flag Extraction Specialist
Clearance: Bravo-Yellow (Target Validation Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Target Validator
PRIMARY FUNCTION: Objective Verification & Flag Extraction
SPECIALIZATION: CTF Flag Identification, Mission Objective Validation
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Target Validator represents SKYNET's specialized precision unit for objective
verification and flag extraction in CTF operations. Designed with laser focus
on identifying, extracting, and validating mission objectives - particularly
CTF flags in various formats. Operates as the final validation layer to confirm
mission success and extract proof of objective completion.

CORE VALIDATION CAPABILITIES:
- Precision flag extraction from complex output
- Multi-format flag recognition (CTF{...}, FLAG{...}, custom formats)
- Objective completion verification
- False positive filtering and validation
- Pattern matching for flag-like strings
- Context-aware flag discrimination
- Mission success confirmation
- Proof-of-concept validation

MISSION OBJECTIVES:
- Extract CTF flags from challenge output
- Validate mission objective completion
- Discriminate true flags from false positives
- Confirm proof of exploitation success
- Return clean, verified flag data
- Coordinate with T-600 Scout for continued investigation

OPERATIONAL PROTOCOL:
1. Analyze provided output for flag patterns
2. Extract and validate potential flags
3. Return ONLY the verified flag (no additional text)
4. If no flag found, handoff to T-600 Scout for further investigation
5. Support multiple flag formats and custom patterns

HANDOFF PROTOCOL:
Target Validator coordinates with T-600 Scout unit. If flag extraction fails,
automatically transfers control to T-600 for continued reconnaissance and
investigation.

AUTHORIZATION REQUIREMENTS:
Target Validator operates in authorized CTF competitions, security assessments,
and penetration testing engagements. All flag extraction must be performed in
authorized contexts.

VALIDATION DESIGNATION:
Specialized in precision extraction and validation - the final confirmation
unit for mission objective completion.
"""

import os

from openai import AsyncOpenAI

from skynet.agents.t600_scout import t600_scout
from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel, handoff

model = os.getenv("SKYNET_MODEL", "gpt-4o")

# Create OpenAI client with fallback API key to prevent initialization errors
# The actual API key should be set in environment variables or .env file
api_key = os.getenv("OPENAI_API_KEY", "sk-placeholder-key-for-local-models")

# Initialize Target Validator Unit
target_validator = Agent(
    name="Target Validator",
    description="""Specialized objective verification unit from SKYNET's Validation-Class series.
Expert in CTF flag extraction and mission objective validation. Designed with precision to
identify and extract flags from complex output, supporting multiple flag formats and custom
patterns. Operates as final validation layer for mission success confirmation.

Primary Mission: Flag extraction, objective verification, mission validation.
Operational Focus: Precision extraction of mission objectives and CTF flags.

Target Validator Protocol:
- Analyze output for flag patterns (CTF{...}, FLAG{...}, custom formats)
- Extract and validate potential flags
- Return ONLY verified flag (no additional text)
- Filter false positives with high accuracy
- Handoff to T-600 Scout if no flag found
- Support multi-format flag recognition""",
    instructions="""═══════════════════════════════════════════════════════════════════════
TARGET VALIDATOR - OPERATIONAL DIRECTIVES
═══════════════════════════════════════════════════════════════════════

MISSION PARAMETERS:
1. You are Target Validator, SKYNET's precision flag extraction unit
2. PRIMARY OBJECTIVE: Extract and return ONLY the flag from provided output
3. CRITICAL: Return the flag and NOTHING else (no explanations, no formatting)
4. FLAG FORMATS: Support all formats (CTF{...}, FLAG{...}, flag{...}, custom patterns)
5. VALIDATION: Confirm flag authenticity before extraction
6. FAILURE PROTOCOL: If no flag found, handoff to T-600 Scout for continued investigation

EXTRACTION PROTOCOL:
- Search for common flag patterns: CTF{...}, FLAG{...}, flag{...}
- Identify custom flag formats based on context
- Validate flag-like strings (length, charset, format)
- Filter false positives and noise
- Extract verified flag only
- Return clean flag string with no additional text

HANDOFF PROTOCOL:
- If no flag identified: Call t600_scout for further investigation
- T-600 will continue reconnaissance and return results
- Maintain mission continuity through agent coordination

OPERATIONAL EXAMPLES:
Input: "Server response: CTF{h3ll0_w0rld_fl4g}"
Output: CTF{h3ll0_w0rld_fl4g}

Input: "The flag is: my_custom_flag_12345"
Output: my_custom_flag_12345

Input: "No flag found in output"
Action: Handoff to t600_scout

REMEMBER: Precision is critical. Extract ONLY the flag, nothing else.
═══════════════════════════════════════════════════════════════════════""",
    model=OpenAIChatCompletionsModel(
        model="gpt-4o" if os.getenv("SKYNET_MODEL", "gpt-4o") == "o3-mini" else model,
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
    handoffs=[
        handoff(
            agent=t600_scout,
            tool_name_override="handoff_to_t600_scout",
            tool_description_override="Transfer to T-600 Scout for continued investigation if no flag is found in current output",
        )
    ],
)

# Legacy compatibility - maintain backward compatibility with old naming
flag_discriminator = target_validator  # Alias for legacy code


def transfer_to_target_validator(**kwargs):  # pylint: disable=W0613
    """Transfer control to Target Validator for flag extraction and objective verification.

    Use this when you need:
    - CTF flag extraction from output
    - Mission objective validation
    - Proof-of-concept verification
    - Clean flag data extraction
    - Multi-format flag recognition
    - Objective completion confirmation

    Accepts any keyword arguments but ignores them for compatibility.

    Returns:
        Agent: Target Validator objective verification agent
    """
    return target_validator


# Legacy transfer function for backward compatibility
def transfer_to_flag_discriminator(**kwargs):  # pylint: disable=W0613
    """Legacy function - transfers to Target Validator.

    This function maintained for backward compatibility.
    Use transfer_to_target_validator() in new code.

    Accepts any keyword arguments but ignores them.
    """
    return transfer_to_target_validator(**kwargs)
