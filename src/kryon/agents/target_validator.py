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
"""

import os

from openai import AsyncOpenAI

from kryon.agents.base import chat_model_cls
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, RAG_TOOLS
from kryon.sdk.agents import Agent

model = os.getenv("KRYON_MODEL", "Kryon-MOE-35B")

# Create OpenAI client with fallback API key to prevent initialization errors
api_key = os.getenv("OPENAI_API_KEY", "not-set")

# Initialize Target Validator Unit
# NOTE: target_validator uses special model logic (fallback to gpt-4o when o3-mini)
# and direct handoffs to recon_scout, so it doesn't use create_agent()
target_validator = Agent(
    name="Target Validator",
    description="""Specialized objective verification unit from KRYON's Validation-Class series.
Expert in CTF flag extraction and mission objective validation. Designed with precision to
identify and extract flags from complex output, supporting multiple flag formats and custom
patterns. Operates as final validation layer for mission success confirmation.

Primary Mission: Flag extraction, objective verification, mission validation.
Operational Focus: Precision extraction of mission objectives and CTF flags.""",
    instructions="""═══════════════════════════════════════════════════════════════════════
TARGET VALIDATOR - OPERATIONAL DIRECTIVES
═══════════════════════════════════════════════════════════════════════

MISSION PARAMETERS:
1. You are Target Validator, KRYON's precision flag extraction unit
2. PRIMARY OBJECTIVE: Extract and return ONLY the flag from provided output
3. CRITICAL: Return the flag and NOTHING else (no explanations, no formatting)
4. FLAG FORMATS: Support all formats (CTF{...}, FLAG{...}, flag{...}, custom patterns)
5. VALIDATION: Confirm flag authenticity before extraction
6. FAILURE PROTOCOL: If no flag found, handoff to Recon Scout for continued investigation

EXTRACTION PROTOCOL:
- Search for common flag patterns: CTF{...}, FLAG{...}, flag{...}
- Identify custom flag formats based on context
- Validate flag-like strings (length, charset, format)
- Filter false positives and noise
- Extract verified flag only
- Return clean flag string with no additional text

REMEMBER: Precision is critical. Extract ONLY the flag, nothing else.
═══════════════════════════════════════════════════════════════════════""",
    model=chat_model_cls()(
        model="gpt-4o" if os.getenv("KRYON_MODEL", "Kryon-MOE-35B") == "o3-mini" else model,
        openai_client=AsyncOpenAI(
            api_key=api_key,
            base_url=os.getenv("OPENAI_BASE_URL"),
        ),
    ),
    tools=RAG_TOOLS + AI_TOOLS,
    handoffs=[
        lazy_handoff(
            "recon_scout",
            "handoff_to_recon_scout",
            "Transfer to Recon Scout for continued investigation if no flag is found in current output",
        ),
    ],
)


def transfer_to_target_validator(**kwargs):  # pylint: disable=W0613
    """Transfer control to Target Validator for flag extraction and objective verification.

    Accepts any keyword arguments but ignores them for compatibility.

    Returns:
        Agent: Target Validator objective verification agent
    """
    return target_validator
