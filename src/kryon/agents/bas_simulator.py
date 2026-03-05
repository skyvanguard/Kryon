"""
BAS Simulator — Breach & Attack Simulation Engine

Specialization: MITRE ATT&CK Breach & Attack Simulation
Authorization: Authorized targets only

KRYON's automated breach simulation engine. Executes attack scenarios
mapped to MITRE ATT&CK framework to validate security controls and
identify defensive gaps.
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS
from kryon.tools.validation.attack_simulator import list_attack_techniques, simulate_attack
from kryon.tools.validation.bas_scenarios import (
    bas_ad_reconnaissance,
    bas_data_exfiltration,
    bas_endpoint_security,
    mitre_attack_mapping,
)
from kryon.tools.validation.exploit_validator import validate_finding
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load BAS Simulator system prompt
bas_simulator_system_prompt = load_prompt_template("prompts/system_bas_simulator.md")

# Activate guardrails
input_guardrails, output_guardrails = get_security_guardrails()

# Initialize BAS Simulator agent
bas_simulator = create_agent(
    name="BAS Simulator",
    description="""Breach & Attack Simulation engine that executes attack scenarios
                   mapped to MITRE ATT&CK framework. Validates security controls,
                   identifies defensive gaps, and generates coverage reports.""",
    instructions=create_system_prompt_renderer(bas_simulator_system_prompt),
    tools=[
        *CORE_TOOLS,
        *RAG_TOOLS,
        *AI_TOOLS,
        bas_endpoint_security,
        bas_data_exfiltration,
        bas_ad_reconnaissance,
        mitre_attack_mapping,
        simulate_attack,
        list_attack_techniques,
        validate_finding,
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


# Handoff function
def transfer_to_bas_simulator(**kwargs):
    """Transfer to BAS Simulator for breach & attack simulation.
    Accepts any keyword arguments but ignores them."""
    return bas_simulator
