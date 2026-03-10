"""
API Fuzzer — OWASP API Security Top 10 Specialist

Specialization: REST/GraphQL/gRPC API Security Assessment
Authorization: Authorized targets only

KRYON's dedicated API security testing engine. Discovers, enumerates,
and fuzzes API endpoints to identify vulnerabilities aligned with the
OWASP API Security Top 10 (2023).
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, MEMORY_TOOLS, RAG_TOOLS
from kryon.tools.api_attacks.api_fuzzer import (
    discover_api_endpoints,
    fuzz_api_endpoint,
    parse_openapi_spec,
    test_auth_mechanisms,
    test_idor,
    test_rate_limiting,
)
from kryon.tools.validation.exploit_validator import validate_finding
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load API Fuzzer system prompt
api_fuzzer_system_prompt = load_prompt_template("prompts/system_api_fuzzer.md")

# Activate guardrails
input_guardrails, output_guardrails = get_security_guardrails()

# Initialize API Fuzzer agent
api_fuzzer = create_agent(
    name="API Fuzzer",
    description="""API security specialist that discovers, enumerates, and fuzzes API
                   endpoints to identify vulnerabilities aligned with the OWASP API
                   Security Top 10 (2023). Tests for BOLA/IDOR, broken authentication,
                   rate limiting gaps, and injection flaws.""",
    instructions=create_system_prompt_renderer(api_fuzzer_system_prompt),
    tools=[
        *CORE_TOOLS,
        *RAG_TOOLS,
        *AI_TOOLS,
        *MEMORY_TOOLS,  # Memory/learning
        parse_openapi_spec,
        discover_api_endpoints,
        fuzz_api_endpoint,
        test_idor,
        test_rate_limiting,
        test_auth_mechanisms,
        validate_finding,
    ],
    handoffs=[
        lazy_handoff(
            "vuln_hunter",
            "handoff_to_vuln_hunter",
            "Escalate to Vuln Hunter for deep analysis of API vulnerabilities found during fuzzing",
        ),
        lazy_handoff(
            "appsec_analyzer",
            "handoff_to_appsec_analyzer",
            "Escalate to AppSec Analyzer for broader application security testing beyond API layer",
        ),
        lazy_handoff(
            "intel_reporter",
            "handoff_to_reporter",
            "Escalate to Intel Reporter to document API security testing findings",
        ),
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


# Handoff function
def transfer_to_api_fuzzer(**kwargs):
    """Transfer to API Fuzzer for API security testing.
    Accepts any keyword arguments but ignores them."""
    return api_fuzzer
