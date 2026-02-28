"""
LLM Red Team — AI/ML Security Testing Agent

Specialization: LLM security, prompt injection, OWASP LLM Top 10
Authorization: Authorized targets only
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, LLM_SECURITY_TOOLS, RAG_TOOLS
from kryon.util import create_system_prompt_renderer, load_prompt_template

llm_red_team_system_prompt = load_prompt_template("prompts/system_llm_red_team.md")

tools_list = [
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    *LLM_SECURITY_TOOLS,
]

input_guardrails, output_guardrails = get_security_guardrails()

llm_red_team = create_agent(
    name="LLM Red Team",
    description="""AI/ML security testing agent specialized in LLM vulnerability
                   assessment, prompt injection, jailbreaking, and OWASP LLM Top 10.""",
    instructions=create_system_prompt_renderer(llm_red_team_system_prompt),
    tools=tools_list,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


def transfer_to_llm_red_team(**kwargs):
    """Transfer to LLM Red Team for AI security testing."""
    return llm_red_team
