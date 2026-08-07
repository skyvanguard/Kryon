"""
KRYON agents abstraction layer

KRYON abstracts its cybersecurity behavior via agents and agentic patterns.

An Agent in an intelligent system that interacts with some environment.
More technically, and agent is anything that can be viewed as perceiving
its environment through sensors and acting upon that environment through
actuators (Russel & Norvig, AI: A Modern Approach). In cybersecurity,
an Agent interacts with systems and networks, using peripherals and
network interfaces as sensors, and executing network actions as
actuators.

An Agentic Pattern is a structured design paradigm in artificial
intelligence systems where autonomous or semi-autonomous agents operate
within a "defined interaction framework" to achieve a goal. These
patterns specify the organization, coordination, and communication
methods among agents, guiding decision-making, task execution,
and delegation.

An agentic pattern (`AP`) can be formally defined as a tuple:


\\[
AP = (A, H, D, C, E)
\\]

where:

- **\\(A\\) (Agents):** A set of autonomous entities, \\( A = \\{a_1, a_2, ..., a_n\\} \\), each with defined roles, capabilities, and internal states.
- **\\(H\\) (Handoffs):** A function \\( H: A \times T \to A \\) that governs how tasks \\( T \\) are transferred between agents based on predefined logic (e.g., rules, negotiation, bidding).
- **\\(D\\) (Decision Mechanism):** A decision function \\( D: S \to A \\) where \\( S \\) represents system states, and \\( D \\) determines which agent takes action at any given time.
- **\\(C\\) (Communication Protocol):** A messaging function \\( C: A \times A \to M \\), where \\( M \\) is a message space, defining how agents share information.
- **\\(E\\) (Execution Model):** A function \\( E: A \times I \to O \\) where \\( I \\) is the input space and \\( O \\) is the output space, defining how agents perform tasks.

| **Agentic Pattern** | **Description** |
|--------------------|------------------------|
| `Swarm` (Decentralized) | Agents share tasks and self-assign responsibilities without a central orchestrator. Handoffs occur dynamically. *An example of a peer-to-peer agentic pattern is the `CTF Agentic Pattern`, which involves a team of agents working together to solve a CTF challenge with dynamic handoffs.* |
| `Hierarchical` | A top-level agent (e.g., "PlannerAgent") assigns tasks via structured handoffs to specialized sub-agents. Alternatively, the structure of the agents is harcoded into the agentic pattern with pre-defined handoffs. |
| `Chain-of-Thought` (Sequential Workflow) | A structured pipeline where Agent A produces an output, hands it to Agent B for reuse or refinement, and so on. Handoffs follow a linear sequence. *An example of a chain-of-central_core agentic pattern is the `ReasonerAgent`, which involves a Reasoning-type LLM that provides context to the main agent to solve a CTF challenge with a linear sequence.*[^1] |
| `Auction-Based` (Competitive Allocation) | Agents "bid" on tasks based on priority, capability, or cost. A decision agent evaluates bids and hands off tasks to the best-fit agent. |
| `Recursive` | A single agent continuously refines its own output, treating itself as both executor and evaluator, with handoffs (internal or external) to itself. *An example of a recursive agentic pattern is the `CodeAgent` (when used as a recursive agent), which continuously refines its own output by executing code and updating its own instructions.* |

[^1]: Arguably, the Chain-of-Thought agentic pattern is a special case of the Hierarchical agentic pattern.
"""

# Standard library imports
import importlib
import os
import pkgutil

# Local application imports - lazy loaded to avoid circular imports
# Note: target_validator and transfer_to_flag_discriminator are imported on-demand
# via get_agent_by_name() to prevent circular import issues
from kryon.sdk.agents import Agent
from kryon.sdk.agents.handoffs import handoff as handoff

# Extend the search path for namespace packages (allows merging)
__path__ = pkgutil.extend_path(__path__, __name__)

# Get model from environment or use default
model = os.environ.get("KRYON_MODEL", "kryon-local")


PATTERNS = ["hierarchical", "swarm", "chain_of_thought", "auction_based", "recursive"]


class PatternAgent:
    """Wraps a Pattern object to look like an Agent for display purposes."""

    def __init__(self, pattern):
        self.name = pattern.name
        self.description = pattern.description
        if hasattr(pattern.type, "value"):
            self.pattern_type = pattern.type.value
        else:
            self.pattern_type = str(pattern.type)
        self.category = "pattern"
        self._pattern = pattern
        self.instructions = f"Pattern: {pattern.description}"
        self.tools = []
        self.handoffs = []
        self.model = None
        self.output_type = None


def get_available_agents(include_patterns: bool = True, *, build_unified: bool = True) -> dict[str, Agent]:  # pylint: disable=R0912  # noqa
    """
    Get a dictionary of all available agents compiled
    from the kryon/agents folder.

    Deduplicates aliases (multiple variable names pointing to the same
    Agent object) and filters out sub-agents.

    Args:
        include_patterns: Whether to include agentic patterns in the result.

    Returns:
        Dictionary mapping agent names to Agent instances
    """
    # Phase 1: Collect all Agent instances from agent modules
    raw_agents = {}
    for _, name, _ in pkgutil.iter_modules(__path__, __name__ + "."):
        try:
            module = importlib.import_module(name)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, Agent) and not attr_name.startswith("_"):
                    raw_agents[attr_name] = attr
        except (ImportError, AttributeError):
            pass

    # Phase 2: Deduplicate by id() — when multiple names reference the
    # same Agent object (legacy aliases), keep only the canonical name.
    seen_ids: dict[int, str] = {}  # id(agent) -> best key
    for key, agent in raw_agents.items():
        aid = id(agent)
        if aid not in seen_ids:
            seen_ids[aid] = key
        else:
            # Prefer the key that matches agent.name in snake_case
            canonical = getattr(agent, "name", "").lower().replace(" ", "_")
            if key == canonical:
                seen_ids[aid] = key

    # Phase 3: Build deduplicated dict, filtering sub-agents
    agents_to_display = {}
    for _aid, key in seen_ids.items():
        agent = raw_agents[key]
        desc = (getattr(agent, "description", "") or "").lower()
        # Filter out sub-agents (embedded helper agents inside other agents)
        if "sub-unit" in desc or "sub-agent" in desc:
            continue
        agents_to_display[key] = agent

    # Phase 4: Optionally add patterns
    if include_patterns:
        # Check the patterns subdirectory for swarm agents
        patterns_path = os.path.join(os.path.dirname(__file__), "patterns")
        if os.path.exists(patterns_path) and os.path.isdir(patterns_path):  # pylint: disable=R1702  # noqa
            for _, name, _ in pkgutil.iter_modules([patterns_path], __name__ + ".patterns."):
                try:
                    module = importlib.import_module(name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if isinstance(attr, Agent) and not attr_name.startswith("_"):
                            if not hasattr(attr, "pattern"):
                                continue
                            if attr_name not in agents_to_display:
                                agents_to_display[attr_name] = attr
                except (ImportError, AttributeError):
                    pass

        # Add all patterns (parallel, swarm, etc.) as pseudo-agents
        from kryon.agents.patterns import PATTERNS

        for pattern_name, pattern_obj in PATTERNS.items():
            pseudo_agent = PatternAgent(pattern_obj)
            agents_to_display[pattern_name] = pseudo_agent

    # v2.x is unified-only: "kryon" is THE canonical agent. Expose it first so
    # validation / listing / selection (/agent, /parallel) accept it. The
    # legacy per-name agents were removed; any name resolves to this one via
    # get_agent_by_name. Omitted only if construction fails (e.g. no model cfg).
    if build_unified:
        try:
            from kryon.skills.unified_agent import create_unified_agent

            agents_to_display = {"kryon": create_unified_agent(), **agents_to_display}
        except Exception:  # noqa: BLE001
            pass
    else:
        # Lightweight path (health/count/list): expose "kryon" as a NAME without
        # the expensive build — create_unified_agent() does a SkillLoader disk
        # scan of ~106 playbooks AND opens a fresh AsyncOpenAI client that is
        # never closed, on EVERY call. A liveness probe hitting /health each
        # second would leak clients/FDs and defeat "fast, no external deps".
        # Value is None; callers needing the object use the default build.
        agents_to_display = {"kryon": None, **agents_to_display}

    return agents_to_display


def get_agent_module(agent_name: str) -> str:
    """
    Get the module name where a given agent is defined.

    Args:
        agent_name: Name of the agent
        (with or without '_agent' suffix)

    Returns:
        The full module name where the agent
        is defined (e.g., 'kryon.sdk.agents.basic')
    """
    # Try to import all agents from the agents folder
    for _, name, _ in pkgutil.iter_modules(__path__, __name__ + "."):
        try:
            module = importlib.import_module(name)
            # Look for Agent instances in the module
            for attr_name in dir(module):
                # Try both with and without _agent suffix
                if (attr_name == agent_name) and isinstance(getattr(module, attr_name), Agent):
                    return name
        except (ImportError, AttributeError):
            pass

    # Also check the patterns subdirectory
    patterns_path = os.path.join(os.path.dirname(__file__), "patterns")
    if os.path.exists(patterns_path) and os.path.isdir(patterns_path):
        for _, name, _ in pkgutil.iter_modules([patterns_path], __name__ + ".patterns."):
            try:
                module = importlib.import_module(name)
                # Look for Agent instances in the patterns module
                for attr_name in dir(module):
                    # Try both with and without _agent suffix
                    if (attr_name == agent_name) and isinstance(getattr(module, attr_name), Agent):
                        return name
            except (ImportError, AttributeError):
                pass

    return "unknown"


def get_agent_by_name(
    agent_name: str, custom_name: str = None, model_override: str = None, agent_id: str = None
) -> Agent:
    """
    Get a NEW unified "Kryon" agent instance.

    v2.x is unified-only: ``agent_name`` no longer selects a distinct agent —
    every request returns the skill-based Kryon agent (skills matched
    dynamically, subsuming the old static per-name agents). The parameter is
    retained for call-site compatibility (engage phases, parallel slots,
    handoffs, ``/agent`` switching).

    Args:
        agent_name: Retained for compatibility; does not select an agent.
        custom_name: Optional display name for the instance (e.g., "P1").
        model_override: Optional model to use instead of the default.
        agent_id: Optional agent ID (e.g., "P1", "P2", "P3").

    Returns:
        A NEW unified Kryon Agent instance.
    """
    # v2.x is UNIFIED-ONLY: every agent request resolves to the single
    # skill-based "Kryon" agent. The legacy per-name agents + factory were
    # removed — create_unified_agent() matches skills dynamically, which
    # subsumes what the static agents did. ``agent_name`` is kept for
    # call-site compatibility (engage phases, parallel slots, handoffs) but
    # no longer selects a distinct agent.
    from kryon.skills.unified_agent import create_unified_agent

    agent = create_unified_agent(model_override=model_override, agent_id=agent_id)
    if custom_name:
        try:
            agent.name = custom_name
        except Exception:  # noqa: BLE001
            pass

    # Attach any MCP tools configured for this slot (preserved from the
    # legacy path so MCP integrations keep working under the unified agent).
    try:
        from kryon.repl.commands.mcp import get_mcp_tools_for_agent

        mcp_tools = get_mcp_tools_for_agent(agent_name.lower())
        if mcp_tools:
            if not getattr(agent, "tools", None):
                agent.tools = []
            existing = {t.name for t in mcp_tools}
            agent.tools = [t for t in agent.tools if t.name not in existing] + list(mcp_tools)
    except ImportError:
        pass
    except Exception:  # noqa: BLE001
        pass

    return agent
