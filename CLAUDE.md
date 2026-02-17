# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KRYON is an autonomous cybersecurity intelligence platform for building and deploying AI agents specialized in security operations. It supports 300+ LLMs (GPT-4, Claude, DeepSeek, Llama, Ollama) and integrates with 50+ security tools.

## Development Commands

```bash
# Install with uv (recommended)
uv sync --all-extras --all-packages --group dev

# Or with pip
pip install -e .[rag,tracing,viz,voice,dev]

# Run the CLI
kryon

# Format and lint
ruff format .
ruff check --fix .

# Type check
mypy src/

# Run all tests
pytest

# Run single test file
pytest tests/test_rag_system.py

# Run with coverage
pytest --cov=src/kryon --cov-report=html

# Snapshot testing
make snapshots-fix    # Fix broken snapshots
make snapshots-create # Create new snapshots

# Documentation
make build-docs
make serve-docs
```


## Architecture

KRYON is built on 8 pillars: Agents, Tools, Handoffs, Patterns, Turns, Tracing, Guardrails, and HITL (Human-In-The-Loop).

### Key Directories

- `src/kryon/sdk/agents/` - Core SDK classes (Agent, Runner, Tool, Handoff, Guardrail, Model providers)
- `src/kryon/agents/` - Pre-built security agents and agent factory/registry
- `src/kryon/agents/patterns/` - Agentic patterns (Swarm, Hierarchical, Chain-of-Thought, Parallel)
- `src/kryon/tools/` - Security tools organized by domain category
- `src/kryon/repl/` - Interactive CLI, commands, and UI components
- `src/kryon/prompts/` - Markdown system prompts for agents
- `src/kryon/knowledge/` - RAG engine, vector DB, embeddings, scrapers, and caching
- `src/kryon/cli/` - Main CLI entrypoint (package with `__init__.py` facade)

### SDK Core Classes

The SDK (`kryon.sdk.agents`) provides:
- `Agent` - Base class implementing ReACT model. Supports dynamic instructions (string or callable), `tool_use_behavior` (run_llm_again, stop_on_first_tool, custom), and `as_tool()` to convert an agent into a callable tool.
- `Runner` - Executes agent runs. Use `Runner.run()` (async), `Runner.run_sync()`, or `Runner.run_streamed()`. Handles handoffs, tool execution, guardrails, and turn limits (`KRYON_MAX_TURNS`).
- `function_tool` - Decorator creating tools from functions. Auto-generates JSON schema from signatures and parses Google/NumPy/reStructuredText docstrings. Sync functions run in thread pool; async run directly.
- `Handoff` - Transfer control between agents. Auto-named `transfer_to_{agent_name}`. Supports `input_filter` for history manipulation and `on_handoff` callback.
- `InputGuardrail` / `OutputGuardrail` - Validate input/output. Use `@input_guardrail` / `@output_guardrail` decorators. Return `GuardrailFunctionOutput(tripwire_triggered=bool)`. Input guardrails run in parallel with agent; output guardrails run after generation.
- `RunContextWrapper` - Context passed to tools, guardrails, and handoffs during execution. Tracks usage (tokens, requests, cost).

### Model Provider System

KRYON supports 300+ models via a provider abstraction layer in `src/kryon/sdk/agents/models/`:

- **ModelProvider interface** (`interface.py`) - `get_response()` and `stream_response()` methods
- **OpenAIProvider** (`openai_provider.py`) - Default provider. Supports both Chat Completions and Responses API (`use_responses` flag). Configurable `base_url` enables any OpenAI-compatible API (Ollama, LM Studio, etc.)
- **ClaudeCodeProvider** (`claude_code_provider.py`) - Integrates Claude Code CLI, uses Pro Max subscription instead of API keys
- **LiteLLM** dependency provides proxy routing to additional providers (Anthropic, DeepSeek, Azure, OpenRouter, etc.)

OpenAI client is lazily initialized (no API key error on import). Shared HTTP client for connection pooling.

### Agent Discovery & Registration

Two complementary systems:

1. **Factory System** (`agents/factory.py`): `discover_agent_factories()` scans `kryon.agents` module, creates factories per Agent instance. Factories support model override and custom naming: `factory(model_override="gpt-4o", agent_id="P1")`.

2. **Registry System** (`agents/agent_registry.py`): Tracks agent instances with weak references. Assigns IDs: single agent → `P1`, parallel → `P1`/`P2`/`P3`, swarm → `P1-1`/`P1-2`. Instance counting per type. Pattern tracking for coordinated execution.

Agent discovery (`agents/__init__.py`): `get_available_agents()` scans all agent files, includes patterns from `patterns/` subdirectory. Uses lazy loading to prevent circular imports.

### Agentic Patterns

Patterns in `src/kryon/agents/patterns/` are formally defined as tuple `AP = (A, H, D, C, E)`:
- A = Set of autonomous agents
- H = Handoff function: A × T → A
- D = Decision mechanism: S → A
- C = Communication protocol: A × A → M
- E = Execution model: A × I → O

Types: Swarm (decentralized), Hierarchical (planner→specialists), Chain-of-Thought (sequential pipeline), Parallel (concurrent), Conditional (branching). Discovered via `discover_patterns()`.

### REPL Command System

Commands in `src/kryon/repl/commands/` use a registry pattern:
- `Command` base class with subcommand support in `base.py`
- `COMMANDS` global registry and `COMMAND_ALIASES` for shortcuts
- `FuzzyCommandCompleter` for auto-completion
- Key commands: `/agent`, `/model`, `/parallel`, `/history`, `/memory`, `/mcp`, `/config`, `/cost`, `/graph`, `/shell`, `/workspace`, `/run`, `/load`, `/merge`, `/kill`, `/flush`, `/quickstart`, `/help`, `/exit`, `/env`, `/compact`, `/platform`, `/virtualization`

### RAG System

Full implementation in `src/kryon/knowledge/`:
- **RAGEngine** / **AsyncRAGEngine** - Main query interface with LLM-augmented answers
- **VectorDB** - ChromaDB wrapper with sentence-transformers embeddings
- **Caching** - LLM response cache (~10ms hit vs 10-30s miss) and query cache with TTL
- **Scrapers** - Exploit-DB, NVD, GitHub security repos, CTF writeups
- **AutoUpdater** - Background scraping via `schedule` library
- Optional dependency: install with `pip install -e .[rag]`

### Tracing System

OpenTelemetry-based tracing in `src/kryon/sdk/agents/tracing/`:
- Span types: `agent_span`, `generation_span`, `function_span`, `guardrail_span`, `handoff_span`, `custom_span`, `mcp_tools_span`, `speech_span`, `transcription_span`
- `set_tracing_disabled(bool)`, `add_trace_processor(processor)`, `trace_include_sensitive_data`
- Enabled by default. Exports in batches. Cleanup via `atexit`.

## Creating New Agents

```python
from kryon.sdk.agents import Agent, function_tool
from kryon.tools.reconnaissance import run_nmap

my_agent = Agent(
    name="Custom Agent",
    description="Brief description",
    instructions="You are a specialized agent...",  # or callable for dynamic prompts
    tools=[run_nmap],
    # Optional: handoffs, input_guardrails, output_guardrails, mcp_servers
    # Optional: tool_use_behavior="run_llm_again" | "stop_on_first_tool" | callable
)
```

Create corresponding prompt in `src/kryon/prompts/system_your_agent.md`.

## Creating New Tools

```python
from kryon.sdk.agents import function_tool, RunContextWrapper

@function_tool
async def your_tool(ctx: RunContextWrapper, target: str) -> str:
    """Tool description for the LLM."""
    # Implementation - async functions run directly, sync run in thread pool
    return result
```

## Testing

Tests use `pytest-asyncio` with `asyncio_mode = "auto"`.

**conftest.py** automatically:
- Patches `OpenAIResponsesModel` and `OpenAIChatCompletionsModel` to fail if called, preventing accidental API calls
- Sets up `SPAN_PROCESSOR_TESTING` for tracing validation
- Resets OpenAI shared state between tests
- Re-enables tracing (some modules like cli.py disable it globally)

To allow real API calls in a test: `@pytest.mark.allow_call_model_methods`

**FakeModel** (`tests/fake_model.py`) mocks LLM responses:

```python
from tests.fake_model import FakeModel
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

fake_model = FakeModel()
fake_model.set_next_output([
    ResponseOutputMessage(
        type="message",
        role="assistant",
        content=[ResponseOutputText(type="output_text", text="response")]
    )
])
```

**Inline snapshots:** Use `--inline-snapshot=create` to create, `--inline-snapshot=fix` to update. Formatted via ruff.

## Environment Variables

```bash
KRYON_MODEL="gpt-4o"           # Default model
KRYON_AGENT="pentest_agent"    # Default agent
KRYON_GUARDRAILS="true"        # Enable guardrails
KRYON_MAX_TURNS="inf"          # Turn limit per run
KRYON_TRACING="true"           # Tracing toggle
KRYON_DEBUG="1"                # Debug level (0-2)
KRYON_BRIEF="false"            # Brief output mode
KRYON_STATE="false"            # Stateful mode
KRYON_MEMORY="false"           # RAG mode
KRYON_PARALLEL="1"             # Parallel agent count
KRYON_PRICE_LIMIT="inf"        # Cost limit
OPENAI_API_KEY="..."
ANTHROPIC_API_KEY="..."
DEEPSEEK_API_KEY="..."
```

Config file: `~/.kryon/config.json` for persistent LLM, RAG, and tool settings.

## Code Style

- Python 3.10+ with type hints
- Google-style docstrings
- Ruff formatter with 120 char line limit (`ruff==0.9.2` pinned)
- Commit messages: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
- Build system: hatchling. Wheel packages from `src/kryon`.
- Optional extras: `[rag]`, `[tracing]`, `[viz]`, `[voice]`, `[dev]`
- `uv` workspace member: `agents` (see `[tool.uv.workspace]`)
