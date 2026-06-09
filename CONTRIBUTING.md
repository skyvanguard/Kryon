# Contributing to KRYON

Thank you for your interest in contributing to KRYON!

## Quick Start

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Setup

```bash
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon

# With uv (recommended)
make sync

# Or with pip
pip install -e .[dev,rag,tracing,viz,voice]
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feat/your-feature
# or
git checkout -b fix/bug-description
```

### 2. Make Changes and Run Checks

```bash
make format    # Format with ruff
make lint      # Lint check
make tests     # Run test suite
```

### 3. Commit

```bash
git commit -m "feat: add new security agent for wireless security"
```

**Commit prefixes:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `ci:`

### 4. Push and Create PR

```bash
git push origin feat/your-feature
```

## Testing

```bash
make tests                          # All tests
pytest tests/test_kryon_imports.py  # Single file
make coverage                       # With coverage report
```

Tests use `FakeModel` to mock LLM responses and prevent accidental API calls. See `tests/conftest.py` for details.

To allow real API calls in a test: `@pytest.mark.allow_call_model_methods`

### Snapshots

```bash
make snapshots-fix      # Fix broken snapshots
make snapshots-create   # Create new snapshots
```

## Coding Standards

- Python 3.10+ with type hints
- Google-style docstrings
- Ruff formatter, 120 char line limit
- `async/await` for I/O operations

## Creating New Agents

1. Create `src/kryon/agents/your_agent.py`:

```python
from kryon.sdk.agents import Agent, function_tool

your_agent = Agent(
    name="Your Agent Name",
    description="Brief description for CLI",
    instructions="You are a specialized agent that...",
    tools=[your_tool],
)
```

2. Create system prompt at `src/kryon/prompts/system_your_agent.md`
3. Add import to `src/kryon/agents/__init__.py`
4. Add tests at `tests/agents/test_your_agent.py`

## Creating New Tools

```python
from kryon.sdk.agents import function_tool, RunContextWrapper

@function_tool
async def your_tool(ctx: RunContextWrapper, target: str) -> str:
    """Brief description for the LLM."""
    # Implementation
    return result
```

Export in `src/kryon/tools/{category}/__init__.py` and add tests.

## Architecture

- `src/kryon/agents/` — LLM-powered security agents (use `create_agent()` from `base.py`)
- `src/kryon/server/` — FastAPI REST API at `/api/v1/*`
- `src/kryon/memory/` — SQLite persistence with schema migrations
- `src/kryon/intelligence/` — MITRE ATT&CK mapping, CVE enrichment
- `src/kryon/knowledge/` — RAG system with 408+ seed documents
- `src/kryon/reporting/` — HTML/PDF report generation (executive, technical, PCI-DSS, SOC2)
- `src/kryon/compliance/` — PCI-DSS v4.0 and SOC 2 Type II compliance mapping
- `src/kryon/integrations/` — SIEM/SOAR (Splunk, QRadar, Elastic)
- `src/kryon/tenancy/` — Tenant scaffolding (scope policy, quotas). **Production is single-tenant per deployment** — the shared-DB multi-tenant path is not wired into the server and is not supported; isolation is at the instance boundary or via `SeparateDatabaseStrategy` (DB file per tenant).
- `src/kryon/engagements/` — Multi-day autonomous pentesting

## Security

- Never commit secrets or API keys
- All offensive tools must document authorization requirements
- Implement guardrails where appropriate
- Validate and sanitize all user inputs
- See [SECURITY.md](SECURITY.md) for vulnerability reporting

## PR Checklist

- [ ] `make format` and `make lint` pass
- [ ] `make tests` pass
- [ ] New code has tests
- [ ] Commit messages follow convention
- [ ] No secrets or credentials included

---

**Thank you for contributing to KRYON!**
