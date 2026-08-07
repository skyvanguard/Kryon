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

## Creating New Capabilities (Playbooks Preferred)

**Preferí playbooks markdown en lugar de nuevos agentes Python.** Kryon v2.x usa un sistema basado en habilidades donde las capacidades se definen en playbooks `.md` dinámicos.

### Option 1: New Playbook (Recommended)

1. Create `src/kryon/skills/playbooks/your-skill.md`:

```markdown
---
triggers:
  tech: ["wordpress"]
  ports: [80, 443]
  keywords: ["web", "audit"]
required_tools: [wpscan, curl]
---

# Your Skill Title

Brief description of what this skill does.

## When to Use

When should this skill be activated?

## How It Works

Step-by-step workflow.
```

2. Add frontmatter with `triggers`, `required_tools`, and optional `pre_hooks`
3. Tests are automatic via skill loader (no separate test file needed)

### Option 2: New Tool (when a playbook needs new capability)

Most new capability is a **tool** wired into a skill's `required_tools`, not a new
agent. Add a `@function_tool` (see "Creating New Tools" below) and reference it from
your playbook's frontmatter. Creating a new Python `Agent` is almost never needed in
v2.x — the static per-name agent factory was removed and the unified agent subsumes it.
If you believe you genuinely need one, open an issue to discuss before implementing.

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

Kryon v2.x is **skill-based**: one unified agent that dynamically loads markdown playbooks based on target profile and intent. Prefer adding a skill over new Python modules.

- `src/kryon/skills/` — **primary interface**: markdown playbooks + loader, tool-budget selector, unified-agent composer, and the deterministic pre-hook runner
- `src/kryon/tools/` — `@function_tool` implementations grouped by kill-chain category
- `src/kryon/sdk/agents/` — agent runtime SDK (run loop, tool executor, model adapters, MCP integration)
- `src/kryon/agents/` — support only (model factory, guardrails, scope); the v1 static per-name agents were removed in v2.x
- `src/kryon/compliance/` — framework modules (PCI-DSS, CIS, NIST CSF, SOC 2, ISO 27001, HIPAA, GDPR, PSD2/FAPI, …) + per-OS/device deterministic checks
- `src/kryon/intelligence/` — MITRE ATT&CK mapping, CVE enrichment, and the reflective intel pipeline
- `src/kryon/learning/` — self-improving loop (ChromaDB experiences, draft synthesis, scoring)
- `src/kryon/knowledge/` — NVD + ExploitDB + writeup corpora (embedding RAG **off** by default)
- `src/kryon/reporting/` — HTML/PDF/DOCX report generation with reproducibility hashes
- `src/kryon/server/` — FastAPI REST API (JWT/RBAC)
- `src/kryon/tenancy/` — **single-tenant per deployment**; the shared-DB multi-tenant path is not supported (isolation at the instance boundary or DB-file-per-tenant)
- `src/kryon/{cli,repl,tui}/` — user interfaces (the `kryon` CLI is the entry point)

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

## License

By contributing to KRYON, you agree that your contributions will be licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later) — the same
license as the project.

---

**Thank you for contributing to KRYON!**
