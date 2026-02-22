# Tests

~500 tests across 137 files covering the full KRYON platform.

## Test Categories

| Directory | Coverage |
|-----------|----------|
| `agents/` | Agent configuration and factory |
| `autonomous/` | Strategic planner, context analyzer, adaptive strategy |
| `cli/` | CLI output and deduplication |
| `commands/` | REPL commands (flush, load, cost, compact) |
| `core/` | SDK core (runner, handoffs, guardrails, streaming) |
| `evaluation/` | Risk scoring, coverage, comparator |
| `intelligence/` | CVE enrichment, IOC parsing, MITRE mapping |
| `knowledge/` | RAG engine, scrapers |
| `mcp/` | MCP server integration |
| `memory/` | Memory store and client manager |
| `orchestration/` | Webhooks, scheduler, profiles |
| `reporting/` | Compliance and report models |
| `server/` | FastAPI endpoints (health, sessions, runs) |
| `tools/` | Function tools, guardrails, CTF automation |
| `tracing/` | OpenTelemetry spans and error handling |
| `tui/` | TUI imports |
| `voice/` | Voice pipeline |

## Running Tests

```bash
# All tests
make tests

# Single file
pytest tests/test_kryon_imports.py

# With coverage
make coverage
```

## Snapshots

Uses [inline-snapshots](https://15r10nk.github.io/inline-snapshot/latest/) for output validation.

```bash
make snapshots-fix      # Fix broken snapshots
make snapshots-create   # Create new snapshots
```

## Key Files

- `conftest.py` — Patches OpenAI models to prevent accidental API calls
- `fake_model.py` — Mock LLM for deterministic testing
- `helpers.py` — Shared test utilities
