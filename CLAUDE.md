# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

KRYON is a Python 3.10+ autonomous cybersecurity intelligence platform: 21 security agents, 204+ tool implementations across 35 categories, FastAPI REST server (136 endpoints), a REPL/TUI, RAG knowledge base (ChromaDB), and multi-tenant/billing/compliance stack. Managed with `uv` (workspace member: `agents/`). License is **Proprietary** — do not reintroduce MIT references.

Entry point: `kryon = "kryon.cli:main"` (see `pyproject.toml`).

## Commands

All via `uv` (Makefile wraps them). On Windows bash, use forward slashes.

```bash
make sync                    # uv sync --all-extras --all-packages --group dev
make format                  # ruff format + ruff check --fix
make lint                    # ruff check
make mypy                    # mypy . (non-strict; many modules in ignore_errors override)
make tests                   # uv run pytest
make coverage                # coverage run + xml + report --fail-under=95
make snapshots-fix           # pytest --inline-snapshot=fix
make docker-build / docker-up / docker-down / docker-prod
make security-scan           # pip-audit + safety
```

Run a single test / subset:

```bash
uv run pytest tests/test_kryon_imports.py
uv run pytest tests/agents/ -k "pentest"
uv run pytest -m "unit and not slow"          # markers: unit, integration, slow, ctf, agent, tool, security, optional, e2e
uv run pytest --inline-snapshot=fix tests/path/to/test.py
```

`asyncio_mode = "auto"` — do not add `@pytest.mark.asyncio` manually; fixture loop scope is `session`.

Coverage target in `make coverage` is **95%** (stricter than the 80% global rule). `[tool.coverage.run] source = ["tests", "src/kryon/sdk/agents"]` — coverage is scoped to the SDK subtree, not the whole package.

## Architecture

Top-level layout: `src/kryon/` (package), `tests/` (mirrors package layout), `docker/`, `helm/`, `k8s/`, `docs/`, `scripts/`, `agents/` (uv workspace member).

### Core subsystems (`src/kryon/`)

- **`sdk/`** — agent runtime SDK (under `sdk/agents/`). This is the execution engine for all agents: run loop, tool executor, MCP integration, model adapters (`openai_chatcompletions`, `openai_responses`), parallel tool executor, JSONL tracing. Most of `mypy` and coverage is focused here. Changes here affect every agent.
- **`agents/`** — 21+ concrete agent definitions (`pentest_agent`, `recon_scout`, `vuln_hunter`, `central_core`, `strategic_core`, etc.) built on top of the SDK. Each file defines prompts, toolsets, and model config. `patterns/` holds multi-agent patterns (swarm, sequential, hierarchical, conditional, parallel).
- **`tools/`** — 204+ tool implementations grouped by kill-chain category (`reconnaissance`, `web`, `exploitation`, `credentials`, `cloud`, `container`, `appsec`, `llm_security`, `dfir`, `evasion`, `api_attacks`, `post_exploitation`, `ai`, `anonymity`, `browser`, `ctf`, `command_and_control`, `data_exfiltration`, ...). Agents bind to categories/tools rather than individual files.
- **`server/`** — FastAPI application (`app.py`) with `routes/`, `auth/`, `middleware/`, JWT/RBAC, audit logging, scheduler, sessions, jobs. 136 endpoints across 28 routers under `/api/v1`. Launched via `kryon-server` script or the Docker stack.
- **`repl/` + `tui/` + `cli/`** — user interfaces. `cli/` is the `kryon` entry point; `repl/` is the interactive shell (`/agent`, `/parallel`, etc.); `tui/` is Textual-based.
- **`knowledge/`** — RAG: ExploitDB/NVD/GitHub/CTF seed loaders + ChromaDB vector store + schedule-based auto-updater. Optional extra `[rag]`.
- **`memory/`** — conversation/session memory layer used by the SDK.
- **`intelligence/`** — CVE/threat-intel correlation.
- **`compliance/`** — PCI-DSS, HIPAA, SOC2, NIST 800-53, ISO 27001, GDPR, OWASP, CIS, MITRE ATT&CK mappings.
- **`engagements/`, `remediation/`, `reporting/`, `evaluation/`, `notifications/`, `tenancy/`, `billing/`, `onboarding/`, `providers/`, `integrations/`** — enterprise workflow modules. Most are server-adjacent and shipped as routers under `server/routes/`.

### Important cross-cutting rules

- **LiteLLM without `[proxy]`** — `uvloop` is not supported on Windows; do not re-add the proxy extra to `pyproject.toml`.
- **`openinference-instrumentation-openai`** is Python-version-gated (`< 3.14`) under the `tracing` extra. Don't move it back to core dependencies.
- **Optional extras**: `voice`, `viz`, `tracing`, `rag`, `server`, `tui`, `reporting`, `orchestration`, `dev`. The base install intentionally stays lean; RAG/server/reporting/TUI features live in extras.
- **Ruff per-file ignores** are deliberately loose for `agents/`, `tools/`, `repl/`, `sdk/`, `knowledge/`, `intelligence/`, `reporting/`, `server/`, etc. (long strings, late imports). Check `[tool.ruff.lint.per-file-ignores]` before "fixing" E501/E402/B904/B008 in those trees — they're allow-listed on purpose.
- **`mypy` `ignore_errors`** covers `kryon.tools.*`, `kryon.agents.*`, `kryon.knowledge.*`, `kryon.repl.*`, `kryon.cache.*`, `kryon.cli*`, and much of `kryon.sdk.agents.*`. Type-level work should target modules *outside* that override list.
- **Tests mirror the package**: `tests/<subsystem>/...`. There are also top-level integration/smoke tests (`test_kryon_imports.py`, `test_integration_workflows.py`, `test_tool_availability.py`, `test_llm_cache.py`, `test_rag_system.py`, etc.).

### Configuration

Runtime configuration is via env vars (see `README.md`): `KRYON_MODEL`, `KRYON_AGENT`, `KRYON_WORKSPACE_DIR`, `KRYON_MAX_TURNS`, `KRYON_MEMORY`, plus provider keys. `agents.yml.example` is a template. Ollama is supported by pointing `OPENAI_BASE_URL` at `http://localhost:11434/v1`.

## Docker / K8s

- `docker/docker-compose.kali.yml` is the recommended dev stack (Kali + Ollama + Kryon).
- `docker-compose.yml` (root) is the lighter dev compose.
- `helm/` and `k8s/` hold production manifests; deployment docs: `DEPLOYMENT.md`, `K8S_DEPLOYMENT_SUMMARY.md`, `QUICKSTART_K8S.md`, `K8S_VERIFICATION.md`.

## Conventions specific to this repo

- Conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`).
- Do **not** commit `.kryon/`, `workspaces/`, `logs/`, `nohup.out`, `ci/`, or `tools/cut_the_rope/` — all excluded from the hatch build and should not appear in diffs either.
- When adding a new agent: place it under `src/kryon/agents/`, register it in the agent discovery, and add a matching test under `tests/agents/`. When adding a new tool: drop it in the correct `src/kryon/tools/<category>/` bucket — agents bind by category.
