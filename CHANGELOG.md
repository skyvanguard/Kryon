# Changelog

All notable changes to KRYON will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-13 — "Hydra"

### Added

- **Self-Improving Loop**: ChromaDB-backed experience store that captures engagement outcomes (target profile, attack chain, signals). Agents recall similar past engagements via `recall_similar_experiences` to optimize future attack chains
- **Dynamic Skill System**: 9 markdown playbooks (`src/kryon/skills/playbooks/`) replace static agents. Skills auto-match by target tech, ports, and user keywords. Hot-reloadable without rebuild
  - recon-scout, pentest, vuln-hunter, wordpress-audit, ssl-audit, server-hardening, appsec, forensics, ctf-master
- **Unified "Kryon" Agent**: Single agent with all 74 tools, dynamically composed prompt from matched skills. Replaces 33 static agent files (kept for backward compatibility)
- **Tool Output Cap**: Results > 5000 chars saved to `/workspace/tool_outputs/`, model receives 700-char preview. Saves ~80% context per tool result
- **Magic Docs**: Session memory auto-generates structured security assessment report with target, ports, findings, and auto-recommendations
- **MicroCompact**: Trims old tool outputs in message history after model processes them (~85% token savings)
- **Session Memory**: Regex-based extraction of target/ports/tech/CVEs, injected as context on every turn
- **Auto-Extract Experiences**: Engagement saved automatically on REPL exit if tools were called
- **Claude Code-style Spinner**: Shimmer glyph animation with RGB interpolation, random verbs, stall detection (turns red after 30s)
- **REPL commands**: `/experiences` (list/show/search/delete/close), `/exp` alias
- **Tool Budget Manager**: Selects active tools based on loaded skills, caps at 30 to fit 32K context
- **Skill Loader**: Parses markdown frontmatter, caches by mtime, matches by tech/port/keyword triggers

### Fixed

- **Tool Calling with Ollama**: 4 SDK fixes enabling autonomous tool execution with local models:
  - Tool name normalization (`nmap:nmap` → `nmap`) for Ollama namespace quirk
  - Hallucination tolerance: unknown tools return error to model instead of crashing
  - Schema fix: `strict_schema.py` preserves Pydantic defaults for Ollama (nuclei_scan went from 23/23 to 1/23 required params)
  - `tool_choice="required"` forced on first 8 turns for Ollama models
- **Context Window**: Created `gemma4:26b-32k` variant with `PARAMETER num_ctx 32768` (Ollama defaults to ~4096, silently truncating tool schemas)
- **Non-streaming Display**: `response.final_output` now displayed and persisted in non-streaming REPL path
- **RAG Seed Idempotence**: Fixed `total_knowledge_items` vs `total_documents` field mismatch causing re-seed on every restart
- **ChromaDB Embeddings**: Custom Ollama HTTP embedding function (no `ollama` Python SDK dependency). Cosine distance for normalized 0-1 scores
- **Docker**: `.dockerignore` allows `entrypoint.sh`, CRLF→LF fix for Linux compatibility
- **Ollama Detection**: Tightened heuristic (no false positives on litellm model IDs with `:`)
- **`run_command`**: `session_id: str | None = None` (was `str = None`, made param required in schema)

### Changed

- **Recommended model**: Gemma 4 26B MoE via Ollama (`gemma4:26b-32k`). 3.8B active params, tool calling, thinking, 262K native context
- **Default agent**: `KRYON_AGENT=kryon` with `KRYON_UNIFIED=true` (unified skill-based agent)
- **System prompts rewritten**: recon_scout, pentest_agent, vuln_hunter — conversation-aware, no `<target>` placeholders, explicit "chain tools without stopping"
- **Markdown rendering**: Stream panel uses `rich.markdown.Markdown` instead of raw `Text`
- **Version**: 1.1.0 → 2.0.0 (breaking: new agent system, new modules)
- **Tagline**: "Autonomous Cybersecurity Intelligence Platform" → "Self-Improving Autonomous Cybersecurity Platform"

## [1.1.1] - 2026-03-03

### Fixed

- **Security**: Updated 7 vulnerable dependencies (starlette, python-multipart, pyasn1, protobuf, pillow, mcp, cryptography)
- **Security**: Suppressed 78 Semgrep false positives (legitimate pentesting tool patterns)
- **CI**: Resolved all lint errors (347 ruff errors + 140 unformatted files)
- **CI**: Fixed Docker build (COPY shell syntax, missing README.md)
- **CI**: Replaced Trivy action with apt install for reliability
- **CI**: Resolved 8 pre-existing test failures (docs + schedule module)
- **Tests**: Lazy import for `schedule` module in auto_updater (optional `rag` dependency)
- **Tests**: Skip `test_add_document` when `sentence_transformers` not installed

### Added

- All documentation markdown files committed to repository (62 files)
- Dependabot configuration for pip, npm, and GitHub Actions
- CI/CD status badges in README

### Changed

- Project version bumped to 1.1.1
- README stats updated (1896 tests, 21 agents, 136 endpoints, 1082 RAG docs)
- SECURITY.md updated to include v1.1.x as supported
- LICENSE year updated to 2025-2026

## [1.1.0] - 2026-02-27

### Added

- **CI/CD Pipeline**: Security scanning (Trivy, Semgrep), Docker multi-arch builds, release automation
- **Agent Guardrails**: Scope enforcement, role-based tool filtering, network egress policy
- **SIEM Integration**: Splunk HEC, QRadar LEEF, Elastic ECS forwarders with IntegrationManager
- **E2E Tests**: Playwright-based browser tests for login, scans, engagements, reports
- **Compliance Reporting**: PCI-DSS v4.0 (25 controls) and SOC 2 Type II (18 controls) report generators
- **Multi-tenancy**: Separate DB isolation, tenant resolution middleware, resource quotas
- **Documentation**: Admin guide, API guide, architecture docs, deployment guides
- GitHub workflows: security-scan.yml, docker-build.yml, release.yml, e2e.yml
- Makefile targets: docker-build, security-scan, release
- docker-compose.yml for development stack

### Changed

- CI workflow includes coverage upload to Codecov
- RBAC permissions extended with scope:read/write, integrations:read/write
- Audit middleware forwards events to SIEM integrations
- ReportType enum includes PCI_DSS and SOC2
- Migrations extended to v7 (scope_whitelist, siem_configs, tenants, tenant_quotas)

## [1.0.0] - 2026-02-26

### Added

- RAG expansion: 408+ seed documents across 10 JSON files
- 4 new scrapers: StaticSeed, OWASP, CWE, VendorAdvisory
- SCRAPER_REGISTRY centralized dispatch
- Security audit: 13 vulnerability fixes
- Agent refactoring: create_agent() factory, ~500 lines eliminated
- Server refactoring: SSE utility, DRY singletons, pagination
- Code audit: SQL whitelisting, state validation, memory leak fixes
- API versioning: all routes at /api/v1/*
- Production readiness: Docker, health checks, OpenAPI metadata
- Enterprise hardening: structured logging, JWT auth, RBAC, audit logging
- Setup wizard, TLS generation, nginx config
- 24 LLM-powered security agents
- RAG knowledge base with 408+ documents
- Multi-day autonomous pentesting engagements
- HTML/PDF security reporting

### Fixed

- All pre-existing test failures resolved (1408 passed, 0 failed)
