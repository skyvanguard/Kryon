# Changelog

All notable changes to KRYON will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
