# Architecture Overview

## Components

```
+------------------+     +-----------------+     +------------------+
|   SvelteKit      |     |   FastAPI        |     |   SQLite DB      |
|   Dashboard      |---->|   REST API       |---->|   (per tenant)   |
|   (port 5173)    |     |   (port 8700)    |     |                  |
+------------------+     +---------+---------+     +------------------+
                                   |
                          +--------+--------+
                          |                 |
                   +------v------+   +------v------+
                   | 24 LLM      |   | RAG Engine  |
                   | Agents      |   | (ChromaDB)  |
                   | (OpenAI)    |   | 408+ docs   |
                   +-------------+   +-------------+
```

## Key Packages

| Package | Responsibility |
|---------|---------------|
| `agents/` | 24 LLM agents with `create_agent()` factory |
| `server/` | FastAPI app, middleware, routes, auth |
| `memory/` | SQLite persistence, schema migrations (v1-v7) |
| `intelligence/` | MITRE ATT&CK mapping, CVE enrichment |
| `knowledge/` | RAG system, 9 scrapers, auto-updater |
| `reporting/` | HTML/PDF reports (executive, technical, PCI-DSS, SOC2) |
| `compliance/` | PCI-DSS v4.0, SOC 2 Type II control mapping |
| `integrations/` | SIEM forwarders (Splunk, QRadar, Elastic) |
| `tenancy/` | Multi-tenant isolation, quotas, middleware |
| `engagements/` | Multi-day autonomous pentesting |

## Middleware Stack (outermost to innermost)

1. **RequestIdMiddleware** — Tags every request with a unique ID
2. **AuditMiddleware** — Logs POST/PUT/DELETE to audit_log + SIEM
3. **SecurityHeadersMiddleware** — CSP, X-Frame-Options, HSTS
4. **RateLimitMiddleware** — Sliding window per IP (60 rpm)
5. **CORSMiddleware** — Restrictive origins, credentials support

## Database Schema

Migrations in `memory/migrations.py`:

| Version | Tables Added |
|---------|-------------|
| v1 | clients, scans, findings, agent_experience, engagements, engagement_phases |
| v2 | clients.owner_user_id column |
| v3 | users, user_client_access |
| v4 | audit_log |
| v5 | scope_whitelist |
| v6 | siem_configs |
| v7 | tenants, tenant_quotas |

## Authentication Flow

1. Client sends `POST /api/v1/auth/login` with username/password
2. Server validates credentials (bcrypt), returns JWT access + refresh tokens
3. JWT contains: user_id, username, role, tenant_id (optional)
4. Protected endpoints validate JWT via `get_current_user()` dependency
5. RBAC checks permissions via `require_permission()` dependency
