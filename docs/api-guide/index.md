# API Guide

KRYON exposes a REST API at `/api/v1/`. All endpoints require authentication via API key or JWT token.

## Authentication

### API Key

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8700/api/v1/scans
```

### JWT Token

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8700/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Admin123!"}' | jq -r .access_token)

# Use token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8700/api/v1/scans
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/health/ready` | Readiness check |
| POST | `/api/v1/auth/login` | Login |
| POST | `/api/v1/auth/refresh` | Refresh token |
| GET | `/api/v1/agents` | List agents |
| POST | `/api/v1/runs` | Start agent run |
| GET/POST | `/api/v1/scans` | Manage scans |
| GET/POST | `/api/v1/engagements` | Manage engagements |
| GET/POST | `/api/v1/clients` | Manage clients |
| POST | `/api/v1/reports` | Generate reports |
| GET/POST | `/api/v1/knowledge/*` | RAG knowledge base |
| GET/POST | `/api/v1/scope/rules` | Scope whitelist |
| GET/POST | `/api/v1/integrations/siem` | SIEM integrations |
| GET/POST | `/api/v1/tenants` | Tenant management |
| GET | `/api/v1/audit` | Audit logs |

## Rate Limiting

Default: 60 requests per minute per IP.

Response headers:
- `X-RateLimit-Limit` — Max requests per window
- `X-RateLimit-Remaining` — Remaining requests
- `X-RateLimit-Reset` — Window reset time

## OpenAPI

Interactive docs available at: `http://localhost:8700/docs`
