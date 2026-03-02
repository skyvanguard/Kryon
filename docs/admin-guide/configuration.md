# Configuration

KRYON is configured via environment variables. Use a `.env` file or set them directly.

## Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | (required) | OpenAI API key for LLM agents |
| `OPENAI_BASE_URL` | (none) | Custom OpenAI-compatible endpoint (Ollama, etc.) |
| `KRYON_MODEL` | `gpt-4o` | Default LLM model |
| `KRYON_DEBUG` | `0` | Enable debug mode (1=on, 0=off) |

## Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `KRYON_JWT_SECRET` | (auto) | JWT signing secret (32+ chars recommended) |
| `KRYON_JWT_ACCESS_TTL` | `30` | Access token TTL in minutes |
| `KRYON_API_KEYS` | (none) | Comma-separated API keys |

## Server

| Variable | Default | Description |
|----------|---------|-------------|
| `KRYON_PORT` | `8700` | Server port |
| `KRYON_CORS_ORIGINS` | `http://localhost:5173` | Allowed CORS origins |
| `KRYON_RATE_LIMIT_RPM` | `60` | Rate limit per IP per minute |
| `KRYON_HTTPS_ENABLED` | `false` | Enable HTTPS |

## RAG / Knowledge

| Variable | Default | Description |
|----------|---------|-------------|
| `KRYON_AUTO_UPDATE` | `true` | Enable knowledge auto-updater |
| `KRYON_AUTO_UPDATE_INTERVAL` | `24` | Update interval in hours |

## Guardrails

| Variable | Default | Description |
|----------|---------|-------------|
| `KRYON_GUARDRAILS` | `true` | Enable prompt injection guardrails |
