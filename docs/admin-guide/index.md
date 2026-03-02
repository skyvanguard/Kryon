# Admin Guide

This guide covers system administration for KRYON.

## Contents

- [Installation](installation.md) - Production installation
- [Configuration](configuration.md) - Environment variables and settings
- [User Management](user-management.md) - Users, roles, and permissions
- [Backup & Restore](backup-restore.md) - Database backup procedures
- [Monitoring](monitoring.md) - Health checks, logs, and metrics
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Quick Reference

### Starting the Server

```bash
# Development
kryon serve --port 8700 --debug

# Production (with Docker)
docker compose -f docker/docker-compose.production.yml up -d
```

### First-Time Setup

```bash
kryon setup
```

This runs the setup wizard which configures:
- Admin user credentials
- JWT secret
- OpenAI API key
- TLS certificates (optional)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | (required) | OpenAI API key |
| `KRYON_MODEL` | `gpt-4o` | Default LLM model |
| `KRYON_DEBUG` | `0` | Enable debug mode |
| `KRYON_JWT_SECRET` | (auto-generated) | JWT signing secret |
| `KRYON_GUARDRAILS` | `true` | Enable agent guardrails |
| `KRYON_RATE_LIMIT_RPM` | `60` | Rate limit (requests per minute) |
