# Docker Deployment

## Development

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f kryon-server

# Stop
docker compose down
```

Services:
- **kryon-server** — API on port 8700
- **dashboard** — Web UI on port 5173
- **chromadb** — RAG vector store on port 8000

## Production

```bash
docker compose -f docker/docker-compose.production.yml up -d

# With optional profiles
docker compose -f docker/docker-compose.production.yml --profile nginx --profile rag up -d
```

### Environment

Create `docker/.env.production`:

```env
OPENAI_API_KEY=sk-your-production-key
KRYON_JWT_SECRET=your-strong-secret-here
KRYON_MODEL=gpt-4o
KRYON_DEBUG=0
KRYON_GUARDRAILS=true
```

### Volumes

| Volume | Purpose |
|--------|---------|
| `kryon-workspace` | Working directory for scans |
| `kryon-logs` | Log files |
| `kryon-config` | Configuration and database |
| `chromadb-data` | RAG vector embeddings |

### SSL/TLS

Enable nginx profile for SSL termination:

```bash
# Generate self-signed certs (dev)
kryon setup --generate-tls

# Or provide your own
cp fullchain.pem docker/nginx/ssl/
cp privkey.pem docker/nginx/ssl/

# Start with nginx
docker compose -f docker/docker-compose.production.yml --profile nginx up -d
```

## Multi-Arch Images

Built for `linux/amd64` and `linux/arm64` via GitHub Actions.

```bash
docker pull ghcr.io/skyvanguard/kryon:latest
```
