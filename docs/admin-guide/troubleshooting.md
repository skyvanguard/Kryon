# Troubleshooting

## Common Issues

### "Database is locked"

SQLite concurrent access issue. Solutions:
- Ensure only one KRYON instance accesses the DB
- Increase `busy_timeout` (default: 5000ms)
- Use WAL mode (enabled by default)

### "OPENAI_API_KEY not set"

Set the environment variable before starting:
```bash
export OPENAI_API_KEY=sk-your-key-here
kryon serve
```

### Rate Limit Errors (429)

Default: 60 requests per minute per IP. Increase with:
```bash
export KRYON_RATE_LIMIT_RPM=120
```

### JWT Token Expired

Access tokens expire after 30 minutes. Use the refresh endpoint:
```bash
curl -X POST http://localhost:8700/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "your-refresh-token"}'
```

### ChromaDB Connection Issues

If using RAG with external ChromaDB:
```bash
export CHROMA_HOST=localhost
export CHROMA_PORT=8000
```
