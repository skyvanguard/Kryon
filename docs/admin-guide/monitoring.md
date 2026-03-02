# Monitoring

## Health Checks

### Liveness

```bash
curl http://localhost:8700/api/v1/health
# {"status": "ok"}
```

### Readiness

```bash
curl http://localhost:8700/api/v1/health/ready
# {"status": "ready", "database": "ok", "rag": "ok", "ai_provider": "ok"}
```

## Logs

KRYON uses structured JSON logging. Key fields:

- `timestamp` — ISO 8601
- `level` — INFO, WARNING, ERROR
- `request_id` — Unique per request (via contextvars)
- `message` — Log message

### Log Levels

Set `KRYON_DEBUG=1` for DEBUG level output.

## Audit Log

All POST/PUT/DELETE API operations are logged to the `audit_log` table.

```bash
curl http://localhost:8700/api/v1/audit \
  -H "Authorization: Bearer <admin-token>"
```

## SIEM Integration

Forward audit events to Splunk, QRadar, or Elastic. Configure via:

```bash
curl -X POST http://localhost:8700/api/v1/integrations/siem \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Splunk", "siem_type": "splunk", "endpoint": "https://splunk:8088", "token": "HEC-token"}'
```
