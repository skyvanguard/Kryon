# KRYON Monitoring Guide

Monitor KRYON deployments for performance, costs, and security.

## Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| API Costs | $ spent on AI calls | > daily budget |
| Response Time | Time to first response | > 30s |
| Error Rate | Failed operations | > 5% |
| Memory Usage | RAM consumption | > 80% |
| Active Sessions | Concurrent users | > capacity |

---

## Built-in Cost Tracking

KRYON tracks costs automatically:

```bash
# View session costs
kryon
> /cost

# Set cost limit
KRYON_PRICE_LIMIT="50"  # Stop at $50
```

### Cost by Model (Approximate)

| Model | Input ($/1M tokens) | Output ($/1M tokens) |
|-------|---------------------|----------------------|
| gpt-4o | $2.50 | $10.00 |
| gpt-4o-mini | $0.15 | $0.60 |
| claude-3-5-sonnet | $3.00 | $15.00 |
| deepseek-chat | $0.14 | $0.28 |
| Ollama (local) | $0 | $0 |

---

## Logging

### Enable Logging

```bash
# Environment variables
KRYON_DEBUG="1"                    # Verbosity
KRYON_LOG_FILE="/var/log/kryon.log"  # File output
```

### Log Levels

- `0` - Errors only
- `1` - Info + Errors (default)
- `2` - Debug (verbose)

### Log Format

```
2026-02-04 10:30:00 INFO [session-abc123] Agent: t800_infiltrator
2026-02-04 10:30:01 INFO [session-abc123] Model: gpt-4o
2026-02-04 10:30:15 INFO [session-abc123] Tool: run_nmap
2026-02-04 10:30:45 INFO [session-abc123] Cost: $0.0234
```

---

## Prometheus Metrics

Export metrics for Prometheus:

```python
# Custom metrics endpoint (example)
from prometheus_client import Counter, Histogram, start_http_server

api_calls = Counter('kryon_api_calls_total', 'Total API calls', ['model'])
response_time = Histogram('kryon_response_seconds', 'Response time')
cost_total = Counter('kryon_cost_dollars_total', 'Total cost in dollars')

# Start metrics server
start_http_server(9090)
```

### Grafana Dashboard

```json
{
  "panels": [
    {
      "title": "API Costs (24h)",
      "type": "stat",
      "targets": [{"expr": "increase(kryon_cost_dollars_total[24h])"}]
    },
    {
      "title": "Response Time (p95)",
      "type": "graph",
      "targets": [{"expr": "histogram_quantile(0.95, kryon_response_seconds_bucket)"}]
    }
  ]
}
```

---

## Health Checks

### Basic Health Check

```bash
# Test if KRYON is responsive
kryon --health-check

# Or via Python
python -c "from kryon.cli import main; print('OK')"
```

### Docker Health Check

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "from kryon.cli import main; print('OK')" || exit 1
```

### Kubernetes Probes

```yaml
livenessProbe:
  exec:
    command: ["python", "-c", "from kryon.cli import main"]
  initialDelaySeconds: 30
  periodSeconds: 60

readinessProbe:
  exec:
    command: ["python", "-c", "import kryon; print('ready')"]
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

## Alerting

### Cost Alerts

```yaml
# AlertManager rule
groups:
- name: kryon
  rules:
  - alert: HighAPICost
    expr: increase(kryon_cost_dollars_total[1h]) > 10
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High API costs detected"
      description: "KRYON spent over $10 in the last hour"
```

### Error Alerts

```yaml
  - alert: HighErrorRate
    expr: rate(kryon_errors_total[5m]) > 0.05
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate in KRYON"
```

---

## Audit Trail

For compliance, enable full audit logging:

```bash
KRYON_TRACING="true"
KRYON_AUDIT_LOG="/var/log/kryon/audit.json"
```

### Audit Log Format

```json
{
  "timestamp": "2026-02-04T10:30:00Z",
  "session_id": "abc123",
  "user": "operator@company.com",
  "agent": "t800_infiltrator",
  "action": "tool_execution",
  "tool": "run_nmap",
  "target": "192.168.1.0/24",
  "result": "success",
  "cost": 0.0234
}
```

---

## Troubleshooting Slow Performance

1. **Check network latency** to AI provider
2. **Monitor memory** - may need more RAM for large contexts
3. **Review model choice** - smaller models are faster
4. **Enable streaming** - `KRYON_STREAM="true"` for better UX

---

## See Also

- [Configuration Reference](configuration.md)
- [Security Hardening](security.md)
- [Troubleshooting](troubleshooting.md)
