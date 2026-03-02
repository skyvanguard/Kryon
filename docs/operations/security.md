# KRYON Security Hardening Guide

Best practices for securing KRYON deployments in enterprise environments.

## Security Checklist

### Critical (Must Do)

- [ ] Enable guardrails: `KRYON_GUARDRAILS="true"`
- [ ] Use secrets manager for API keys
- [ ] Run with minimum required privileges
- [ ] Enable audit logging
- [ ] Restrict network access

### Recommended

- [ ] Disable telemetry: `KRYON_TELEMETRY="false"`
- [ ] Set cost limits: `KRYON_PRICE_LIMIT="50"`
- [ ] Use dedicated service account
- [ ] Implement rate limiting
- [ ] Regular security updates

---

## Secrets Management

### Never Do This

```bash
# BAD: Hardcoded secrets
OPENAI_API_KEY="sk-actual-key-here"  # In code or committed files
```

### Best Practices

#### 1. Environment Variables (Development)

```bash
# Set in shell session (not persisted)
export OPENAI_API_KEY="sk-..."
kryon
```

#### 2. Secrets Manager (Production)

```bash
# AWS Secrets Manager
OPENAI_API_KEY=$(aws secretsmanager get-secret-value \
  --secret-id kryon/openai-key \
  --query SecretString --output text)

# HashiCorp Vault
OPENAI_API_KEY=$(vault kv get -field=key secret/kryon/openai)

# Azure Key Vault
OPENAI_API_KEY=$(az keyvault secret show \
  --vault-name myvault \
  --name openai-key \
  --query value -o tsv)
```

#### 3. Docker Secrets

```yaml
# docker-compose.yml
services:
  kryon:
    secrets:
      - openai_key
    environment:
      OPENAI_API_KEY_FILE: /run/secrets/openai_key

secrets:
  openai_key:
    external: true
```

---

## Network Security

### Firewall Rules

```bash
# Only allow outbound to AI providers
# OpenAI
iptables -A OUTPUT -p tcp -d api.openai.com --dport 443 -j ACCEPT
# Anthropic
iptables -A OUTPUT -p tcp -d api.anthropic.com --dport 443 -j ACCEPT
# Block all other outbound (adjust as needed)
iptables -A OUTPUT -j DROP
```

### Proxy Configuration

```bash
# Route through corporate proxy
export HTTPS_PROXY="http://proxy.company.com:8080"
export NO_PROXY="localhost,127.0.0.1,.internal"
```

---

## Access Control

### Linux (systemd)

```bash
# Create dedicated user
sudo useradd -r -s /bin/false kryon

# Set file permissions
sudo chown -R kryon:kryon /opt/kryon
sudo chmod 750 /opt/kryon
sudo chmod 600 /opt/kryon/.env

# Run as non-root
[Service]
User=kryon
Group=kryon
```

### Docker

```dockerfile
# Don't run as root
FROM python:3.11-slim
RUN useradd -m -u 1000 kryon
USER kryon
```

---

## Guardrails

KRYON includes built-in security guardrails that should always be enabled in production.

### What Guardrails Protect Against

1. **Prompt Injection** - 70+ detection patterns
2. **Unicode Bypass** - Normalization before processing
3. **Command Injection** - Sanitized shell commands
4. **Data Exfiltration** - Restricted file operations

### Configuration

```bash
# Always enable in production
KRYON_GUARDRAILS="true"

# Optional: Strict mode (blocks more, may have false positives)
KRYON_GUARDRAILS_STRICT="true"
```

---

## Audit Logging

### Enable Comprehensive Logging

```bash
# Enable tracing for audit trail
KRYON_TRACING="true"

# Log to file
KRYON_LOG_FILE="/var/log/kryon/audit.log"
KRYON_LOG_LEVEL="INFO"
```

### Log Retention

```bash
# logrotate configuration: /etc/logrotate.d/kryon
/var/log/kryon/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 640 kryon kryon
}
```

---

## Compliance Considerations

### GDPR

```bash
# Disable telemetry
KRYON_TELEMETRY="false"

# Local processing only
OLLAMA_API_BASE="http://localhost:11434/v1"
KRYON_MODEL="qwen2.5:14b"
```

### SOC 2

- Enable audit logging
- Implement access controls
- Use secrets management
- Regular security reviews

### PCI-DSS

- Network segmentation
- Encrypted communications (HTTPS only)
- Access logging
- Vulnerability management

---

## Incident Response

### If API Key is Compromised

1. **Immediately rotate the key** at provider dashboard
2. Review API usage logs for unauthorized access
3. Update key in secrets manager
4. Restart KRYON services
5. Document incident

### Security Contacts

- GitHub Security: https://github.com/skyvanguard/Kryon/security
- Report vulnerabilities responsibly

---

## Regular Maintenance

### Weekly

- Review access logs
- Check for security updates
- Verify guardrails are enabled

### Monthly

- Rotate API keys
- Review user access
- Update dependencies

### Quarterly

- Security audit
- Penetration testing
- Policy review

---

## See Also

- [Deployment Guide](deployment.md)
- [Configuration Reference](configuration.md)
- [Troubleshooting](troubleshooting.md)
