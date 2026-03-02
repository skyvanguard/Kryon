# KRYON Deployment Guide

## Table of Contents

1. [Requirements](#requirements)
2. [Installation Methods](#installation-methods)
3. [Configuration](#configuration)
4. [Deployment Options](#deployment-options)
5. [Post-Deployment](#post-deployment)

---

## Requirements

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 10 GB | 50+ GB |
| Python | 3.10 | 3.11+ |

### Supported Platforms

- **Linux**: Ubuntu 20.04+, Debian 11+, RHEL 8+, CentOS 8+
- **Windows**: Windows 10/11, Windows Server 2019+
- **macOS**: macOS 12+ (Monterey)
- **Docker**: Any platform with Docker 20.10+

### Network Requirements

| Service | Port | Direction | Required |
|---------|------|-----------|----------|
| OpenAI API | 443 | Outbound | If using OpenAI |
| Anthropic API | 443 | Outbound | If using Claude |
| Ollama | 11434 | Local/Outbound | If using local models |

---

## Installation Methods

### Method 1: pip (Recommended)

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install KRYON
pip install kryon

# Or install from source
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon
pip install -e .
```

### Method 2: Docker

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -e .

# Don't run as root
RUN useradd -m kryon
USER kryon

ENTRYPOINT ["kryon"]
```

```bash
# Build and run
docker build -t kryon:latest .
docker run -it --env-file .env kryon:latest
```

### Method 3: Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  kryon:
    build: .
    env_file: .env
    volumes:
      - ./workspaces:/app/workspaces
      - ./logs:/app/logs
    stdin_open: true
    tty: true

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama

volumes:
  ollama_data:
```

---

## Configuration

### Environment Variables

Create `.env` from the example:

```bash
cp .env.example .env
```

#### Required Settings

```bash
# Choose ONE AI provider
OPENAI_API_KEY="sk-..."           # OpenAI
# or
ANTHROPIC_API_KEY="sk-ant-..."    # Anthropic
# or
OLLAMA_API_BASE="http://localhost:11434/v1"  # Local (free)
```

#### Production Settings

```bash
# Security (REQUIRED for production)
KRYON_GUARDRAILS="true"

# Privacy
KRYON_TELEMETRY="false"
KRYON_TRACING="false"

# Cost control
KRYON_PRICE_LIMIT="50"

# Performance
KRYON_STREAM="true"
KRYON_DEBUG="0"
```

### Secrets Management

**Never commit secrets to version control!**

#### Option 1: Environment Variables

```bash
export OPENAI_API_KEY="sk-..."
kryon
```

#### Option 2: .env File (Development)

```bash
# .env (add to .gitignore!)
OPENAI_API_KEY="sk-..."
```

#### Option 3: Secrets Manager (Production)

```bash
# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id kryon/prod | jq -r .SecretString > .env

# HashiCorp Vault
vault kv get -format=json secret/kryon/prod | jq -r .data.data > .env

# Azure Key Vault
az keyvault secret show --vault-name myvault --name openai-key --query value -o tsv
```

---

## Deployment Options

### Option 1: Standalone Server

```bash
# systemd service file: /etc/systemd/system/kryon.service
[Unit]
Description=KRYON Cybersecurity Platform
After=network.target

[Service]
Type=simple
User=kryon
WorkingDirectory=/opt/kryon
EnvironmentFile=/opt/kryon/.env
ExecStart=/opt/kryon/venv/bin/kryon --server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable kryon
sudo systemctl start kryon
```

### Option 2: Kubernetes

```yaml
# kryon-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kryon
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kryon
  template:
    metadata:
      labels:
        app: kryon
    spec:
      containers:
      - name: kryon
        image: kryon:latest
        envFrom:
        - secretRef:
            name: kryon-secrets
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "8Gi"
            cpu: "4"
---
apiVersion: v1
kind: Secret
metadata:
  name: kryon-secrets
type: Opaque
stringData:
  OPENAI_API_KEY: "sk-..."
  KRYON_GUARDRAILS: "true"
  KRYON_TELEMETRY: "false"
```

### Option 3: Air-Gapped (Offline)

For environments without internet access:

```bash
# 1. On connected machine: download Ollama models
ollama pull qwen2.5:14b
ollama pull llama3.1:70b

# 2. Export models
tar -cvf ollama-models.tar ~/.ollama/models/

# 3. Transfer to air-gapped machine
# (USB, secure file transfer, etc.)

# 4. On air-gapped machine
tar -xvf ollama-models.tar -C ~/.ollama/models/

# 5. Configure KRYON for local-only
OLLAMA_API_BASE="http://localhost:11434/v1"
KRYON_MODEL="qwen2.5:14b"
```

---

## Post-Deployment

### Verification

```bash
# Test installation
kryon --version

# Test connectivity
python -c "from kryon.cli import main; print('OK')"

# Run health check
kryon --health-check
```

### Monitoring

See [monitoring.md](monitoring.md) for detailed monitoring setup.

Quick metrics to track:
- API costs per session
- Response latency
- Error rates
- Memory usage

### Backup

```bash
# Backup workspaces and configuration
tar -cvzf kryon-backup-$(date +%Y%m%d).tar.gz \
  .env \
  workspaces/ \
  .kryon/
```

### Updates

```bash
# Update KRYON
pip install --upgrade kryon

# Or from source
git pull origin main
pip install -e .
```

---

## Next Steps

- [Configuration Reference](configuration.md)
- [Security Hardening](security.md)
- [Troubleshooting](troubleshooting.md)
