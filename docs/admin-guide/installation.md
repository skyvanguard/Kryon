# Installation

## Docker (Recommended)

```bash
# Development stack
docker compose up -d

# Production stack
docker compose -f docker/docker-compose.production.yml up -d
```

## Bare Metal

```bash
# Install Python 3.10+
pip install kryon[server,rag,reporting]

# Start the server
kryon serve --port 8700
```

## systemd Service

Create `/etc/systemd/system/kryon.service`:

```ini
[Unit]
Description=KRYON Security Platform
After=network.target

[Service]
Type=simple
User=kryon
WorkingDirectory=/opt/kryon
ExecStart=/opt/kryon/venv/bin/kryon serve --port 8700
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable kryon
systemctl start kryon
```
