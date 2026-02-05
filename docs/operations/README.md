# KRYON Operations Guide

This directory contains operational documentation for deploying and maintaining KRYON in production environments.

## Contents

| Document | Description |
|----------|-------------|
| [deployment.md](deployment.md) | Installation and deployment guide |
| [configuration.md](configuration.md) | Environment configuration reference |
| [monitoring.md](monitoring.md) | Monitoring and observability |
| [security.md](security.md) | Security hardening guidelines |
| [troubleshooting.md](troubleshooting.md) | Common issues and solutions |

## Quick Links

- [Quick Start](#quick-start)
- [Production Checklist](#production-checklist)
- [Support](#support)

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon
pip install -e .

# 2. Configure
cp .env.example .env
# Edit .env with your API keys

# 3. Run
kryon
```

## Production Checklist

Before deploying to production, ensure:

- [ ] API keys configured securely (not in code)
- [ ] `KRYON_GUARDRAILS="true"` enabled
- [ ] `KRYON_TELEMETRY="false"` for privacy
- [ ] Logging configured appropriately
- [ ] Network access restricted as needed
- [ ] Backup strategy defined
- [ ] Monitoring alerts configured

## Support

- GitHub Issues: [Report a bug](https://github.com/skyvanguard/Kryon/issues)
- Documentation: [Full docs](https://github.com/skyvanguard/Kryon/docs)
