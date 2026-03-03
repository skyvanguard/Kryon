# KRYON

```
██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║
██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
```

<div align="center">

**Autonomous Cybersecurity Intelligence Platform**

[![CI](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml)
[![Security Scan](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml)
[![Docker Build](https://github.com/skyvanguard/Kryon/actions/workflows/docker-build.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/docker-build.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1896_passed-brightgreen.svg)](#testing)
[![Agents](https://img.shields.io/badge/agents-21-orange.svg)](#security-agents)
[![Tools](https://img.shields.io/badge/tools-204+-red.svg)](#tool-categories)
[![Stars](https://img.shields.io/github/stars/skyvanguard/Kryon?style=social)](https://github.com/skyvanguard/Kryon)

[Installation](#installation) | [Quick Start](#quick-start) | [Agents](#security-agents) | [Dashboard](#web-dashboard) | [Docker](#docker-deployment) | [Kubernetes](#kubernetes) | [API](#api) | [Contributing](#contributing)

</div>

---

## What is KRYON?

KRYON is an open-source platform for building and deploying autonomous AI agents specialized in cybersecurity operations. It provides a full-cycle security platform from reconnaissance to remediation, powered by LLMs with RAG-enhanced knowledge.

### Platform at a Glance

| Component | Count |
|-----------|:-----:|
| Security Agents | 21 |
| Tool Implementations | 204+ |
| Tool Categories | 35 |
| API Endpoints | 136 |
| Dashboard Pages | 25 |
| Compliance Frameworks | 9 |
| RAG Knowledge Documents | 1082 |
| DB Migrations | 16 |
| Test Suite | 1896 passed |

### Core Capabilities

- **21 Autonomous Agents** - Pre-built agents for pentesting, forensics, AppSec, red team, CTF, and more
- **204+ Security Tools** - Across 35 categories covering the full kill chain
- **Multi-Model Support** - Works with 300+ LLMs including GPT-4o, Claude, DeepSeek, Llama, and local models via Ollama
- **RAG Knowledge Base** - 1082 documents from ExploitDB, NVD, GitHub, CTF writeups, and custom seed data with ChromaDB vector search
- **Web Dashboard** - Full SvelteKit dashboard with 25 pages for managing operations
- **REST API** - 136 endpoints across 28 routers for full programmatic control
- **Compliance** - PCI-DSS, HIPAA, SOC2, NIST 800-53, ISO 27001, GDPR, OWASP, CIS, MITRE ATT&CK
- **Enterprise Features** - Multi-tenancy, JWT auth, RBAC, audit logging, SIEM integration, billing/licensing
- **Attack Path Visualization** - D3.js force-directed graphs with kill chain analysis
- **Remediation Workflow** - SLA enforcement, assignment, retest, MTTR metrics
- **Professional Reports** - Branded PDF/DOCX reports with SVG charts and multiple templates

### Use Cases

- Automated penetration testing
- Bug bounty hunting
- CTF competitions
- Security research and education
- Incident response and forensics
- Vulnerability assessment
- Application security (SAST/DAST/SCA)
- Compliance auditing
- Attack surface management

---

## Installation

### Requirements

- Python 3.10 or higher
- API key for at least one LLM provider (OpenAI, Anthropic, DeepSeek, etc.) or Ollama for local models

### Install from Source

```bash
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon
pip install -e .

# With optional features
pip install -e .[rag,tracing,viz,voice]
```

### Configuration

Create a `.env` file:

```bash
# Choose your AI model
KRYON_MODEL="gpt-4o"  # or claude-sonnet-4-20250514, deepseek-chat, dolphin-mistral:7b

# API Keys (add the ones you need)
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."
DEEPSEEK_API_KEY="..."

# Local LLM via Ollama (no API key needed)
# OPENAI_API_KEY="ollama"
# OPENAI_BASE_URL="http://localhost:11434/v1"
# KRYON_MODEL="dolphin-mistral:7b"

# Agent and workspace
KRYON_AGENT=recon_scout
KRYON_WORKSPACE_DIR=workspaces
KRYON_MAX_TURNS=50

# Memory / RAG
KRYON_MEMORY=true
```

---

## Quick Start

### CLI Mode

```bash
# Launch interactive REPL
kryon

# Select an agent
KRYON> /agent pentest_agent

# Run a security assessment
KRYON> Scan 192.168.1.0/24 and identify vulnerabilities

# Parallel operations (Swarm Mode)
KRYON> /parallel 3
KRYON> Perform comprehensive assessment of target.com
```

### Server Mode

```bash
# Start the API server
kryon-server

# Or with Docker
docker compose -f docker/docker-compose.kali.yml up -d
```

### Dashboard

```bash
cd dashboard
npm install && npm run dev
# Open http://localhost:3000
```

---

## Security Agents

| Agent | Specialization |
|-------|---------------|
| `pentest_agent` | System infiltration and exploitation |
| `vuln_hunter` | Bug hunting and vulnerability research |
| `recon_scout` | Reconnaissance and enumeration |
| `guardian_protocol` | Defensive security and hardening |
| `forensic_analyzer` | Incident response and forensics |
| `network_analyst` | Network traffic analysis |
| `memory_analyst` | Memory forensics |
| `reverse_engineer` | Binary analysis and reverse engineering |
| `mobile_infiltrator` | Mobile application security |
| `wireless_infiltrator` | WiFi and wireless security |
| `ctf_master` | CTF competition solver |
| `central_core` | Mission coordination and orchestration |
| `strategic_core` | Strategic planning and multi-agent coordination |
| `appsec_analyzer` | Application security (SAST/DAST/SCA) |
| `llm_red_team` | LLM/AI model security testing |
| `purple_team` | Combined offensive/defensive operations |
| `asm_agent` | Attack surface management |
| `target_validator` | Target validation and scope verification |
| `retester` | Remediation verification and retesting |
| `reporter` | Report generation and analysis |
| `mission_analyst` | Mission analysis and threat modeling |
| `rf_analyzer` | RF signal analysis |
| `chrome_infiltrator` | Browser-based security testing |
| `codeagent` | Code review and secure development |

### Multi-Agent Patterns

KRYON supports advanced multi-agent execution patterns:

- **Swarm** - Parallel agents working on subdivided targets
- **Sequential** - Ordered pipeline of agents
- **Hierarchical** - Manager agent delegating to specialists
- **Conditional** - Dynamic agent selection based on findings
- **Parallel** - Concurrent independent operations

---

## Tool Categories

204+ tools organized in 35 categories:

| Category | Tools | Description |
|----------|:-----:|-------------|
| `reconnaissance` | Nmap, Masscan, DNS enum | Network and service discovery |
| `web` | Nikto, SQLmap, XSS detection | Web application testing |
| `exploitation` | Metasploit, exploit builder | Vulnerability exploitation |
| `privilege_escalation` | LinPEAS, WinPEAS, kernel exploits | Local privilege escalation |
| `lateral_movement` | Pass-the-hash, pivoting | Network lateral movement |
| `credentials` | Hashcat, John, Hydra | Password cracking and spraying |
| `osint` | Shodan, theHarvester, Maltego | Open source intelligence |
| `cloud` | AWS/Azure/GCP scanners | Cloud security assessment |
| `container` | Docker, Kubernetes security | Container and orchestration |
| `mobile` | APK analysis, Frida | Mobile app security |
| `wifi` | Aircrack, deauth, WPS | Wireless network attacks |
| `appsec` | Semgrep, Bandit, npm audit | SAST, DAST, SCA scanning |
| `intelligence` | CVE correlation, threat intel | Vulnerability intelligence |
| `validation` | Target validation, scope check | Input validation |
| `llm_security` | Prompt injection, jailbreak tests | AI/LLM security testing |
| `dfir` | Volatility, log analysis | Digital forensics |
| `evasion` | Payload encoding, AV bypass | Defense evasion techniques |
| `api_attacks` | REST/GraphQL testing | API security testing |
| `discovery` | ASM, subdomain enum | Attack surface discovery |
| `post_exploitation` | Data exfil, persistence | Post-exploitation operations |
| + 15 more | ... | See `src/kryon/tools/` |

---

## Web Dashboard

Full-featured SvelteKit web interface with 25 pages:

- **Findings** - Consolidated security findings with filtering and export
- **Clients** - Multi-tenant client management
- **Scans** - Scan scheduling, monitoring, and results
- **Engagements** - Multi-day pentesting engagement management
- **Compliance** - Framework compliance reports (PCI-DSS, HIPAA, SOC2, etc.)
- **Attack Paths** - D3.js interactive attack path visualization
- **Risk** - Business risk scoring with contextual analysis
- **Remediation** - Kanban board with SLA tracking and MTTR metrics
- **Reports** - Professional branded report generation (PDF/DOCX)
- **Knowledge** - RAG knowledge base management
- **Notifications** - Multi-channel alerts (Email, Slack, Teams, PagerDuty)
- **Billing** - License management and usage metering
- **Onboarding** - Multi-step client onboarding wizard
- **Admin** - User management, backups, system settings
- **Assets / Scope** - Asset inventory and scope management

---

## API

136 REST endpoints across 28 routers. Base URL: `/api/v1`

### Key Endpoints

| Router | Endpoints | Description |
|--------|:---------:|-------------|
| `/health` | 2 | Health and readiness checks |
| `/auth` | 4 | JWT authentication and RBAC |
| `/agents` | 6 | Agent listing and execution |
| `/scans` | 8 | Scan CRUD and scheduling |
| `/findings` | 10 | Finding management and export |
| `/engagements` | 8 | Engagement lifecycle |
| `/compliance` | 6 | Compliance framework checks |
| `/reports` | 6 | Report generation (PDF/DOCX) |
| `/attack-paths` | 3 | Attack path analysis |
| `/risk` | 3 | Business risk scoring |
| `/remediation` | 6 | Remediation workflow |
| `/notifications` | 9 | Multi-channel notifications |
| `/billing` | 5 | Licensing and metering |
| `/onboarding` | 9 | Client onboarding |
| `/knowledge` | 6 | RAG knowledge base |
| `/integrations` | 4 | SIEM and webhook integrations |
| + 12 more | ... | See API docs |

---

## Docker Deployment

### Kali Linux Stack (Recommended)

Full deployment with Kali Linux tools, Ollama for local LLM, and the web dashboard:

```bash
# Copy and configure environment
cp docker/.env.docker.example docker/.env.docker

# Launch the stack
docker compose -f docker/docker-compose.kali.yml up -d

# Pull a model (first time only)
docker exec kryon-ollama ollama pull dolphin-mistral:7b

# Access
# API:       http://localhost:8000/api/v1/health
# Dashboard: http://localhost:3000
```

### Stack Components

| Container | Image | Purpose |
|-----------|-------|---------|
| `kryon` | Kali Linux + Python | Main platform with all security tools |
| `kryon-ollama` | Ollama (GPU) | Local LLM inference |
| `kryon-dashboard` | Nginx + SvelteKit | Web dashboard |

---

## Kubernetes

Production-grade Kubernetes deployment with Helm chart:

```bash
# Quick deploy with script
./scripts/deploy-k8s.sh

# Or with Helm
helm install kryon helm/kryon/ -n kryon --create-namespace

# Or raw manifests
kubectl apply -f k8s/
```

Features: HPA (auto-scaling 2-10 pods), health probes, ingress with TLS, persistent volumes, configmaps/secrets.

See [DEPLOYMENT.md](DEPLOYMENT.md) and [QUICKSTART_K8S.md](QUICKSTART_K8S.md) for full guides.

---

## Compliance Frameworks

| Framework | Coverage |
|-----------|----------|
| PCI-DSS v4.0 | Network segmentation, encryption, access control |
| HIPAA | PHI protection, audit controls, transmission security |
| SOC 2 Type II | Security, availability, confidentiality |
| NIST 800-53 | Full control family mapping |
| ISO 27001 | Information security management |
| GDPR | Data protection and privacy |
| OWASP Top 10 | Web application security |
| CIS Benchmarks | System hardening baselines |
| MITRE ATT&CK | Technique coverage mapping |

---

## Supported AI Models

| Provider | Models | Config |
|----------|--------|--------|
| OpenAI | GPT-4o, O1, O3-mini | `OPENAI_API_KEY` |
| Anthropic | Claude Sonnet 4, Opus 4 | `ANTHROPIC_API_KEY` |
| DeepSeek | DeepSeek V3, R1 | `DEEPSEEK_API_KEY` |
| Ollama | Qwen, Llama, Mistral, Dolphin | `OPENAI_BASE_URL` |
| OpenRouter | 200+ models | `OPENROUTER_API_KEY` |
| Groq | Llama, Mixtral (fast) | `GROQ_API_KEY` |
| Azure | Azure OpenAI | `AZURE_OPENAI_*` |

For fully uncensored security operations with local models, we recommend `dolphin-mistral:7b` via Ollama.

---

## Building Custom Agents

```python
from kryon.sdk.agents import Agent, function_tool

@function_tool
async def my_scan(target: str) -> str:
    """Run a custom scan against the target."""
    # your logic here
    return result

my_agent = Agent(
    name="Custom Scanner",
    instructions="You are a network security scanner...",
    tools=[my_scan],
)
```

---

## Project Structure

```
Kryon/
├── src/kryon/
│   ├── agents/          # 21 security agents + patterns
│   ├── sdk/             # Agent SDK (Agent, Runner, Handoff, Guardrail)
│   ├── tools/           # 204+ tools in 35 categories
│   ├── knowledge/       # RAG engine + ChromaDB + scrapers
│   ├── intelligence/    # Vulnerability correlation + threat intel
│   ├── evaluation/      # Risk scoring + business impact
│   ├── reporting/       # Report generation (PDF/DOCX/HTML)
│   ├── remediation/     # SLA + assignment + retest workflow
│   ├── notifications/   # Email, Slack, Teams, PagerDuty
│   ├── onboarding/      # Client onboarding + credential vault
│   ├── billing/         # Licensing (JWT RS256) + metering
│   ├── compliance/      # 9 compliance frameworks
│   ├── memory/          # SQLite store + 16 migrations
│   ├── server/          # FastAPI + 28 routers + middleware
│   ├── repl/            # Interactive CLI + commands
│   └── prompts/         # System prompts (markdown)
├── dashboard/           # SvelteKit web dashboard (25 pages)
├── docker/              # Docker Compose (Kali + Ollama)
├── k8s/                 # Kubernetes manifests
├── helm/                # Helm chart
├── tests/               # 1896 tests
└── scripts/             # Deployment and utility scripts
```

---

## Testing

```bash
# Run full test suite
pytest tests/ -x -q --ignore=tests/e2e

# Run specific module tests
pytest tests/tools/ -v
pytest tests/server/ -v
pytest tests/agents/ -v
```

Current status: **1896 passed, 24 skipped, 0 failed**

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon
pip install -e .[dev]
pytest
```

---

## Disclaimer

> **KRYON is designed exclusively for authorized security testing, research, and education.**
>
> You must have explicit written authorization before testing any system you do not own. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse. See [DISCLAIMER](DISCLAIMER) for the full legal notice.

---

## License

MIT License - see [LICENSE](LICENSE)

---

<div align="center">

**KRYON** - Autonomous Cybersecurity Intelligence Platform

[GitHub](https://github.com/skyvanguard/Kryon) | [Issues](https://github.com/skyvanguard/Kryon/issues) | [Deployment Guide](DEPLOYMENT.md)

</div>
