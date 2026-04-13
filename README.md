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

**Self-Improving Autonomous Cybersecurity Platform**

[![CI](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml)
[![Security Scan](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml)
[![Docker Build](https://github.com/skyvanguard/Kryon/actions/workflows/docker-build.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/docker-build.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1896_passed-brightgreen.svg)](#testing)
[![Skills](https://img.shields.io/badge/skills-9_playbooks-purple.svg)](#skill-system)
[![Tools](https://img.shields.io/badge/tools-204+-red.svg)](#tool-categories)
[![Stars](https://img.shields.io/github/stars/skyvanguard/Kryon?style=social)](https://github.com/skyvanguard/Kryon)

[Installation](#installation) | [Quick Start](#quick-start) | [Skills](#skill-system) | [Learning Loop](#self-improving-loop) | [Docker](#docker-deployment) | [API](#api)

</div>

---

## What is KRYON?

KRYON is an autonomous cybersecurity platform that **learns from every engagement**. Give it a target, and it chains tools autonomously (nmap, whatweb, gobuster, nuclei...), produces a professional security report, and saves the experience. Next time it encounters a similar target, it recalls what worked and optimizes its approach.

Unlike static prompt-based agents, KRYON has a **self-improving loop**: the more pentests it runs, the better it gets.

### One Prompt, Full Assessment

```
KRYON> haceme un analisis de seguridad de www.target.com

 ✶ Kryon → recall_similar_experiences (3s)
 ✻ Kryon → nmap -sV -sC -T4 (40s)
 ✽ Kryon → whatweb_scan (10s)
 ✢ Kryon → gobuster (30s)
 ✳ Kryon → nuclei_scan (60s)

╭─ Kryon ────────────────────────────────────────────╮
│ ## Security Assessment: www.target.com              │
│ **IP:** 54.69.84.63 | **Stack:** Apache, Bootstrap │
│ **Ports:** 80, 110, 443, 993                       │
│ **Findings:** 2 CVEs, 12 directories, email leak   │
│ **Risk:** MEDIUM                                    │
│ **Recommendations:** ...                            │
╰────────────────────────────────────────────────────╯

✅ Experience auto-saved: eng_3e03db5ef859
```

### Platform at a Glance

| Component | Count |
|-----------|:-----:|
| Dynamic Skills (playbooks) | 9 |
| Tool Implementations | 204+ |
| Tool Categories | 35 |
| API Endpoints | 136 |
| Compliance Frameworks | 9 |
| RAG Knowledge Documents | 486+ |
| Legacy Agents | 33 |
| Test Suite | 1896 passed |

### Core Capabilities

- **Self-Improving Loop** - Learns from every engagement via ChromaDB experience store. Recalls similar past targets to optimize attack chains
- **Dynamic Skill System** - 9 markdown playbooks loaded based on target profile (tech, ports, keywords). Create custom skills without writing Python
- **Autonomous Tool Chaining** - One prompt triggers full recon: nmap, whatweb, gobuster, nuclei, then a consolidated report. No manual intervention
- **204+ Security Tools** - Across 35 categories covering the full kill chain
- **Magic Docs** - Auto-generated security assessment report updated in real-time during engagement
- **Context Management** - Tool output capping (large results saved to disk), micro-compaction, session memory with auto-recommendations
- **Multi-Model Support** - Works with 300+ LLMs. Optimized for Gemma 4 26B (MoE) via Ollama for fully local, zero-cost operation
- **RAG Knowledge Base** - ExploitDB, NVD, GitHub, CTF writeups with ChromaDB vector search + Ollama embeddings
- **REST API** - 136 endpoints across 28 routers for full programmatic control
- **Compliance** - PCI-DSS, HIPAA, SOC2, NIST 800-53, ISO 27001, GDPR, OWASP, CIS, MITRE ATT&CK
- **Enterprise Features** - Multi-tenancy, JWT auth, RBAC, audit logging, SIEM integration
- **Server Hardening** - Audit and fix Linux servers via SSH with one command
- **Professional Reports** - Branded PDF/DOCX reports with SVG charts

### Use Cases

- Automated penetration testing
- Bug bounty hunting
- CTF competitions
- Server hardening and remediation
- Security research and education
- Incident response and forensics
- Vulnerability assessment
- Application security (SAST/DAST/SCA)
- Compliance auditing

---

## Skill System

KRYON uses **dynamic skills** instead of static agents. Skills are markdown files with YAML frontmatter that define specialized playbooks, automatically loaded based on the target:

```
src/kryon/skills/playbooks/
├── recon-scout.md        # Reconnaissance chain (nmap→whatweb→gobuster→nuclei)
├── pentest.md            # Exploitation + privilege escalation
├── vuln-hunter.md        # Bug bounty, WAF bypass, zero-day hunting
├── wordpress-audit.md    # WordPress-specific (wpscan, xmlrpc, REST API)
├── ssl-audit.md          # TLS/SSL configuration audit
├── server-hardening.md   # SSH audit + remediation via credentials
├── appsec.md             # OWASP Top 10, SAST/DAST/SCA
├── forensics.md          # Incident response + log analysis
└── ctf-master.md         # CTF solver (HackTheBox, TryHackMe)
```

### Skill Format

```yaml
---
name: wordpress-audit
description: "WordPress security audit"
triggers:
  tech: ["wordpress"]
  keywords: ["wordpress", "wp-content", "wpscan"]
priority: 15
required_tools:
  - run_command
  - nuclei_scan
  - search_vulnerabilities
---

## When WordPress is detected:
1. Confirm with whatweb
2. wpscan --enumerate u,p,t
3. Check xmlrpc.php, debug.log, wp-config backups
4. nuclei with WordPress templates
5. Report with CVSS scores
```

Skills are matched automatically by target profile (detected tech, open ports) and user intent (keywords). Create your own by dropping a `.md` file in `skills/playbooks/`.

---

## Self-Improving Loop

KRYON remembers what works. Every engagement is stored in ChromaDB with:

- **Target profile**: host, IP, ports, services, tech stack
- **Attack chain**: ordered sequence of tools + arguments + outcomes
- **Outcome classification**: success / partial / recon-only / fail
- **Signals**: CVEs found, shell gained, flags captured, directories discovered

On the next engagement, the agent queries `recall_similar_experiences` and shapes its plan based on what worked against similar targets.

```
Session 1: scan britimp.com.py → nmap→whatweb→gobuster→nuclei → saved

Session 2: scan similar-apache-site.com
  → recall: "Against Apache+Bootstrap, nmap→whatweb→nuclei found CVE in 5 min"
  → skips gobuster (was slow), goes straight to nuclei → faster engagement
```

### REPL Commands

| Command | Action |
|---------|--------|
| `/experiences` | List stored engagement experiences |
| `/experiences close [summary]` | Mine current session and save |
| `/experiences search <query>` | Similarity search over experiences |
| `/experiences show <id>` | Full experience dump |
| `/flush` | Clear agent history + session memory |

Experiences are also **auto-saved on exit** if the session had tool calls.

---

## Installation

### Requirements

- Python 3.10 or higher
- GPU recommended for local models (12+ GB VRAM for Gemma 4 26B)
- Docker for Kali Linux tools (nmap, metasploit, gobuster, etc.)

### Docker Deployment (Recommended)

```bash
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon

# Configure environment
cp docker/.env.docker.example docker/.env.docker
# Edit docker/.env.docker with your model and settings

# Launch Kali + Ollama stack
docker compose -f docker/docker-compose.kali.yml up -d

# Pull recommended model (Gemma 4 26B MoE — runs like 4B, quality of 26B)
docker exec kryon-ollama ollama pull gemma4:26b

# Create optimized variant with 32K context
docker exec kryon-ollama sh -c 'printf "FROM gemma4:26b\nPARAMETER num_ctx 32768\n" > /tmp/Modelfile && ollama create gemma4:26b-32k -f /tmp/Modelfile'

# Pull embedding model for RAG
docker exec kryon-ollama ollama pull nomic-embed-text

# Launch REPL
docker exec -it kryon kryon
```

### Configuration

Key environment variables in `docker/.env.docker`:

```bash
# Model (recommended: Gemma 4 26B MoE via Ollama)
KRYON_MODEL=gemma4:26b-32k
OPENAI_API_KEY=ollama
OPENAI_BASE_URL=http://ollama:11434/v1
OLLAMA=true

# Unified agent with dynamic skills (recommended)
KRYON_AGENT=kryon
KRYON_UNIFIED=true

# Runtime
KRYON_MAX_TURNS=50
KRYON_MEMORY=true
KRYON_STREAM=false

# RAG embeddings (uses Ollama's nomic-embed-text)
KRYON_EMBEDDING_MODEL=nomic-embed-text
KRYON_EMBEDDING_BASE_URL=http://ollama:11434
```

### Supported AI Models

| Provider | Recommended Model | Config |
|----------|-------------------|--------|
| **Ollama (local)** | **gemma4:26b-32k** | `OLLAMA=true` |
| Ollama | dolphin-mistral:7b, qwen3:8b | `OLLAMA=true` |
| OpenAI | GPT-4o, O1, O3-mini | `OPENAI_API_KEY` |
| Anthropic | Claude Sonnet 4, Opus 4 | `ANTHROPIC_API_KEY` |
| DeepSeek | DeepSeek V3, R1 | `DEEPSEEK_API_KEY` |
| OpenRouter | 200+ models | `OPENROUTER_API_KEY` |

**Recommended**: Gemma 4 26B via Ollama. MoE architecture means only 3.8B parameters active per token, so it runs fast on 12+ GB VRAM while delivering 26B quality. Supports native tool calling, thinking, and 262K context.

---

## Quick Start

```bash
# Launch REPL (inside Docker)
docker exec -it kryon kryon

# Full security assessment (autonomous — no interaction needed)
KRYON> haceme un analisis de seguridad de www.target.com

# Server hardening via SSH
KRYON> audita y corrige la seguridad del servidor admin@192.168.1.10

# CTF mode
KRYON> resuelve esta maquina de HackTheBox: 10.10.10.5

# View auto-generated report
KRYON> /report   # or: cat /workspace/.kryon_session.md

# Check what Kryon learned
KRYON> /experiences

# Exit (auto-saves experience)
KRYON> /exit
```

### Legacy Agents

The original 33 agents are still available for backward compatibility:

```bash
KRYON> /agent select recon_scout
KRYON> /agent select pentest_agent
```

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
| `appsec` | Semgrep, Bandit, npm audit | SAST, DAST, SCA scanning |
| `llm_security` | Prompt injection, jailbreak tests | AI/LLM security testing |
| `dfir` | Volatility, log analysis | Digital forensics |
| + 23 more | ... | See `src/kryon/tools/` |

---

## API

136 REST endpoints across 28 routers. Base URL: `/api/v1`

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
| `/knowledge` | 6 | RAG knowledge base |
| + 19 more | ... | See API docs |

---

## Docker Deployment

### Kali Linux Stack (Recommended)

```bash
# Launch with GPU support for Ollama
docker compose -f docker/docker-compose.kali.yml up -d

# With memory overrides for Gemma 4 26B
docker compose -f docker/docker-compose.kali.yml -f docker/docker-compose.override.yml up -d

# Interactive REPL
docker exec -it kryon kryon

# Kali shell (nmap, metasploit, sqlmap, hydra, etc.)
docker exec -it kryon bash

# VPN for CTFs
docker exec -u root -d kryon openvpn --config /workspace/htb.ovpn
```

### Stack Components

| Container | Image | Purpose |
|-----------|-------|---------|
| `kryon` | Kali Linux + Python | Main platform with all security tools |
| `kryon-ollama` | Ollama (GPU) | Local LLM inference |
| `nginx` (optional) | Nginx | Reverse proxy with TLS |

---

## Architecture

```
src/kryon/
├── skills/             # Dynamic skill system (playbooks + loader + unified agent)
├── learning/           # Self-improving loop (experiences + profiler + chain extractor)
├── services/           # Context management (micro-compact, session memory, auto-extract, tool cap)
├── sdk/                # Agent SDK (Agent, Runner, Handoff, Guardrail, MCP)
├── agents/             # 33 legacy agents + patterns (swarm, sequential, hierarchical)
├── tools/              # 204+ tools in 35 categories
├── knowledge/          # RAG engine + ChromaDB + scrapers + auto-updater
├── server/             # FastAPI + 28 routers + middleware + JWT/RBAC
├── repl/               # Interactive CLI + commands + Claude Code-style spinner
├── prompts/            # System prompts (markdown)
├── memory/             # SQLite store + 16 migrations
├── intelligence/       # CVE correlation + threat intel
├── compliance/         # 9 compliance frameworks
├── reporting/          # PDF/DOCX/HTML report generation
├── remediation/        # SLA + assignment + retest workflow
└── ...                 # billing, onboarding, notifications, etc.
```

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

## Testing

```bash
# Run full test suite
uv run pytest

# Run specific module
uv run pytest tests/agents/ -k "pentest"
uv run pytest -m "unit and not slow"

# Coverage (target: 95%)
make coverage
```

Current status: **1896 passed, 24 skipped, 0 failed**

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Creating a Custom Skill

Drop a `.md` file in `src/kryon/skills/playbooks/`:

```yaml
---
name: my-custom-audit
description: "My specialized audit playbook"
triggers:
  tech: ["nginx"]
  keywords: ["nginx", "reverse proxy"]
priority: 20
required_tools:
  - run_command
  - nuclei_scan
---

## My Custom Audit Steps
1. Check nginx version and config
2. ...
```

No Python code needed. Kryon loads it automatically on next session.

---

## Disclaimer

> **KRYON is designed exclusively for authorized security testing, research, and education.**
>
> You must have explicit written authorization before testing any system you do not own. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse. See [DISCLAIMER](DISCLAIMER) for the full legal notice.

---

## License

Proprietary - All Rights Reserved. See [LICENSE](LICENSE) for details.

---

<div align="center">

**KRYON** - Self-Improving Autonomous Cybersecurity Platform

[GitHub](https://github.com/skyvanguard/Kryon) | [Issues](https://github.com/skyvanguard/Kryon/issues) | [Deployment Guide](DEPLOYMENT.md)

</div>
